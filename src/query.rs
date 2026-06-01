//! WHOIS query execution and result handling.
//!
//! Provides [`WhoisQuery`] as the main query engine, [`QueryOptions`] for
//! configuring enhanced protocol features, and [`QueryResult`] for wrapping
//! server responses. Supports IANA referral resolution, RADB fallback for
//! empty RIR results, and the WHOIS-COLOR enhanced protocol (server-side
//! coloring, Markdown, images).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::protocol::WhoisColorProtocol;
use crate::servers::{ServerSelector, WhoisServer, DEFAULT_WHOIS_SERVER};

const TIMEOUT_SECONDS: u64 = 10;

/// Query options that control server selection, protocol features, and rendering.
#[expect(clippy::struct_excessive_bools, reason = "CLI options naturally map to booleans")]
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Whether to use DN42 server (lantian.pub)
    pub use_dn42: bool,
    /// Whether to use BGP.tools server
    pub use_bgptools: bool,
    /// Explicit server to use (bypasses auto-detection)
    pub explicit_server: Option<String>,
    /// Port number for the WHOIS connection
    pub port: u16,
    /// Whether to request server-side coloring
    pub use_server_color: bool,
    /// Whether to request Markdown-formatted output
    pub enable_markdown: bool,
    /// Whether to request image display support
    pub enable_images: bool,
    /// Preferred color scheme name (e.g., "mtf")
    pub preferred_color_scheme: Option<String>,
}

impl QueryOptions {
    /// Create default query options
    #[must_use] 
    pub fn new() -> Self {
        Self {
            use_dn42: false,
            use_bgptools: false,
            explicit_server: None,
            port: 43,
            use_server_color: false,
            enable_markdown: false,
            enable_images: false,
            preferred_color_scheme: None,
        }
    }
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if a WHOIS response is effectively empty or indicates no results
fn is_empty_result(response: &str) -> bool {
    let response = response.trim();

    if response.is_empty() {
        return true;
    }

    // Common empty response indicators (case-insensitive)
    let response_lower = response.to_lowercase();
    let empty_indicators = [
        "no found",
        "no match",
        "not found",
        "no data found",
        "no entries found",
        "no records found",
        "no such domain",
        "no whois server is known",
        "object does not exist",
        "%error: no objects found",
        "% no objects found",
    ];

    if empty_indicators.iter().any(|indicator| response_lower.contains(indicator)) {
        return true;
    }

    // Check if response only contains comment lines (lines starting with % or #)
    let has_content = response
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .any(|line| !line.starts_with('%') && !line.starts_with('#'));

    if !has_content {
        return true;
    }

    // Check if response is very short (less than 30 characters) and likely just headers/boilerplate
    if response.len() < 30 {
        let content_len: usize = response
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with('%') && !line.starts_with('#'))
            .map(str::len)
            .sum();
        if content_len < 10 {
            return true;
        }
    }

    false
}

/// The result of a WHOIS query, containing the raw response and metadata.
#[derive(Debug)]
pub struct QueryResult {
    /// Raw text response from the WHOIS server.
    pub response: String,
    /// The server that ultimately served the response (after IANA referral).
    pub server_used: WhoisServer,
    /// Whether the response already contains server-generated color codes.
    pub server_colored: bool,
}

impl QueryResult {
    /// Create a new `QueryResult` without server-side coloring.
    #[must_use] 
    pub fn new(response: String, server_used: WhoisServer) -> Self {
        Self {
            response,
            server_used,
            server_colored: false,
        }
    }

    /// Create a new `QueryResult` with an explicit server-coloring flag.
    #[must_use] 
    pub fn new_with_color(response: String, server_used: WhoisServer, server_colored: bool) -> Self {
        Self {
            response,
            server_used,
            server_colored,
        }
    }
}

/// Main WHOIS query engine.
///
/// Manages the query lifecycle:
/// 1. Server selection (via [`ServerSelector`])
/// 2. IANA referral resolution
/// 3. Enhanced or standard protocol execution
/// 4. RADB fallback on empty results
pub struct WhoisQuery {
    verbose: bool,
}

impl WhoisQuery {
    /// Create a new `WhoisQuery` with optional verbose logging.
    #[must_use] 
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Perform a direct WHOIS query to a specific server.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection fails, timeouts are not set,
    /// writing the query fails, or reading the response fails.
    pub fn query_direct(&self, query: &str, server: &WhoisServer) -> Result<String> {
        let address = server.address();

        if self.verbose {
            println!("Connecting to: {address}");
        }

        let mut stream = TcpStream::connect(&address)
            .with_context(|| format!("Cannot connect to WHOIS server: {address}"))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
            .context("Failed to set read timeout")?;

        stream
            .set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
            .context("Failed to set write timeout")?;

        let query_string = format!("{query}\r\n");
        stream
            .write_all(query_string.as_bytes())
            .context("Failed to write query to WHOIS server")?;

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .context("Failed to read response from WHOIS server")?;

        Ok(response)
    }

    /// Main query method with full protocol support.
    ///
    /// # Errors
    ///
    /// Returns an error if server selection, IANA referral resolution, or
    /// the actual query execution (TCP connection, write, read) fails.
    pub fn query_with_enhanced_protocol(
        &self,
        domain: &str,
        options: &QueryOptions,
    ) -> Result<QueryResult> {
        let server = self.select_server(domain, options);
        let result = self.execute_query(domain, &server, options)?;

        if Self::should_radb_fallback(&result, options, &server) {
            return self.fallback_to_radb(domain, options);
        }

        Ok(result)
    }

    /// Basic query without enhanced protocol features.
    ///
    /// # Errors
    ///
    /// Delegates to [`Self::query_with_enhanced_protocol`]; see that method
    /// for error conditions.
    // Legacy method: callers should prefer `query_with_enhanced_protocol` with `QueryOptions`
    pub fn query(
        &self,
        domain: &str,
        use_dn42: bool,
        use_bgptools: bool,
        explicit_server: Option<&str>,
        port: u16,
    ) -> Result<QueryResult> {
        let options = QueryOptions {
            use_dn42,
            use_bgptools,
            explicit_server: explicit_server.map(String::from),
            port,
            ..Default::default()
        };
        self.query_with_enhanced_protocol(domain, &options)
    }

    /// Legacy query with color protocol support.
    ///
    /// # Errors
    ///
    /// Delegates to [`Self::query_with_enhanced_protocol`]; see that method
    /// for error conditions.
    #[expect(clippy::too_many_arguments, reason = "legacy public API, prefer QueryOptions")]
    pub fn query_with_color_protocol(
        &self,
        domain: &str,
        use_dn42: bool,
        use_bgptools: bool,
        use_server_color: bool,
        explicit_server: Option<&str>,
        port: u16,
        preferred_color_scheme: Option<&str>,
    ) -> Result<QueryResult> {
        let options = QueryOptions {
            use_dn42,
            use_bgptools,
            explicit_server: explicit_server.map(String::from),
            port,
            use_server_color,
            preferred_color_scheme: preferred_color_scheme.map(String::from),
            ..Default::default()
        };
        self.query_with_enhanced_protocol(domain, &options)
    }

    // --- Private helpers (extracted to eliminate duplication) ---

    /// Select the appropriate server based on query options
    #[expect(clippy::unused_self, reason = "instance method for future verbose-aware selection")]
    fn select_server(&self, domain: &str, options: &QueryOptions) -> WhoisServer {
        ServerSelector::select_server(
            domain,
            options.use_dn42,
            options.use_bgptools,
            options.explicit_server.as_deref(),
            options.port,
        )
    }

    /// Execute a query, choosing enhanced or basic path based on options
    fn execute_query(
        &self,
        domain: &str,
        server: &WhoisServer,
        options: &QueryOptions,
    ) -> Result<QueryResult> {
        let use_enhanced =
            options.use_server_color || options.enable_markdown || options.enable_images;

        if use_enhanced {
            self.query_enhanced(domain, server, options)
        } else {
            self.query_with_referral(domain, server)
        }
    }

    /// Perform a WHOIS query with IANA referral if needed (basic, no protocol enhancements)
    fn query_with_referral(
        &self,
        query: &str,
        initial_server: &WhoisServer,
    ) -> Result<QueryResult> {
        if initial_server.name != "IANA" && self.verbose {
            println!(
                "Using {} server: {}",
                initial_server.name,
                initial_server.address()
            );
        }

        let target = self.resolve_iana_referral(query, initial_server)?;
        let response = self.query_direct(query, &target)?;
        Ok(QueryResult::new(response, target))
    }

    /// Execute enhanced protocol query (v1.1 with color, markdown, images)
    fn query_enhanced(
        &self,
        domain: &str,
        server: &WhoisServer,
        options: &QueryOptions,
    ) -> Result<QueryResult> {
        let protocol = WhoisColorProtocol;
        let target = self.resolve_iana_referral(domain, server)?;

        let capabilities = protocol
            .probe_capabilities(&target.address(), self.verbose)
            .unwrap_or_default();

        let response = protocol.query_with_enhanced_protocol(
            &target.address(),
            domain,
            &capabilities,
            options.preferred_color_scheme.as_deref(),
            options.enable_markdown,
            options.enable_images,
            self.verbose,
        )?;

        let server_colored = protocol.is_server_colored(&response);
        Ok(QueryResult::new_with_color(response, target, server_colored))
    }

    /// Resolve IANA referral to determine the final target server
    fn resolve_iana_referral(
        &self,
        query: &str,
        server: &WhoisServer,
    ) -> Result<WhoisServer> {
        if server.name != "IANA" {
            return Ok(server.clone());
        }

        if self.verbose {
            println!("Querying IANA at: {}", server.address());
        }

        let iana_response = self.query_direct(query, server)?;
        let whois_server_host = ServerSelector::extract_whois_server(&iana_response)
            .unwrap_or_else(|| DEFAULT_WHOIS_SERVER.to_string());

        let final_server = WhoisServer::custom(whois_server_host, server.port);

        if self.verbose {
            if final_server.host == DEFAULT_WHOIS_SERVER {
                println!(
                    "No referral found, using default: {DEFAULT_WHOIS_SERVER}"
                );
            } else {
                println!("IANA referred to: {}", final_server.host);
            }
        }

        Ok(final_server)
    }

    /// Check if RADB fallback should be attempted
    fn should_radb_fallback(
        result: &QueryResult,
        options: &QueryOptions,
        server: &WhoisServer,
    ) -> bool {
        is_empty_result(&result.response)
            && !options.use_dn42
            && !options.use_bgptools
            && options.explicit_server.is_none()
            && server.name != "RADB"
    }

    /// Try RADB fallback when RIR servers return empty results
    fn fallback_to_radb(
        &self,
        domain: &str,
        options: &QueryOptions,
    ) -> Result<QueryResult> {
        if self.verbose {
            println!("Empty result from RIR servers, trying RADB fallback...");
        }

        let radb_server = WhoisServer::radb();

        if self.verbose {
            println!("Querying RADB at: {}", radb_server.address());
        }

        self.execute_query(domain, &radb_server, options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_empty_result_should_return_true_when_completely_empty() {
        assert!(is_empty_result(""));
        assert!(is_empty_result("   "));
        assert!(is_empty_result("\n\n\n"));
    }

    #[test]
    fn is_empty_result_should_return_false_when_valid_content() {
        let valid_content = r"
domain:         example.com
descr:          Example Domain
admin-c:        ADMIN123
tech-c:         TECH456
status:         ASSIGNED
mnt-by:         EXAMPLE-MNT
created:        2020-01-01T00:00:00Z
last-modified:  2020-12-31T23:59:59Z
source:         RIPE
        ";
        assert!(!is_empty_result(valid_content));
    }

    #[test]
    fn is_empty_result_should_return_true_when_comment_only() {
        assert!(is_empty_result("% Comment only\n% Another comment\n# More comments"));
        assert!(is_empty_result("% This is just comments\n\n% More comments"));
    }

    #[test]
    fn is_empty_result_should_return_false_when_has_content_amidst_comments() {
        assert!(!is_empty_result("% Comment\nactual content\n% Another comment"));
        assert!(!is_empty_result("Some real content\n% with comment"));
    }

    #[test]
    fn is_empty_result_should_return_true_when_short_response() {
        assert!(is_empty_result("Short"));
        assert!(is_empty_result("Tiny"));
    }

    #[test]
    fn is_empty_result_should_return_false_when_response_long_enough() {
        assert!(!is_empty_result("Very short response"));
        assert!(!is_empty_result(
            "This is a longer response that should be considered valid content with enough information"
        ));
    }

    #[test]
    fn radb_server_should_have_correct_properties() {
        let radb = WhoisServer::radb();
        assert_eq!(radb.host, "whois.radb.net");
        assert_eq!(radb.port, 43);
        assert_eq!(radb.name, "RADB");
        assert_eq!(radb.address(), "whois.radb.net:43");
    }
}
