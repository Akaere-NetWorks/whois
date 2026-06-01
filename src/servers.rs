//! WHOIS server definitions and selection logic.
//!
//! Defines well-known WHOIS server constants (IANA, RIPE, DN42, BGP.tools,
//! RADB) and provides [`WhoisServer`] for representing server connections,
//! and [`ServerSelector`] for choosing the correct server based on query
//! parameters (DN42 auto-detection, `--bgptools`, explicit server, env var).
//!
//! Server selection priority:
//! 1. DN42 (flag or `AS42424xxxxx` domain pattern)
//! 2. BGP.tools (`--bgptools` flag)
//! 3. Explicit server (`--server` flag)
//! 4. `WHOIS_SERVER` environment variable
//! 5. IANA whois (for referral-based resolution)

use std::env;

/// IANA WHOIS server hostname.
pub const IANA_WHOIS_SERVER: &str = "whois.iana.org";
/// Default WHOIS server hostname (RIPE).
pub const DEFAULT_WHOIS_SERVER: &str = "whois.ripe.net";
/// Default WHOIS port.
pub const DEFAULT_WHOIS_PORT: u16 = 43;
/// DN42 WHOIS server hostname (lantian.pub).
pub const DN42_WHOIS_SERVER: &str = "lantian.pub";
/// DN42 WHOIS port.
pub const DN42_WHOIS_PORT: u16 = 43;
/// BGP.tools WHOIS server hostname.
pub const BGPTOOLS_WHOIS_SERVER: &str = "bgp.tools";
/// BGP.tools WHOIS port.
pub const BGPTOOLS_WHOIS_PORT: u16 = 43;
/// RADB (Routing Assets Database) WHOIS server hostname.
pub const RADB_WHOIS_SERVER: &str = "whois.radb.net";
/// RADB WHOIS port.
pub const RADB_WHOIS_PORT: u16 = 43;

/// Represents a WHOIS server with host, port, and display name.
#[derive(Debug, Clone)]
pub struct WhoisServer {
    /// Server hostname or IP address.
    pub host: String,
    /// TCP port number (default: 43).
    pub port: u16,
    /// Human-readable name (e.g., "RIPE", "IANA", "DN42", "Custom").
    pub name: String,
}

impl Default for WhoisServer {
    fn default() -> Self {
        Self::new(DEFAULT_WHOIS_SERVER, DEFAULT_WHOIS_PORT, "RIPE")
    }
}

impl WhoisServer {
    /// Create a new `WhoisServer` with the given host, port, and name.
    pub fn new(host: impl Into<String>, port: u16, name: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            name: name.into(),
        }
    }

    /// Create a `WhoisServer` pointing to IANA (`whois.iana.org`).
    #[must_use] 
    pub fn iana() -> Self {
        Self::new(IANA_WHOIS_SERVER, DEFAULT_WHOIS_PORT, "IANA")
    }

    /// Create a `WhoisServer` pointing to DN42 (`lantian.pub`).
    #[must_use] 
    pub fn dn42() -> Self {
        Self::new(DN42_WHOIS_SERVER, DN42_WHOIS_PORT, "DN42")
    }

    /// Create a `WhoisServer` pointing to BGP.tools (`bgp.tools`).
    #[must_use] 
    pub fn bgptools() -> Self {
        Self::new(BGPTOOLS_WHOIS_SERVER, BGPTOOLS_WHOIS_PORT, "BGP.tools")
    }

    /// Create a `WhoisServer` pointing to RADB (`whois.radb.net`).
    #[must_use] 
    pub fn radb() -> Self {
        Self::new(RADB_WHOIS_SERVER, RADB_WHOIS_PORT, "RADB")
    }

    /// Create a `WhoisServer` with a custom host and port.
    pub fn custom(host: impl Into<String>, port: u16) -> Self {
        Self::new(host.into(), port, "Custom")
    }

    /// Get the full `host:port` address string for TCP connections.
    #[must_use] 
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Static utility for selecting the appropriate WHOIS server.
///
/// Server selection follows a priority chain:
/// 1. DN42 (flag or `AS42424xxxxx` domain pattern)
/// 2. BGP.tools (`--bgptools` flag)
/// 3. Explicit server (`--server` flag)
/// 4. `WHOIS_SERVER` environment variable
/// 5. IANA whois (referral-based resolution)
pub struct ServerSelector;

impl ServerSelector {
    /// Extract WHOIS server from IANA response
    #[must_use] 
    pub fn extract_whois_server(response: &str) -> Option<String> {
        for line in response.lines() {
            let line = line.trim();
            
            // Look for "whois:" field
            if line.starts_with("whois:") {
                return Some(line.split_whitespace()
                    .nth(1)?
                    .trim()
                    .to_string());
            }
            // Also look for "refer:" field as a fallback
            if line.starts_with("refer:") {
                return Some(line.split_whitespace()
                    .nth(1)?
                    .trim()
                    .to_string());
            }
        }
        None
    }

    /// Get server from environment variable if available
    #[must_use] 
    pub fn from_env() -> Option<String> {
        env::var("WHOIS_SERVER").ok()
    }

    /// Select appropriate server based on query and options
    #[must_use] 
    pub fn select_server(
        domain: &str,
        use_dn42: bool,
        use_bgptools: bool,
        explicit_server: Option<&str>,
        port: u16,
    ) -> WhoisServer {
        // Priority: special flags > explicit server > environment > default
        if use_dn42 || domain.to_uppercase().starts_with("AS42424") {
            return WhoisServer::dn42();
        }

        if use_bgptools {
            return WhoisServer::bgptools();
        }

        if let Some(server) = explicit_server {
            return WhoisServer::custom(server, port);
        }

        if let Some(env_server) = Self::from_env() {
            return WhoisServer::custom(env_server, port);
        }

        // Default: use IANA for referral
        WhoisServer::iana()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod whois_server {
        use super::*;

        #[test]
        fn new_should_create_server_with_given_params() {
            let server = WhoisServer::new("test.com", 43, "Test");
            assert_eq!(server.host, "test.com");
            assert_eq!(server.port, 43);
            assert_eq!(server.name, "Test");
        }

        #[test]
        fn iana_should_return_iana_server() {
            let server = WhoisServer::iana();
            assert_eq!(server.host, IANA_WHOIS_SERVER);
            assert_eq!(server.port, DEFAULT_WHOIS_PORT);
            assert_eq!(server.name, "IANA");
        }

        #[test]
        fn default_should_return_ripe_server() {
            let server = WhoisServer::default();
            assert_eq!(server.host, DEFAULT_WHOIS_SERVER);
            assert_eq!(server.port, DEFAULT_WHOIS_PORT);
            assert_eq!(server.name, "RIPE");
        }

        #[test]
        fn dn42_should_return_lantian_server() {
            let server = WhoisServer::dn42();
            assert_eq!(server.host, DN42_WHOIS_SERVER);
            assert_eq!(server.port, DN42_WHOIS_PORT);
            assert_eq!(server.name, "DN42");
        }

        #[test]
        fn bgptools_should_return_bgp_tools_server() {
            let server = WhoisServer::bgptools();
            assert_eq!(server.host, BGPTOOLS_WHOIS_SERVER);
            assert_eq!(server.port, BGPTOOLS_WHOIS_PORT);
            assert_eq!(server.name, "BGP.tools");
        }

        #[test]
        fn radb_should_return_radb_server() {
            let server = WhoisServer::radb();
            assert_eq!(server.host, RADB_WHOIS_SERVER);
            assert_eq!(server.port, RADB_WHOIS_PORT);
            assert_eq!(server.name, "RADB");
        }

        #[test]
        fn custom_should_create_custom_server() {
            let server = WhoisServer::custom("custom.server.com", 4343);
            assert_eq!(server.host, "custom.server.com");
            assert_eq!(server.port, 4343);
            assert_eq!(server.name, "Custom");
        }

        #[test]
        fn address_should_format_host_and_port() {
            let server = WhoisServer::new("example.com", 43, "Test");
            assert_eq!(server.address(), "example.com:43");
        }

        #[test]
        fn address_should_include_non_default_port() {
            let server = WhoisServer::new("example.com", 4343, "Test");
            assert_eq!(server.address(), "example.com:4343");
        }
    }

    mod extract_whois_server {
        use super::*;

        #[test]
        fn should_extract_whois_field() {
            let response = "domain: example.com\nwhois: whois.example.com\n";
            assert_eq!(
                ServerSelector::extract_whois_server(response),
                Some("whois.example.com".to_string())
            );
        }

        #[test]
        fn should_extract_refer_field() {
            let response = "domain: example.com\nrefer: whois.example.com\n";
            assert_eq!(
                ServerSelector::extract_whois_server(response),
                Some("whois.example.com".to_string())
            );
        }

        #[test]
        fn should_prefer_whois_over_refer() {
            let response = "whois: whois-primary.example.com\nrefer: whois-fallback.example.com\n";
            assert_eq!(
                ServerSelector::extract_whois_server(response),
                Some("whois-primary.example.com".to_string())
            );
        }

        #[test]
        fn should_return_none_when_no_server_found() {
            let response = "domain: example.com\nsource: RIPE\n";
            assert_eq!(ServerSelector::extract_whois_server(response), None);
        }

        #[test]
        fn should_return_none_for_empty_response() {
            assert_eq!(ServerSelector::extract_whois_server(""), None);
        }

        #[test]
        fn should_ignore_whitespace_around_field() {
            let response = "  whois:  spaced.server.com  \n";
            assert_eq!(
                ServerSelector::extract_whois_server(response),
                Some("spaced.server.com".to_string())
            );
        }

        #[test]
        fn should_return_none_for_malformed_whois_line() {
            let response = "whois:\n";
            assert_eq!(ServerSelector::extract_whois_server(response), None);
        }

        #[test]
        fn should_return_none_for_malformed_refer_line() {
            let response = "refer:\n";
            assert_eq!(ServerSelector::extract_whois_server(response), None);
        }
    }

    mod select_server {
        use super::*;

        #[test]
        fn should_return_dn42_when_flag_set() {
            let server = ServerSelector::select_server("example.com", true, false, None, 43);
            assert_eq!(server.name, "DN42");
            assert_eq!(server.host, DN42_WHOIS_SERVER);
        }

        #[test]
        fn should_return_dn42_when_as42424_pattern_detected() {
            let server = ServerSelector::select_server("AS4242420000", false, false, None, 43);
            assert_eq!(server.name, "DN42");
            assert_eq!(server.host, DN42_WHOIS_SERVER);
        }

        #[test]
        fn should_return_dn42_for_lowercase_as42424_pattern() {
            let server = ServerSelector::select_server("as4242420000", false, false, None, 43);
            assert_eq!(server.name, "DN42");
        }

        #[test]
        fn should_return_bgptools_when_flag_set() {
            let server = ServerSelector::select_server("example.com", false, true, None, 43);
            assert_eq!(server.name, "BGP.tools");
            assert_eq!(server.host, BGPTOOLS_WHOIS_SERVER);
        }

        #[test]
        fn should_return_custom_when_explicit_server_given() {
            let server = ServerSelector::select_server("example.com", false, false, Some("custom.server.com"), 4343);
            assert_eq!(server.host, "custom.server.com");
            assert_eq!(server.port, 4343);
            assert_eq!(server.name, "Custom");
        }

        #[test]
        fn should_return_iana_by_default() {
            // Ensure no env var interference
            std::env::remove_var("WHOIS_SERVER");
            let server = ServerSelector::select_server("example.com", false, false, None, 43);
            assert_eq!(server.name, "IANA");
            assert_eq!(server.host, IANA_WHOIS_SERVER);
        }

        #[test]
        fn should_prioritize_dn42_over_bgptools() {
            let server = ServerSelector::select_server("example.com", true, true, None, 43);
            assert_eq!(server.name, "DN42");
        }

        #[test]
        fn should_prioritize_dn42_over_explicit_server() {
            let server = ServerSelector::select_server("example.com", true, false, Some("explicit.com"), 43);
            assert_eq!(server.name, "DN42");
        }

        #[test]
        fn should_prioritize_bgptools_over_explicit_server() {
            let server = ServerSelector::select_server("example.com", false, true, Some("explicit.com"), 43);
            assert_eq!(server.name, "BGP.tools");
        }

        #[test]
        fn should_use_env_var_when_no_flags_or_explicit_server() {
            std::env::set_var("WHOIS_SERVER", "env.server.com");
            let server = ServerSelector::select_server("example.com", false, false, None, 4343);
            std::env::remove_var("WHOIS_SERVER");
            assert_eq!(server.host, "env.server.com");
            assert_eq!(server.port, 4343);
            assert_eq!(server.name, "Custom");
        }
    }
} 