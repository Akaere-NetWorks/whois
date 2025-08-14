use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use anyhow::{Context, Result};
use crate::servers::{WhoisServer, ServerSelector, DEFAULT_WHOIS_SERVER};
use crate::protocol::WhoisColorProtocol;

const TIMEOUT_SECONDS: u64 = 10;

/// Check if a WHOIS response is effectively empty or indicates no results
fn is_empty_result(response: &str) -> bool {
    let response = response.trim();
    
    // Obviously empty
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
    
    for indicator in &empty_indicators {
        if response_lower.contains(indicator) {
            return true;
        }
    }
    
    // Check if response only contains comment lines (lines starting with % or #)
    let content_lines: Vec<&str> = response
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('%') && !line.starts_with('#'))
        .collect();
    
    if content_lines.is_empty() {
        return true;
    }
    
    // Check if response is very short (less than 30 characters) and likely just headers/boilerplate
    // Only apply this for extremely short responses that have minimal content
    if response.len() < 30 && content_lines.join(" ").len() < 10 {
        return true;
    }
    
    false
}

#[derive(Debug)]
pub struct QueryResult {
    pub response: String,
    pub server_used: WhoisServer,
    pub server_colored: bool,
}

impl QueryResult {
    pub fn new(response: String, server_used: WhoisServer) -> Self {
        Self { 
            response, 
            server_used,
            server_colored: false,
        }
    }

    pub fn new_with_color(response: String, server_used: WhoisServer, server_colored: bool) -> Self {
        Self { 
            response, 
            server_used,
            server_colored,
        }
    }
}

pub struct WhoisQuery {
    verbose: bool,
}

impl WhoisQuery {
    pub fn new(verbose: bool) -> Self {
        Self { verbose }
    }

    /// Perform a direct WHOIS query to a specific server
    pub fn query_direct(&self, query: &str, server: &WhoisServer) -> Result<String> {
        let address = server.address();
        
        if self.verbose {
            println!("Connecting to: {}", address);
        }

        let mut stream = TcpStream::connect(&address)
            .with_context(|| format!("Cannot connect to WHOIS server: {}", address))?;
        
        stream.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
            .context("Failed to set read timeout")?;
        
        stream.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
            .context("Failed to set write timeout")?;
        
        let query_string = format!("{}\r\n", query);
        stream.write_all(query_string.as_bytes())
            .context("Failed to write query to WHOIS server")?;
        
        let mut response = String::new();
        stream.read_to_string(&mut response)
            .context("Failed to read response from WHOIS server")?;
        
        Ok(response)
    }

    /// Perform a WHOIS query with IANA referral if needed
    pub fn query_with_referral(&self, query: &str, initial_server: &WhoisServer) -> Result<QueryResult> {
        if initial_server.name == "IANA" {
            if self.verbose {
                println!("Querying IANA at: {}", initial_server.address());
            }

            // First query IANA
            let iana_response = self.query_direct(query, initial_server)?;
            
            // Extract the referral WHOIS server from IANA's response
            let whois_server_host = ServerSelector::extract_whois_server(&iana_response)
                .unwrap_or_else(|| DEFAULT_WHOIS_SERVER.to_string());
            
            let final_server = WhoisServer::custom(whois_server_host, initial_server.port);
            
            if self.verbose {
                if final_server.host != DEFAULT_WHOIS_SERVER {
                    println!("IANA referred to: {}", final_server.host);
                } else {
                    println!("No referral found, using default: {}", DEFAULT_WHOIS_SERVER);
                }
            }
            
            // Query the actual WHOIS server
            let final_response = self.query_direct(query, &final_server)?;
            
            Ok(QueryResult::new(final_response, final_server))
        } else {
            // Direct query to specified server
            if self.verbose {
                println!("Using {} server: {}", initial_server.name, initial_server.address());
            }

            let response = self.query_direct(query, initial_server)?;
            Ok(QueryResult::new(response, initial_server.clone()))
        }
    }

    /// Main query method that handles all logic
    pub fn query(
        &self,
        domain: &str,
        use_dn42: bool,
        use_bgptools: bool,
        explicit_server: Option<&str>,
        port: u16,
    ) -> Result<QueryResult> {
        let server = ServerSelector::select_server(
            domain,
            use_dn42,
            use_bgptools,
            explicit_server,
            port,
        );

        let result = self.query_with_referral(domain, &server)?;
        
        // Check if result is empty and fallback to RADB if needed
        // Only fallback if we're not already using a specific server (DN42, BGPtools, or explicit server)
        if is_empty_result(&result.response) && 
           !use_dn42 && !use_bgptools && explicit_server.is_none() && 
           server.name != "RADB" {
            
            if self.verbose {
                println!("Empty result from RIR servers, trying RADB fallback...");
            }
            
            return self.try_radb_fallback(domain, false, false, false, None);
        }
        
        Ok(result)
    }

    /// Query with enhanced protocol support (v1.1 with markdown and images)
    pub fn query_with_enhanced_protocol(
        &self,
        domain: &str,
        use_dn42: bool,
        use_bgptools: bool,
        use_server_color: bool,
        enable_markdown: bool,
        enable_images: bool,
        explicit_server: Option<&str>,
        port: u16,
        preferred_color_scheme: Option<&str>,
    ) -> Result<QueryResult> {
        let server = ServerSelector::select_server(
            domain,
            use_dn42,
            use_bgptools,
            explicit_server,
            port,
        );

        let result = if use_server_color || enable_markdown || enable_images {
            self.query_with_enhanced_protocol_impl(domain, &server, preferred_color_scheme, enable_markdown, enable_images)?
        } else {
            self.query_with_referral(domain, &server)?
        };

        // Check if result is empty and fallback to RADB if needed
        // Only fallback if we're not already using a specific server (DN42, BGPtools, or explicit server)
        if is_empty_result(&result.response) && 
           !use_dn42 && !use_bgptools && explicit_server.is_none() && 
           server.name != "RADB" {
            
            if self.verbose {
                println!("Empty result from RIR servers, trying RADB fallback...");
            }
            
            return self.try_radb_fallback(domain, use_server_color, enable_markdown, enable_images, preferred_color_scheme);
        }

        Ok(result)
    }

    /// Legacy method for backward compatibility
    /// Query with color protocol support
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
        let server = ServerSelector::select_server(
            domain,
            use_dn42,
            use_bgptools,
            explicit_server,
            port,
        );

        let result = if use_server_color {
            self.query_with_enhanced_protocol_impl(domain, &server, preferred_color_scheme, false, false)?
        } else {
            self.query_with_referral(domain, &server)?
        };

        // Check if result is empty and fallback to RADB if needed
        // Only fallback if we're not already using a specific server (DN42, BGPtools, or explicit server)
        if is_empty_result(&result.response) && 
           !use_dn42 && !use_bgptools && explicit_server.is_none() && 
           server.name != "RADB" {
            
            if self.verbose {
                println!("Empty result from RIR servers, trying RADB fallback...");
            }
            
            return self.try_radb_fallback(domain, use_server_color, false, false, preferred_color_scheme);
        }

        Ok(result)
    }

    /// Implementation of enhanced protocol query (v1.1)
    fn query_with_enhanced_protocol_impl(
        &self,
        domain: &str,
        server: &WhoisServer,
        preferred_color_scheme: Option<&str>,
        enable_markdown: bool,
        enable_images: bool,
    ) -> Result<QueryResult> {
        let protocol = WhoisColorProtocol;
        
        if server.name == "IANA" {
            // Handle IANA referral first
            if self.verbose {
                println!("Querying IANA at: {}", server.address());
            }

            let iana_response = self.query_direct(domain, server)?;
            let whois_server_host = ServerSelector::extract_whois_server(&iana_response)
                .unwrap_or_else(|| DEFAULT_WHOIS_SERVER.to_string());
            
            let final_server = WhoisServer::custom(whois_server_host, server.port);
            
            if self.verbose {
                if final_server.host != DEFAULT_WHOIS_SERVER {
                    println!("IANA referred to: {}", final_server.host);
                } else {
                    println!("No referral found, using default: {}", DEFAULT_WHOIS_SERVER);
                }
            }

            // Try enhanced protocol with final server
            return self.try_enhanced_protocol_query(domain, &final_server, &protocol, preferred_color_scheme, enable_markdown, enable_images);
        } else {
            // Direct server query with enhanced protocol
            return self.try_enhanced_protocol_query(domain, server, &protocol, preferred_color_scheme, enable_markdown, enable_images);
        }
    }


    /// Try enhanced protocol query with all v1.1 features
    fn try_enhanced_protocol_query(
        &self,
        domain: &str,
        server: &WhoisServer,
        protocol: &WhoisColorProtocol,
        preferred_color_scheme: Option<&str>,
        enable_markdown: bool,
        enable_images: bool,
    ) -> Result<QueryResult> {
        // Probe server capabilities
        let capabilities = protocol.probe_capabilities(&server.address(), self.verbose)
            .unwrap_or_default(); // Use default (no support) if probe fails

        // Perform query based on capabilities
        let response = protocol.query_with_enhanced_protocol(
            &server.address(),
            domain,
            &capabilities,
            preferred_color_scheme,
            enable_markdown,
            enable_images,
            self.verbose
        )?;

        let server_colored = protocol.is_server_colored(&response);
        Ok(QueryResult::new_with_color(response, server.clone(), server_colored))
    }

    /// Try RADB fallback when RIR servers return empty results
    fn try_radb_fallback(
        &self,
        domain: &str,
        use_server_color: bool,
        enable_markdown: bool,
        enable_images: bool,
        preferred_color_scheme: Option<&str>,
    ) -> Result<QueryResult> {
        let radb_server = WhoisServer::radb();
        
        if self.verbose {
            println!("Querying RADB at: {}", radb_server.address());
        }
        
        if use_server_color || enable_markdown || enable_images {
            // Try enhanced protocol with RADB
            self.query_with_enhanced_protocol_impl(domain, &radb_server, preferred_color_scheme, enable_markdown, enable_images)
        } else {
            // Direct query to RADB
            let response = self.query_direct(domain, &radb_server)?;
            Ok(QueryResult::new(response, radb_server))
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_empty_result_completely_empty() {
        assert!(is_empty_result(""));
        assert!(is_empty_result("   "));
        assert!(is_empty_result("\n\n\n"));
    }

    #[test]
    fn test_is_empty_result_common_indicators() {
        assert!(is_empty_result("No Found"));
        assert!(is_empty_result("NO MATCH"));
        assert!(is_empty_result("not found"));
        assert!(is_empty_result("No data found"));
        assert!(is_empty_result("No entries found"));
        assert!(is_empty_result("No records found"));
        assert!(is_empty_result("No such domain"));
        assert!(is_empty_result("No whois server is known"));
        assert!(is_empty_result("Object does not exist"));
        assert!(is_empty_result("%Error: No objects found"));
        assert!(is_empty_result("% No objects found"));
    }

    #[test]
    fn test_is_empty_result_short_responses() {
        assert!(is_empty_result("Short"));
        assert!(is_empty_result("Tiny"));
        assert!(!is_empty_result("Very short response")); // This is now long enough to be considered valid
        assert!(!is_empty_result("This is a longer response that should be considered valid content with enough information"));
    }

    #[test]
    fn test_is_empty_result_comment_only() {
        assert!(is_empty_result("% Comment only\n% Another comment\n# More comments"));
        assert!(is_empty_result("% This is just comments\n\n% More comments"));
        assert!(!is_empty_result("% Comment\nactual content\n% Another comment"));
        assert!(!is_empty_result("Some real content\n% with comment"));
    }

    #[test]
    fn test_is_empty_result_valid_content() {
        let valid_content = r#"
domain:         example.com
descr:          Example Domain
admin-c:        ADMIN123
tech-c:         TECH456
status:         ASSIGNED
mnt-by:         EXAMPLE-MNT
created:        2020-01-01T00:00:00Z
last-modified:  2020-12-31T23:59:59Z
source:         RIPE
        "#;
        assert!(!is_empty_result(valid_content));
    }

    #[test]
    fn test_radb_server_creation() {
        let radb = WhoisServer::radb();
        assert_eq!(radb.host, "whois.radb.net");
        assert_eq!(radb.port, 43);
        assert_eq!(radb.name, "RADB");
        assert_eq!(radb.address(), "whois.radb.net:43");
    }
} 