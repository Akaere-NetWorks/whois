use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use anyhow::{Context, Result};

/// WHOIS-COLOR Protocol v1.0
/// A backward-compatible extension protocol for server-side colorization
pub struct WhoisColorProtocol;

/// Server capability information
#[derive(Debug, Clone, PartialEq)]
pub struct ServerCapabilities {
    pub supports_color: bool,
    pub color_schemes: Vec<String>,
    pub protocol_version: String,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            supports_color: false,
            color_schemes: vec![],
            protocol_version: "none".to_string(),
        }
    }
}

/// Protocol constants
pub const PROTOCOL_VERSION: &str = "1.0";
pub const CAPABILITY_PROBE: &str = "X-WHOIS-COLOR-PROBE: v1.0\r\n";
pub const COLOR_REQUEST_PREFIX: &str = "X-WHOIS-COLOR: ";
pub const CAPABILITY_RESPONSE_PREFIX: &str = "X-WHOIS-COLOR-SUPPORT: ";
pub const CAPABILITY_TIMEOUT_MS: u64 = 2000; // 2 seconds for capability probe

impl WhoisColorProtocol {
    /// Probe server for color protocol support
    /// This method sends a capability probe and waits for a response
    /// If no response or timeout, assumes standard WHOIS server
    pub fn probe_capabilities(
        &self, 
        server_address: &str,
        verbose: bool
    ) -> Result<ServerCapabilities> {
        if verbose {
            println!("Probing color capabilities for: {}", server_address);
        }

        let mut stream = TcpStream::connect(server_address)
            .with_context(|| format!("Cannot connect to server for capability probe: {}", server_address))?;
        
        // Set shorter timeout for capability probe
        stream.set_read_timeout(Some(Duration::from_millis(CAPABILITY_TIMEOUT_MS)))
            .context("Failed to set read timeout for capability probe")?;
        
        stream.set_write_timeout(Some(Duration::from_millis(CAPABILITY_TIMEOUT_MS)))
            .context("Failed to set write timeout for capability probe")?;

        // Send capability probe
        // Format: "X-WHOIS-COLOR-PROBE: v1.0\r\n\r\n"
        let probe_query = format!("{}\r\n", CAPABILITY_PROBE);
        
        if let Err(_) = stream.write_all(probe_query.as_bytes()) {
            // If write fails, assume standard WHOIS server
            if verbose {
                println!("Capability probe write failed, assuming standard WHOIS");
            }
            return Ok(ServerCapabilities::default());
        }

        // Try to read response
        let mut response = String::new();
        match stream.read_to_string(&mut response) {
            Ok(_) => {
                let capabilities = self.parse_capability_response(&response);
                if verbose {
                    println!("Server capabilities: {:?}", capabilities);
                }
                Ok(capabilities)
            }
            Err(_) => {
                // Timeout or read error - assume standard WHOIS server
                if verbose {
                    println!("No capability response, assuming standard WHOIS");
                }
                Ok(ServerCapabilities::default())
            }
        }
    }

    /// Parse capability response from server
    /// Expected format: "X-WHOIS-COLOR-SUPPORT: v1.0 schemes=ripe,bgptools,mtf\r\n"
    fn parse_capability_response(&self, response: &str) -> ServerCapabilities {
        for line in response.lines() {
            let line = line.trim();
            if line.starts_with(CAPABILITY_RESPONSE_PREFIX) {
                return self.parse_capability_line(&line[CAPABILITY_RESPONSE_PREFIX.len()..]);
            }
        }
        ServerCapabilities::default()
    }

    /// Parse a single capability line
    /// Format: "v1.0 schemes=ripe,bgptools,mtf"
    fn parse_capability_line(&self, capability_data: &str) -> ServerCapabilities {
        let parts: Vec<&str> = capability_data.split_whitespace().collect();
        if parts.is_empty() {
            return ServerCapabilities::default();
        }

        let mut capabilities = ServerCapabilities {
            supports_color: true,
            protocol_version: parts[0].to_string(),
            color_schemes: vec![],
        };

        // Parse additional parameters
        for part in &parts[1..] {
            if let Some(schemes_part) = part.strip_prefix("schemes=") {
                capabilities.color_schemes = schemes_part
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        capabilities
    }

    /// Perform query with color protocol support
    /// If server supports color, request colored output
    /// Otherwise, fall back to standard query
    pub fn query_with_color(
        &self,
        server_address: &str,
        query: &str,
        capabilities: &ServerCapabilities,
        preferred_scheme: Option<&str>,
        verbose: bool
    ) -> Result<String> {
        let mut stream = TcpStream::connect(server_address)
            .with_context(|| format!("Cannot connect to WHOIS server: {}", server_address))?;
        
        stream.set_read_timeout(Some(Duration::from_secs(10)))
            .context("Failed to set read timeout")?;
        
        stream.set_write_timeout(Some(Duration::from_secs(10)))
            .context("Failed to set write timeout")?;

        let query_string = if capabilities.supports_color {
            self.build_color_query(query, capabilities, preferred_scheme, verbose)
        } else {
            // Standard WHOIS query
            format!("{}\r\n", query)
        };

        if verbose && capabilities.supports_color {
            println!("Sending color-enabled query");
        }

        stream.write_all(query_string.as_bytes())
            .context("Failed to write query to WHOIS server")?;
        
        let mut response = String::new();
        stream.read_to_string(&mut response)
            .context("Failed to read response from WHOIS server")?;
        
        Ok(response)
    }

    /// Build query string with color protocol headers
    /// Format: "X-WHOIS-COLOR: scheme=ripe\r\nquery\r\n"
    fn build_color_query(
        &self,
        query: &str,
        capabilities: &ServerCapabilities,
        preferred_scheme: Option<&str>,
        verbose: bool
    ) -> String {
        let scheme = self.select_color_scheme(capabilities, preferred_scheme);
        
        if let Some(scheme) = scheme {
            if verbose {
                println!("Requesting server-side coloring with scheme: {}", scheme);
            }
            format!("{}scheme={}\r\n{}\r\n", COLOR_REQUEST_PREFIX, scheme, query)
        } else {
            // No suitable scheme, use standard query
            if verbose {
                println!("No suitable color scheme, falling back to standard query");
            }
            format!("{}\r\n", query)
        }
    }

    /// Select appropriate color scheme based on server capabilities and preference
    fn select_color_scheme(
        &self,
        capabilities: &ServerCapabilities,
        preferred_scheme: Option<&str>
    ) -> Option<String> {
        if !capabilities.supports_color {
            return None;
        }

        // If preferred scheme is supported, use it
        if let Some(preferred) = preferred_scheme {
            if capabilities.color_schemes.contains(&preferred.to_string()) {
                return Some(preferred.to_string());
            }
        }

        // Otherwise, use first available scheme
        capabilities.color_schemes.first().cloned()
    }

    /// Check if response contains server-generated colors
    /// Server-colored responses should contain color control sequences
    pub fn is_server_colored(&self, response: &str) -> bool {
        // Check for ANSI color escape sequences
        response.contains("\x1b[") || 
        // Check for color protocol markers (optional)
        response.contains("X-WHOIS-COLOR-APPLIED:")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_capability_response() {
        let protocol = WhoisColorProtocol;
        
        let response = "X-WHOIS-COLOR-SUPPORT: v1.0 schemes=ripe,bgptools,mtf\r\n";
        let capabilities = protocol.parse_capability_response(response);
        
        assert!(capabilities.supports_color);
        assert_eq!(capabilities.protocol_version, "v1.0");
        assert_eq!(capabilities.color_schemes, vec!["ripe", "bgptools", "mtf"]);
    }

    #[test]
    fn test_parse_capability_response_minimal() {
        let protocol = WhoisColorProtocol;
        
        let response = "X-WHOIS-COLOR-SUPPORT: v1.0\r\n";
        let capabilities = protocol.parse_capability_response(response);
        
        assert!(capabilities.supports_color);
        assert_eq!(capabilities.protocol_version, "v1.0");
        assert!(capabilities.color_schemes.is_empty());
    }

    #[test]
    fn test_parse_capability_response_no_support() {
        let protocol = WhoisColorProtocol;
        
        let response = "Some other response\r\n";
        let capabilities = protocol.parse_capability_response(response);
        
        assert!(!capabilities.supports_color);
        assert_eq!(capabilities.protocol_version, "none");
        assert!(capabilities.color_schemes.is_empty());
    }

    #[test]
    fn test_select_color_scheme_preferred() {
        let protocol = WhoisColorProtocol;
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string(), "bgptools".to_string()],
            protocol_version: "v1.0".to_string(),
        };
        
        let scheme = protocol.select_color_scheme(&capabilities, Some("bgptools"));
        assert_eq!(scheme, Some("bgptools".to_string()));
    }

    #[test]
    fn test_select_color_scheme_fallback() {
        let protocol = WhoisColorProtocol;
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string(), "bgptools".to_string()],
            protocol_version: "v1.0".to_string(),
        };
        
        let scheme = protocol.select_color_scheme(&capabilities, Some("invalid"));
        assert_eq!(scheme, Some("ripe".to_string()));
    }

    #[test]
    fn test_select_color_scheme_no_support() {
        let protocol = WhoisColorProtocol;
        let capabilities = ServerCapabilities::default();
        
        let scheme = protocol.select_color_scheme(&capabilities, Some("ripe"));
        assert_eq!(scheme, None);
    }

    #[test]
    fn test_build_color_query() {
        let protocol = WhoisColorProtocol;
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string()],
            protocol_version: "v1.0".to_string(),
        };
        
        let query = protocol.build_color_query("example.com", &capabilities, Some("ripe"), false);
        assert_eq!(query, "X-WHOIS-COLOR: scheme=ripe\r\nexample.com\r\n");
    }

    #[test]
    fn test_build_color_query_no_scheme() {
        let protocol = WhoisColorProtocol;
        let capabilities = ServerCapabilities::default();
        
        let query = protocol.build_color_query("example.com", &capabilities, Some("ripe"), false);
        assert_eq!(query, "example.com\r\n");
    }

    #[test]
    fn test_is_server_colored() {
        let protocol = WhoisColorProtocol;
        
        assert!(protocol.is_server_colored("text with \x1b[31mcolor\x1b[0m"));
        assert!(protocol.is_server_colored("X-WHOIS-COLOR-APPLIED: ripe\ntext"));
        assert!(!protocol.is_server_colored("plain text"));
    }
}