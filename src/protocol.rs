//! WHOIS-COLOR protocol implementation (v1.1).
//!
//! A backward-compatible extension to the standard WHOIS protocol that allows
//! clients to request server-side colorization, Markdown-formatted output,
//! and image display support via capability probing and HTTP-style headers.
//!
//! # Protocol Flow
//!
//! 1. Send a `X-WHOIS-COLOR-PROBE` to discover server capabilities
//! 2. Parse the `X-WHOIS-COLOR-SUPPORT` response into [`ServerCapabilities`]
//! 3. Build an enhanced query with `X-WHOIS-COLOR`, `X-WHOIS-MARKDOWN`,
//!    and/or `X-WHOIS-IMAGES` headers
//! 4. Non-supporting servers ignore unknown headers and respond normally

use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use anyhow::{Context, Result};

/// WHOIS-COLOR Protocol v1.1.
///
/// A backward-compatible extension protocol for server-side colorization,
/// Markdown rendering, and image display support.
pub struct WhoisColorProtocol;

/// Server capability information from a WHOIS-COLOR capability probe.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerCapabilities {
    /// Whether the server supports the WHOIS-COLOR protocol.
    pub supports_color: bool,
    /// List of color scheme names the server can apply (e.g., `ripe`, `bgptools`, `mtf`).
    pub color_schemes: Vec<String>,
    /// Protocol version string (e.g., `"v1.0"`, `"v1.1"`, or `"none"`).
    pub protocol_version: String,
    /// Whether the server supports Markdown-formatted responses.
    pub supports_markdown: bool,
    /// Whether the server supports inline image transmission.
    pub supports_images: bool,
    /// List of image format identifiers the server can provide (e.g., `png`, `jpg`).
    pub image_formats: Vec<String>,
}

impl Default for ServerCapabilities {
    fn default() -> Self {
        Self {
            supports_color: false,
            color_schemes: vec![],
            protocol_version: "none".to_string(),
            supports_markdown: false,
            supports_images: false,
            image_formats: vec![],
        }
    }
}

/// Protocol version string for the current WHOIS-COLOR protocol.
pub const PROTOCOL_VERSION: &str = "1.1";
/// Legacy protocol version string (v1.0 — color only, no markdown/images).
pub const LEGACY_VERSION: &str = "1.0";
/// Capability probe query string sent to discover server features.
pub const CAPABILITY_PROBE: &str = "X-WHOIS-COLOR-PROBE: v1.1\r\n";
/// Prefix for the color scheme request header.
pub const COLOR_REQUEST_PREFIX: &str = "X-WHOIS-COLOR: ";
/// Prefix for the Markdown request header.
pub const MARKDOWN_REQUEST_PREFIX: &str = "X-WHOIS-MARKDOWN: ";
/// Prefix for the image request header.
pub const IMAGE_REQUEST_PREFIX: &str = "X-WHOIS-IMAGES: ";
/// Prefix for the capability response line from the server.
pub const CAPABILITY_RESPONSE_PREFIX: &str = "X-WHOIS-COLOR-SUPPORT: ";
/// Timeout in milliseconds for the capability probe connection.
pub const CAPABILITY_TIMEOUT_MS: u64 = 2000;

impl WhoisColorProtocol {
    /// Probe a server for WHOIS-COLOR protocol support.
    ///
    /// Sends a capability probe (`X-WHOIS-COLOR-PROBE`) and waits for a
    /// structured response. If the probe fails (timeout, connection error,
    /// or unrecognized response) the server is assumed to be a standard
    /// WHOIS server with no capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error only if the TCP connection itself fails. Timeouts
    /// and missing capability responses are handled gracefully by returning
    /// [`ServerCapabilities::default`].
    pub fn probe_capabilities(
        &self, 
        server_address: &str,
        verbose: bool
    ) -> Result<ServerCapabilities> {
        if verbose {
            println!("Probing color capabilities for: {server_address}");
        }

        let mut stream = TcpStream::connect(server_address)
            .with_context(|| format!("Cannot connect to server for capability probe: {server_address}"))?;
        
        // Set shorter timeout for capability probe
        stream.set_read_timeout(Some(Duration::from_millis(CAPABILITY_TIMEOUT_MS)))
            .context("Failed to set read timeout for capability probe")?;
        
        stream.set_write_timeout(Some(Duration::from_millis(CAPABILITY_TIMEOUT_MS)))
            .context("Failed to set write timeout for capability probe")?;

        // Send capability probe
        // Format: "X-WHOIS-COLOR-PROBE: v1.0\r\n\r\n"
        let probe_query = format!("{CAPABILITY_PROBE}\r\n");
        
        if stream.write_all(probe_query.as_bytes()).is_err() {
            // If write fails, assume standard WHOIS server
            if verbose {
                println!("Capability probe write failed, assuming standard WHOIS");
            }
            return Ok(ServerCapabilities::default());
        }

        // Try to read response
        let mut response = String::new();
        if stream.read_to_string(&mut response).is_ok() {
            let capabilities = Self::parse_capability_response(&response);
            if verbose {
                println!("Server capabilities: {capabilities:?}");
            }
            Ok(capabilities)
        } else {
            // Timeout or read error - assume standard WHOIS server
            if verbose {
                println!("No capability response, assuming standard WHOIS");
            }
            Ok(ServerCapabilities::default())
        }
    }

    /// Parse capability response from server
    /// Expected format: "X-WHOIS-COLOR-SUPPORT: v1.1 schemes=ripe,bgptools,mtf markdown=true images=png,jpg\r\n"
    /// Legacy format: "X-WHOIS-COLOR-SUPPORT: v1.0 schemes=ripe,bgptools,mtf\r\n"
    fn parse_capability_response(response: &str) -> ServerCapabilities {
        for line in response.lines() {
            let line = line.trim();
            if let Some(stripped) = line.strip_prefix(CAPABILITY_RESPONSE_PREFIX) {
                return Self::parse_capability_line(stripped);
            }
        }
        ServerCapabilities::default()
    }

    /// Parse a single capability line
    /// Format v1.1: "v1.1 schemes=ripe,bgptools,mtf markdown=true images=png,jpg"
    /// Format v1.0: "v1.0 schemes=ripe,bgptools,mtf"
    fn parse_capability_line(capability_data: &str) -> ServerCapabilities {
        let parts: Vec<&str> = capability_data.split_whitespace().collect();
        if parts.is_empty() {
            return ServerCapabilities::default();
        }

        let protocol_version = parts[0].to_string();
        let mut capabilities = ServerCapabilities {
            supports_color: true,
            protocol_version,
            color_schemes: vec![],
            supports_markdown: false,
            supports_images: false,
            image_formats: vec![],
        };

        // Parse additional parameters
        for part in &parts[1..] {
            if let Some(schemes_part) = part.strip_prefix("schemes=") {
                capabilities.color_schemes = schemes_part
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            } else if let Some(markdown_part) = part.strip_prefix("markdown=") {
                capabilities.supports_markdown = markdown_part == "true";
            } else if let Some(images_part) = part.strip_prefix("images=") {
                capabilities.supports_images = !images_part.is_empty();
                capabilities.image_formats = images_part
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }

        capabilities
    }

    /// Perform a WHOIS query with enhanced protocol support (color, markdown,
    /// images). Falls back to a standard plain-text query for older servers.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP connection fails, timeouts cannot be set,
    /// writing the query fails, or reading the response fails.
    #[expect(clippy::too_many_arguments, reason = "protocol query requires many parameters")]
    pub fn query_with_enhanced_protocol(
        &self,
        server_address: &str,
        query: &str,
        capabilities: &ServerCapabilities,
        preferred_scheme: Option<&str>,
        enable_markdown: bool,
        enable_images: bool,
        verbose: bool
    ) -> Result<String> {
        let mut stream = TcpStream::connect(server_address)
            .with_context(|| format!("Cannot connect to WHOIS server: {server_address}"))?;
        
        stream.set_read_timeout(Some(Duration::from_secs(10)))
            .context("Failed to set read timeout")?;
        
        stream.set_write_timeout(Some(Duration::from_secs(10)))
            .context("Failed to set write timeout")?;

        let query_string = if capabilities.supports_color || capabilities.supports_markdown || capabilities.supports_images {
            Self::build_enhanced_query(query, capabilities, preferred_scheme, enable_markdown, enable_images, verbose)
        } else {
            // Standard WHOIS query
            format!("{query}\r\n")
        };

        if verbose {
            if capabilities.supports_color {
                println!("Sending color-enabled query");
            }
            if capabilities.supports_markdown && enable_markdown {
                println!("Requesting Markdown format");
            }
            if capabilities.supports_images && enable_images {
                println!("Requesting image support");
            }
        }

        stream.write_all(query_string.as_bytes())
            .context("Failed to write query to WHOIS server")?;
        
        let mut response = String::new();
        stream.read_to_string(&mut response)
            .context("Failed to read response from WHOIS server")?;
        
        Ok(response)
    }

    /// Build query string with enhanced protocol headers
    /// Format v1.1: "X-WHOIS-COLOR: scheme=ripe\r\nX-WHOIS-MARKDOWN: true\r\nX-WHOIS-IMAGES: png,jpg\r\nquery\r\n"
    /// Format v1.0: "X-WHOIS-COLOR: scheme=ripe\r\nquery\r\n"
    fn build_enhanced_query(
        query: &str,
        capabilities: &ServerCapabilities,
        preferred_scheme: Option<&str>,
        enable_markdown: bool,
        enable_images: bool,
        verbose: bool
    ) -> String {
        let mut headers = String::new();
        
        // Add color header if supported
        if capabilities.supports_color {
            if let Some(scheme) = Self::select_color_scheme(capabilities, preferred_scheme) {
                if verbose {
                    println!("Requesting server-side coloring with scheme: {scheme}");
                }
                let _ = write!(headers, "{COLOR_REQUEST_PREFIX}scheme={scheme}\r\n");
            }
        }
        
        // Add markdown header if supported and requested
        if capabilities.supports_markdown && enable_markdown {
            let _ = write!(headers, "{MARKDOWN_REQUEST_PREFIX}true\r\n");
        }
        
        // Add images header if supported and requested
        if capabilities.supports_images && enable_images && !capabilities.image_formats.is_empty() {
            let formats = capabilities.image_formats.join(",");
            let _ = write!(headers, "{IMAGE_REQUEST_PREFIX}{formats}\r\n");
        }
        
        if headers.is_empty() {
            // No protocol features, use standard query
            format!("{query}\r\n")
        } else {
            // Enhanced protocol query
            format!("{headers}{query}\r\n")
        }
    }

    /// Legacy method for backward compatibility
    /// Build query string with color protocol headers
    /// Format: "X-WHOIS-COLOR: scheme=ripe\r\nquery\r\n"
    #[allow(dead_code)]
    fn build_color_query(
        query: &str,
        capabilities: &ServerCapabilities,
        preferred_scheme: Option<&str>,
        verbose: bool
    ) -> String {
        let scheme = Self::select_color_scheme(capabilities, preferred_scheme);
        
        if let Some(scheme) = scheme {
            if verbose {
                println!("Requesting server-side coloring with scheme: {scheme}");
            }
            format!("{COLOR_REQUEST_PREFIX}scheme={scheme}\r\n{query}\r\n")
        } else {
            // No suitable scheme, use standard query
            if verbose {
                println!("No suitable color scheme, falling back to standard query");
            }
            format!("{query}\r\n")
        }
    }

    /// Select appropriate color scheme based on server capabilities and preference
    fn select_color_scheme(
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
    #[must_use] 
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
    fn test_parse_capability_response_v10() {
        let response = "X-WHOIS-COLOR-SUPPORT: v1.0 schemes=ripe,bgptools,mtf\r\n";
        let capabilities = WhoisColorProtocol::parse_capability_response(response);
        
        assert!(capabilities.supports_color);
        assert_eq!(capabilities.protocol_version, "v1.0");
        assert_eq!(capabilities.color_schemes, vec!["ripe", "bgptools", "mtf"]);
        assert!(!capabilities.supports_markdown); // v1.0 doesn't support markdown
        assert!(!capabilities.supports_images); // v1.0 doesn't support images
    }

    #[test]
    fn test_parse_capability_response_v11() {
        let response = "X-WHOIS-COLOR-SUPPORT: v1.1 schemes=ripe,bgptools,mtf markdown=true images=png,jpg\r\n";
        let capabilities = WhoisColorProtocol::parse_capability_response(response);
        
        assert!(capabilities.supports_color);
        assert_eq!(capabilities.protocol_version, "v1.1");
        assert_eq!(capabilities.color_schemes, vec!["ripe", "bgptools", "mtf"]);
        assert!(capabilities.supports_markdown);
        assert!(capabilities.supports_images);
        assert_eq!(capabilities.image_formats, vec!["png", "jpg"]);
    }

    #[test]
    fn test_parse_capability_response_minimal() {
        let response = "X-WHOIS-COLOR-SUPPORT: v1.0\r\n";
        let capabilities = WhoisColorProtocol::parse_capability_response(response);
        
        assert!(capabilities.supports_color);
        assert_eq!(capabilities.protocol_version, "v1.0");
        assert!(capabilities.color_schemes.is_empty());
    }

    #[test]
    fn test_parse_capability_response_no_support() {
        let response = "Some other response\r\n";
        let capabilities = WhoisColorProtocol::parse_capability_response(response);
        
        assert!(!capabilities.supports_color);
        assert_eq!(capabilities.protocol_version, "none");
        assert!(capabilities.color_schemes.is_empty());
    }

    #[test]
    fn test_select_color_scheme_preferred() {
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string(), "bgptools".to_string()],
            protocol_version: "v1.0".to_string(),
            supports_markdown: false,
            supports_images: false,
            image_formats: vec![],
        };
        
        let scheme = WhoisColorProtocol::select_color_scheme(&capabilities, Some("bgptools"));
        assert_eq!(scheme, Some("bgptools".to_string()));
    }

    #[test]
    fn test_select_color_scheme_fallback() {
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string(), "bgptools".to_string()],
            protocol_version: "v1.0".to_string(),
            supports_markdown: false,
            supports_images: false,
            image_formats: vec![],
        };
        
        let scheme = WhoisColorProtocol::select_color_scheme(&capabilities, Some("invalid"));
        assert_eq!(scheme, Some("ripe".to_string()));
    }

    #[test]
    fn test_select_color_scheme_no_support() {
        let capabilities = ServerCapabilities::default();
        
        let scheme = WhoisColorProtocol::select_color_scheme(&capabilities, Some("ripe"));
        assert_eq!(scheme, None);
    }

    #[test]
    fn test_build_enhanced_query_v10_compat() {
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string()],
            protocol_version: "v1.0".to_string(),
            supports_markdown: false,
            supports_images: false,
            image_formats: vec![],
        };
        
        let query = WhoisColorProtocol::build_enhanced_query("example.com", &capabilities, Some("ripe"), false, false, false);
        assert_eq!(query, "X-WHOIS-COLOR: scheme=ripe\r\nexample.com\r\n");
    }

    #[test]
    fn test_build_enhanced_query_v11_full() {
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string()],
            protocol_version: "v1.1".to_string(),
            supports_markdown: true,
            supports_images: true,
            image_formats: vec!["png".to_string(), "jpg".to_string()],
        };
        
        let query = WhoisColorProtocol::build_enhanced_query("example.com", &capabilities, Some("ripe"), true, true, false);
        let expected = "X-WHOIS-COLOR: scheme=ripe\r\nX-WHOIS-MARKDOWN: true\r\nX-WHOIS-IMAGES: png,jpg\r\nexample.com\r\n";
        assert_eq!(query, expected);
    }

    #[test]
    fn test_build_color_query_legacy() {
        let capabilities = ServerCapabilities {
            supports_color: true,
            color_schemes: vec!["ripe".to_string()],
            protocol_version: "v1.0".to_string(),
            supports_markdown: false,
            supports_images: false,
            image_formats: vec![],
        };
        
        let query = WhoisColorProtocol::build_color_query("example.com", &capabilities, Some("ripe"), false);
        assert_eq!(query, "X-WHOIS-COLOR: scheme=ripe\r\nexample.com\r\n");
    }

    #[test]
    fn test_build_color_query_no_scheme() {
        let capabilities = ServerCapabilities::default();
        
        let query = WhoisColorProtocol::build_color_query("example.com", &capabilities, Some("ripe"), false);
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