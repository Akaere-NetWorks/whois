use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use anyhow::{Context, Result};
use crate::servers::{WhoisServer, ServerSelector, DEFAULT_WHOIS_SERVER};
use crate::protocol::WhoisColorProtocol;

const TIMEOUT_SECONDS: u64 = 10;

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

        self.query_with_referral(domain, &server)
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

        if use_server_color || enable_markdown || enable_images {
            self.query_with_enhanced_protocol_impl(domain, &server, preferred_color_scheme, enable_markdown, enable_images)
        } else {
            self.query_with_referral(domain, &server)
        }
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

        if use_server_color {
            self.query_with_enhanced_protocol_impl(domain, &server, preferred_color_scheme, false, false)
        } else {
            self.query_with_referral(domain, &server)
        }
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

} 