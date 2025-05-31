use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use anyhow::{Context, Result};
use crate::servers::{WhoisServer, ServerSelector, DEFAULT_WHOIS_SERVER};

const TIMEOUT_SECONDS: u64 = 10;

#[derive(Debug)]
pub struct QueryResult {
    pub response: String,
    pub server_used: WhoisServer,
}

impl QueryResult {
    pub fn new(response: String, server_used: WhoisServer) -> Self {
        Self { response, server_used }
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
} 