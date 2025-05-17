use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use anyhow::{Context, Result};
use clap::Parser;

const DEFAULT_WHOIS_SERVER: &str = "whois.ripe.net";
const DEFAULT_WHOIS_PORT: u16 = 43;
const TIMEOUT_SECONDS: u64 = 10;

#[derive(Parser)]
#[command(author, version, about = "A simple WHOIS query tool")]
struct Cli {
    /// Domain name or IP address to query
    domain: String,

    /// WHOIS server to use
    #[arg(short, long)]
    server: Option<String>,

    /// Port number to use
    #[arg(short, long, default_value_t = DEFAULT_WHOIS_PORT)]
    port: u16,

    /// Display verbose output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    
    let server = args.server.unwrap_or_else(|| DEFAULT_WHOIS_SERVER.to_string());
    let port = args.port;
    let verbose = args.verbose;
    
    if verbose {
        println!("Query: {}", args.domain);
        println!("Server: {}:{}", server, port);
    }
    
    match query_whois(&args.domain, &server, port) {
        Ok(result) => {
            if !result.trim().is_empty() {
                println!("{}", result);
                Ok(())
            } else {
                println!("Empty response received. Please check if your query is correct.");
                std::process::exit(1);
            }
        },
        Err(err) => {
            eprintln!("Query failed: {}", err);
            
            // Try to recommend a suitable WHOIS server
            if let Some(recommended_server) = recommend_server(&args.domain) {
                if server != recommended_server {
                    eprintln!("\nTip: For '{}' you might want to use '{}' server.", 
                              args.domain, recommended_server);
                    eprintln!("Try: whois {} --server {}", args.domain, recommended_server);
                }
            }
            
            std::process::exit(1);
        }
    }
}

fn query_whois(query: &str, server: &str, port: u16) -> Result<String> {
    let address = format!("{}:{}", server, port);
    
    let mut stream = TcpStream::connect(&address)
        .with_context(|| format!("Cannot connect to WHOIS server: {}", address))?;
    
    stream.set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
        .context("Failed to set read timeout")?;
    
    stream.set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECONDS)))
        .context("Failed to set write timeout")?;
    
    let query = format!("{}\r\n", query);
    stream.write_all(query.as_bytes())
        .context("Failed to write query to WHOIS server")?;
    
    let mut response = String::new();
    stream.read_to_string(&mut response)
        .context("Failed to read response from WHOIS server")?;
    
    Ok(response)
}

fn recommend_server(domain: &str) -> Option<String> {
    // Simple TLD detection logic to recommend different WHOIS servers
    if domain.ends_with(".com") || domain.ends_with(".net") || domain.ends_with(".edu") {
        Some("whois.verisign-grs.com".to_string())
    } else if domain.ends_with(".org") {
        Some("whois.pir.org".to_string())
    } else if domain.ends_with(".ru") {
        Some("whois.tcinet.ru".to_string())
    } else if domain.ends_with(".cn") {
        Some("whois.cnnic.cn".to_string())
    } else if domain.ends_with(".uk") {
        Some("whois.nic.uk".to_string())
    } else if domain.ends_with(".jp") {
        Some("whois.jprs.jp".to_string())
    } else if domain.ends_with(".de") {
        Some("whois.denic.de".to_string())
    } else if domain.contains(":") || (domain.chars().all(|c| c.is_digit(10) || c == '.')) {
        // Simple check if it's an IP address or IPv6 address
        Some("whois.arin.net".to_string())
    } else {
        None
    }
}
