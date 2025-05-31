use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use std::env;

const IANA_WHOIS_SERVER: &str = "whois.iana.org";
const DEFAULT_WHOIS_SERVER: &str = "whois.ripe.net";
const DEFAULT_WHOIS_PORT: u16 = 43;
const TIMEOUT_SECONDS: u64 = 10;
const DN42_WHOIS_SERVER: &str = "lantian.pub";
const DN42_WHOIS_PORT: u16 = 43;
const BGPTOOLS_WHOIS_SERVER: &str = "bgp.tools";
const BGPTOOLS_WHOIS_PORT: u16 = 43;

#[derive(Parser)]
#[command(author, version, about = "A simple WHOIS query tool")]
struct Cli {
    /// Domain name or IP address to query
    domain: String,

    /// WHOIS server to use (bypasses IANA lookup)
    #[arg(short, long)]
    server: Option<String>,

    /// Port number to use
    #[arg(short, long, default_value_t = DEFAULT_WHOIS_PORT)]
    port: u16,

    /// Display verbose output
    #[arg(short, long)]
    verbose: bool,
    
    /// Query DN42 information from lantian.pub
    #[arg(long = "42")]
    dn42: bool,
    
    /// Query from bgp.tools
    #[arg(long)]
    bgptools: bool,
    
    /// Disable colored output
    #[arg(long)]
    no_color: bool,
    
    /// Easter egg: MTF flag colors (hidden option)
    #[arg(long, hide = true)]
    mtf: bool,
}

fn main() -> Result<()> {
    let args = Cli::parse();
    let port = args.port;
    let verbose = args.verbose;
    let use_color = !args.no_color;
    let mtf_colors = args.mtf;
    
    // Check for WHOIS_SERVER environment variable if --server is not provided
    // This works on both Linux and Windows
    let env_server = if args.server.is_none() {
        env::var("WHOIS_SERVER").ok()
    } else {
        None
    };
    
    if verbose {
        println!("{}: {}", "Query".bright_green(), args.domain.bright_white());
    }
    
    // Auto-detect DN42 ASNs (AS42424xxxxx)
    let is_dn42_asn = args.domain.to_uppercase().starts_with("AS42424");
    
    if is_dn42_asn && verbose {
        println!("{}: {}", "Detected DN42 ASN pattern".bright_blue(), args.domain.bright_white());
    }
    
    // Process based on the provided flags
    let result = if args.dn42 || is_dn42_asn {
        if verbose {
            if args.dn42 {
                println!("{}: {}:{} (from --42 flag)", 
                    "Using DN42 WHOIS server".bright_cyan(), 
                    DN42_WHOIS_SERVER.yellow(), 
                    DN42_WHOIS_PORT.to_string().yellow());
            } else {
                println!("{}: {}:{} (auto-detected from ASN)", 
                    "Using DN42 WHOIS server".bright_cyan(), 
                    DN42_WHOIS_SERVER.yellow(), 
                    DN42_WHOIS_PORT.to_string().yellow());
            }
        }
        query_whois(&args.domain, DN42_WHOIS_SERVER, DN42_WHOIS_PORT)
    } else if args.bgptools {
        if verbose {
            println!("{}: {}:{}", 
                "Using BGP.tools WHOIS server".bright_cyan(), 
                BGPTOOLS_WHOIS_SERVER.yellow(), 
                BGPTOOLS_WHOIS_PORT.to_string().yellow());
        }
        query_whois(&args.domain, BGPTOOLS_WHOIS_SERVER, BGPTOOLS_WHOIS_PORT)
    } else if let Some(server) = &args.server {
        // Direct server specified
        if verbose {
            println!("{}: {}:{} (user-specified)", 
                "Server".bright_cyan(), 
                server.yellow(), 
                port.to_string().yellow());
        }
        query_whois(&args.domain, server, port)
    } else if let Some(env_server) = env_server {
        // Use WHOIS_SERVER from environment variable
        if verbose {
            println!("{}: {}:{} (from WHOIS_SERVER env)", 
                "Server".bright_cyan(), 
                env_server.yellow(), 
                port.to_string().yellow());
        }
        query_whois(&args.domain, &env_server, port)
    } else {
        // Default behavior: query through IANA
        let (final_result, used_server) = query_with_iana_referral(&args.domain, port, verbose, use_color)?;
        if verbose {
            println!("{}: {}", "Final server used".bright_cyan(), used_server.yellow());
        }
        Ok(final_result)
    };
    
    match result {
        Ok(output) => {
            if !output.trim().is_empty() {
                println!("{}", if use_color { 
                    // Detect and apply appropriate colorization based on format
                    if mtf_colors {
                        colorize_mtf_output(&output)
                    } else if is_bgp_tools_format(&output) {
                        colorize_bgptools_output(&output)
                    } else {
                        colorize_ripe_output(&output)
                    }
                } else { 
                    output 
                });
                Ok(())
            } else {
                eprintln!("{}", "Empty response received. Please check if your query is correct.".bright_red());
                std::process::exit(1);
            }
        },
        Err(err) => {
            eprintln!("{}: {}", "Query failed".bright_red(), err);
            std::process::exit(1);
        }
    }
}

fn query_with_iana_referral(query: &str, port: u16, verbose: bool, _use_color: bool) -> Result<(String, String)> {
    if verbose {
        println!("{} {}:{}", 
            "First querying IANA at".bright_blue(), 
            IANA_WHOIS_SERVER.yellow(), 
            port.to_string().yellow());
    }
    
    // First query IANA
    let iana_response = query_whois(query, IANA_WHOIS_SERVER, port)?;
    
    // Extract the referral WHOIS server from IANA's response
    let whois_server = extract_whois_server(&iana_response)
        .unwrap_or_else(|| DEFAULT_WHOIS_SERVER.to_string());
    
    if verbose {
        if whois_server != DEFAULT_WHOIS_SERVER {
            println!("{}: {}", "IANA referred to".bright_blue(), whois_server.yellow());
        } else {
            println!("{}: {}", "No referral found, using default".bright_yellow(), DEFAULT_WHOIS_SERVER.yellow());
        }
    }
    
    // Query the actual WHOIS server
    let final_response = query_whois(query, &whois_server, port)?;
    
    Ok((final_response, whois_server))
}

fn extract_whois_server(response: &str) -> Option<String> {
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

// Detect if the output is in BGP Tools format
fn is_bgp_tools_format(output: &str) -> bool {
    let lines: Vec<&str> = output.lines().collect();
    if lines.len() >= 2 {
        // Check if first line contains a typical BGP Tools header
        let first_line = lines[0].trim();
        return first_line.contains("AS") && 
               first_line.contains("|") && 
               (first_line.contains("BGP") || 
                first_line.contains("CC") || 
                first_line.contains("Registry"));
    }
    false
}

// Colorize RIPE format output (used for RIPE and most WHOIS responses)
fn colorize_ripe_output(output: &str) -> String {
    let mut colored_lines = Vec::new();
    let mut in_comment_block = false;
    
    for line in output.lines() {
        // Handle comment lines (starting with %, # or empty remarks)
        if line.starts_with('%') || line.starts_with('#') || line.starts_with("remarks:") {
            colored_lines.push(line.bright_black().to_string());
            in_comment_block = true;
            continue;
        }
        
        // If we were in a comment block and hit an empty line, keep the comment block state
        if in_comment_block && line.trim().is_empty() {
            colored_lines.push(line.to_string());
            continue;
        }
        
        // End comment block on non-comment, non-empty line
        if in_comment_block && !line.trim().is_empty() {
            in_comment_block = false;
        }
        
        // Handle empty lines
        if line.trim().is_empty() {
            colored_lines.push(line.to_string());
            continue;
        }
        
        // Handle RIPE format field: value pairs
        if line.contains(':') {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                let field = parts[0].trim();
                let value = parts[1].trim();
                
                // Color field name (left side of colon)
                let colored_field = match field.to_lowercase().as_str() {
                    // Main fields - cyan
                    "aut-num" | "as-block" | "inet6num" | "inetnum" | "route" | "route6" | "netname" =>
                        field.bright_cyan().to_string(),
                    
                    // Domain name specific fields - bright cyan
                    "domain" | "domain name" =>
                        field.bright_cyan().bold().to_string(),
                    
                    // DNS servers - yellow
                    "nserver" | "name server" | "nameserver" | "name servers" =>
                        field.yellow().bold().to_string(),
                    
                    // Domain status fields - bright yellow
                    "domain status" | "status" =>
                        field.bright_yellow().to_string(),
                    
                    // Registrar information - bright blue
                    "registrar" | "sponsoring registrar" | "registrar iana id" | "reseller" =>
                        field.bright_blue().to_string(),
                    
                    // Registry specific - blue
                    "registry domain id" | "registrar whois server" | "registrar url" =>
                        field.blue().to_string(),
                    
                    // Dates for domains - magenta
                    "creation date" | "created" | "created on" | "registration date" |
                    "updated date" | "last modified" | "last update" |
                    "expiration date" | "expiry date" | "registry expiry date" | "registrar registration expiration date" =>
                        field.bright_magenta().to_string(),
                    
                    // Privacy/WHOIS protection - red
                    "privacy" | "whois privacy" | "domain privacy" =>
                        field.bright_red().to_string(),
                    
                    // Name fields - green
                    "as-name" | "org-name" | "role" | "person" | "registrant name" | "admin name" | "tech name" =>
                        field.bright_green().to_string(),
                    
                    // Organization fields - yellow
                    "org" | "organisation" | "org-type" | "registrant organization" | "registrant" =>
                        field.yellow().to_string(),
                    
                    // Contact fields - green
                    "admin-c" | "tech-c" | "abuse-c" | "nic-hdl" | "abuse-mailbox" |
                    "registrant contact" | "admin contact" | "technical contact" | "billing contact" =>
                        field.green().to_string(),
                    
                    // Maintainer fields - blue
                    "mnt-by" | "mnt-ref" | "mnt-domains" | "mnt-lower" | "mnt-routes" =>
                        field.bright_blue().to_string(),
                    
                    // Import/Export - magenta
                    "import" | "export" | "mp-import" | "mp-export" | "default" | "peer" =>
                        field.magenta().to_string(),
                    
                    // Status fields - yellow
                    "sponsoring-org" =>
                        field.bright_yellow().to_string(),
                    
                    // Dates - cyan
                    "changed" =>
                        field.bright_cyan().to_string(),
                    
                    // Location - white
                    "country" | "address" | "source" | "registrant country" | "admin country" | "tech country" =>
                        field.bright_white().to_string(),
                    
                    // Communication - blue
                    "e-mail" | "email" | "phone" | "registrant email" | "admin email" | "tech email" =>
                        field.blue().to_string(),
                    
                    // DNSSEC - magenta
                    "dnssec" | "ds record" =>
                        field.magenta().bold().to_string(),
                    
                    // Default for other fields
                    _ => field.white().to_string(),
                };
                
                // Color value based on content and context
                let colored_value = if field.to_lowercase() == "domain" || field.to_lowercase() == "domain name" {
                    // Domain names
                    value.bright_white().bold().to_string()
                } else if field.to_lowercase() == "aut-num" {
                    // AS Numbers for aut-num field
                    value.bright_red().bold().to_string()
                } else if field.to_lowercase() == "status" || field.to_lowercase() == "domain status" {
                    // Status values
                    match value.to_uppercase().as_str() {
                        "ASSIGNED" | "ALLOCATED" => value.bright_green().to_string(),
                        "AVAILABLE" => value.bright_cyan().to_string(),
                        "RESERVED" => value.yellow().to_string(),
                        "CLIENT DELETE PROHIBITED" | "CLIENT TRANSFER PROHIBITED" | "CLIENT UPDATE PROHIBITED" =>
                            value.bright_yellow().to_string(),
                        "INACTIVE" | "PENDING DELETE" => value.bright_red().to_string(),
                        "OK" | "ACTIVE" | "CLIENT OK" => value.bright_green().to_string(),
                        _ => value.bright_yellow().to_string()
                    }
                } else if field.to_lowercase() == "source" {
                    // Source registry
                    value.bright_blue().to_string()
                } else if field.to_lowercase() == "country" || field.to_lowercase().contains("country") {
                    // Country code
                    value.yellow().to_string()
                } else if field.to_lowercase().contains("name server") || field.to_lowercase().contains("nserver") || field.to_lowercase() == "nameserver" {
                    // Name servers
                    value.bright_green().to_string()
                } else if field.to_lowercase().contains("registrar") {
                    // Registrar information
                    value.bright_blue().bold().to_string()
                } else if field.to_lowercase().contains("dnssec") {
                    // DNSSEC status
                    if value.to_lowercase().contains("signed") || value.to_lowercase().contains("yes") {
                        value.bright_green().to_string()
                    } else {
                        value.bright_red().to_string()
                    }
                } else if field.to_lowercase().contains("date") || field.to_lowercase().contains("created") || 
                         field.to_lowercase().contains("changed") || field.to_lowercase().contains("expir") || 
                         field.to_lowercase().contains("update") {
                    // Dates
                    value.bright_magenta().to_string()
                } else if value.contains('@') {
                    // Email addresses
                    value.bright_yellow().to_string()
                } else if field.to_lowercase().contains("phone") {
                    // Phone numbers
                    value.bright_white().to_string()
                } else if value.starts_with("AS") && value[2..].chars().all(|c| c.is_digit(10)) {
                    // AS numbers in values
                    value.bright_red().to_string()
                } else if (field == "import" || field == "export") && value.contains("AS") {
                    // AS numbers in import/export lines - specialized coloring
                    let mut colored_parts = Vec::new();
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    for part in parts {
                        if part.starts_with("AS") && part[2..].chars().all(|c| c.is_digit(10)) {
                            colored_parts.push(part.bright_red().to_string());
                        } else if part == "from" || part == "to" || part == "accept" || part == "announce" {
                            colored_parts.push(part.bright_cyan().to_string());
                        } else {
                            colored_parts.push(part.white().to_string());
                        }
                    }
                    colored_parts.join(" ")
                } else if value.chars().all(|c| c.is_digit(10) || c == '.' || c == ':' || c == '/') {
                    // IP addresses, CIDR blocks
                    value.bright_cyan().to_string()
                } else if field.starts_with("mnt-") {
                    // Maintainer values
                    if value.contains("-") {
                        value.bright_blue().to_string()
                    } else {
                        value.white().to_string()
                    }
                } else if field.to_lowercase() == "as-name" || field.to_lowercase() == "org-name" || field.to_lowercase() == "netname" {
                    // Names
                    value.bright_white().bold().to_string()
                } else if field.to_lowercase() == "role" || field.to_lowercase() == "person" || field.to_lowercase().contains("registrant name") {
                    // Person/role names
                    value.bright_green().bold().to_string()
                } else if field.ends_with("-c") {
                    // Handle handles
                    value.green().to_string()
                } else {
                    // Default
                    value.white().to_string()
                };
                
                colored_lines.push(format!("{}: {}", colored_field, colored_value));
            } else {
                colored_lines.push(line.white().to_string());
            }
        } else if line.contains("error") || line.contains("not found") || line.to_lowercase().contains("no match") {
            // Error messages
            colored_lines.push(line.bright_red().to_string());
        } else if line.contains("available") {
            // Domain availability
            colored_lines.push(line.bright_green().to_string());
        } else {
            // Default coloring for lines without a field:value format
            colored_lines.push(line.white().to_string());
        }
    }
    
    colored_lines.join("\n")
}

// Colorize BGP Tools format output (table format with | separators)
fn colorize_bgptools_output(output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let mut colored_lines = Vec::new();
    let mut headers: Vec<&str> = Vec::new();
    
    // Process each line
    for (i, line) in lines.iter().enumerate() {
        // Skip empty lines
        if line.trim().is_empty() {
            colored_lines.push("".to_string());
            continue;
        }
        
        // Process header row (first non-empty row)
        if i == 0 || (i == 1 && lines[0].trim().is_empty()) {
            headers = line.split('|').map(|s| s.trim()).collect();
            let colored_headers: Vec<String> = headers.iter()
                .map(|&header| header.bright_cyan().bold().to_string())
                .collect();
            colored_lines.push(colored_headers.join(" | "));
            continue;
        }
        
        // Process data rows
        let fields: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        let mut colored_fields = Vec::new();
        
        for (j, field) in fields.iter().enumerate() {
            let header = if j < headers.len() { headers[j] } else { "" };
            
            let colored_field = match header {
                "AS" => field.bright_red().to_string(),
                "IP" | "BGP Prefix" => field.bright_cyan().to_string(),
                "CC" => field.bright_yellow().to_string(),
                "Registry" => field.bright_blue().to_string(),
                "Allocated" => field.bright_magenta().to_string(),
                "AS Name" => field.bright_white().bold().to_string(),
                _ => field.white().to_string(),
            };
            
            colored_fields.push(colored_field);
        }
        
        colored_lines.push(colored_fields.join(" | "));
    }
    
    colored_lines.join("\n")
}

// MTF flag coloring function
fn colorize_mtf_output(output: &str) -> String {
    let mut colored_lines = Vec::new();
    let mut line_count = 0;
    
    for line in output.lines() {
        if line.trim().is_empty() {
            colored_lines.push(line.to_string());
            continue;
        }
        
        // Alternate colors in trans flag pattern (blue, pink, white, pink, blue)
        match line_count % 5 {
            0 => colored_lines.push(line.truecolor(91, 207, 250).to_string()), // Blue #5BCFFA
            1 => colored_lines.push(line.truecolor(245, 171, 185).to_string()), // Pink #F5ABB9
            2 => colored_lines.push(line.truecolor(255, 255, 255).to_string()), // Pure White #FFFFFF
            3 => colored_lines.push(line.truecolor(245, 171, 185).to_string()), // Pink #F5ABB9
            4 => colored_lines.push(line.truecolor(91, 207, 250).to_string()), // Blue #5BCFFA
            _ => unreachable!(),
        }
        
        line_count += 1;
    }
    
    colored_lines.join("\n")
}
