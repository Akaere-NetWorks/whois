use anyhow::Result;
use clap::Parser;
use colored::*;

use whois::{Cli, WhoisQuery, OutputColorizer, ColorScheme};

fn main() -> Result<()> {
    let args = Cli::parse();
    
    if args.verbose {
        println!("{}: {}", "Query".bright_green(), args.domain.bright_white());
    }
    
    // Auto-detect DN42 ASNs for verbose output
    if args.use_dn42() && args.verbose {
        if args.dn42 {
            println!("{}: {}", "Using DN42 server (from --42 flag)".bright_cyan(), args.domain.bright_white());
        } else {
            println!("{}: {}", "Detected DN42 ASN pattern".bright_blue(), args.domain.bright_white());
        }
    }
    
    // Create query handler
    let query_handler = WhoisQuery::new(args.verbose);
    
    // Perform the query
    let result = match query_handler.query(
        &args.domain,
        args.use_dn42(),
        args.use_bgptools(),
        args.server.as_deref(),
        args.port,
    ) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("{}: {}", "Query failed".bright_red(), err);
            std::process::exit(1);
        }
    };
    
    if args.verbose {
        println!("{}: {}", "Final server used".bright_cyan(), result.server_used.host.yellow());
    }
    
    // Handle output
    if !result.response.trim().is_empty() {
        let output = if args.use_color() {
            let scheme = if args.use_mtf_colors() {
                ColorScheme::Mtf
            } else {
                OutputColorizer::detect_scheme(&result.response)
            };
            OutputColorizer::colorize(&result.response, scheme)
        } else {
            result.response
        };
        
        println!("{}", output);
        Ok(())
    } else {
        eprintln!("{}", "Empty response received. Please check if your query is correct.".bright_red());
        std::process::exit(1);
    }
}
