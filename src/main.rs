use anyhow::Result;
use colored::*;
use clap::Parser;

use whois_cli::{Cli, WhoisQuery, OutputColorizer, ColorScheme, RirHyperlinkProcessor, is_rir_response, MarkdownRenderer};

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
    
    // Determine preferred color scheme for server-side coloring
    let preferred_scheme = if args.use_mtf_colors() {
        Some("mtf")
    } else {
        None
    };

    // Perform the query with enhanced protocol (v1.1) by default
    let result = match query_handler.query_with_enhanced_protocol(
        &args.domain,
        args.use_dn42(),
        args.use_bgptools(),
        args.use_server_color(),
        args.use_markdown(),
        args.use_images(),
        args.server.as_deref(),
        args.port,
        preferred_scheme,
    ) {
        Ok(result) => result,
        Err(err) => {
            eprintln!("{}: {}", "Query failed".bright_red(), err);
            std::process::exit(1);
        }
    };
    
    if args.verbose {
        println!("{}: {}", "Final server used".bright_cyan(), result.server_used.host.yellow());
        if result.server_colored {
            println!("{}: {}", "Server-side coloring".bright_green(), "enabled".bright_green());
        }
    }
    
    // Handle output
    if !result.response.trim().is_empty() {
        let mut output = result.response.clone();
        let mut is_markdown_content = false;
        
        // Check if response contains Markdown and render it
        if args.use_markdown() && MarkdownRenderer::is_markdown(&output) {
            if args.verbose {
                println!("{}", "Rendering Markdown content".bright_cyan());
            }
            let mut markdown_renderer = MarkdownRenderer::new(args.use_images());
            match markdown_renderer.render(&output) {
                Ok(rendered) => {
                    output = rendered;
                    is_markdown_content = true;
                }
                Err(err) => {
                    if args.verbose {
                        println!("{}: {}", "Markdown rendering failed".bright_yellow(), err);
                    }
                    // Fall back to original output
                }
            }
        }
        
        // Apply hyperlinks if enabled, response is from any RIR, and not already rendered as Markdown
        if args.use_hyperlinks() && !is_markdown_content && is_rir_response(&output) {
            let hyperlink_processor = RirHyperlinkProcessor::new();
            output = hyperlink_processor.process(&output);
        }
        
        // Apply client-side coloring if server-side is disabled OR server didn't provide colors
        // Skip if already rendered as Markdown (which has its own coloring)
        if args.use_color() && !is_markdown_content && (!args.use_server_color() || !result.server_colored) {
            let scheme = if args.use_mtf_colors() {
                ColorScheme::Mtf
            } else {
                OutputColorizer::detect_scheme(&output)
            };
            output = OutputColorizer::colorize(&output, scheme);
            
            if args.verbose && args.use_server_color() && !result.server_colored {
                println!("{}", "Server coloring not available, using client-side coloring".bright_yellow());
            }
        } else if args.verbose && result.server_colored && !is_markdown_content {
            println!("{}", "Using server-provided coloring".bright_cyan());
        }
        
        println!("{}", output);
        Ok(())
    } else {
        eprintln!("{}", "Empty response received. Please check if your query is correct.".bright_red());
        std::process::exit(1);
    }
}
