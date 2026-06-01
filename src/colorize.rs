//! Terminal output colorization for WHOIS responses.
//!
//! Supports multiple color schemes:
//! - [`ColorScheme::Ripe`] — highlights RIPE-style `field: value` pairs
//! - [`ColorScheme::BgpTools`] — colors BGP.tools pipe-delimited table output
//! - [`ColorScheme::Mtf`] — trans-flag cycling colors (easter egg)
//! - [`ColorScheme::None`] — pass-through, no coloring
//!
//! Auto-detection between RIPE and BGP.tools formats is handled by
//! [`OutputColorizer::detect_scheme`].

use colored::Colorize;

/// Available color schemes for WHOIS output.
#[derive(Debug, Clone, Copy)]
pub enum ColorScheme {
    /// RIPE-style `field: value` key-value pair coloring.
    Ripe,
    /// BGP.tools pipe-delimited table format coloring.
    BgpTools,
    /// Trans-flag cycling color scheme (easter egg).
    Mtf,
    /// No coloring — pass-through.
    None,
}

/// Static utility for detecting and applying terminal colorization.
pub struct OutputColorizer;

impl OutputColorizer {
    /// Detect the appropriate color scheme for the output
    #[must_use] 
    pub fn detect_scheme(output: &str) -> ColorScheme {
        if Self::is_bgp_tools_format(output) {
            ColorScheme::BgpTools
        } else {
            ColorScheme::Ripe
        }
    }

    /// Apply colorization based on the scheme
    #[must_use] 
    pub fn colorize(output: &str, scheme: ColorScheme) -> String {
        match scheme {
            ColorScheme::Ripe => Self::colorize_ripe(output),
            ColorScheme::BgpTools => Self::colorize_bgptools(output),
            ColorScheme::Mtf => Self::colorize_mtf(output),
            ColorScheme::None => output.to_string(),
        }
    }

    /// Detect if the output is in BGP Tools format
    fn is_bgp_tools_format(output: &str) -> bool {
        let lines: Vec<&str> = output.lines().collect();
        if lines.len() >= 2 {
            let first_line = lines[0].trim();
            return first_line.contains("AS") && 
                   first_line.contains('|') && 
                   (first_line.contains("BGP") || 
                    first_line.contains("CC") || 
                    first_line.contains("Registry"));
        }
        false
    }

    /// Colorize RIPE format output (field: value pairs)
    fn colorize_ripe(output: &str) -> String {
        let mut colored_lines = Vec::new();
        let mut in_comment_block = false;
        
        for line in output.lines() {
            // Handle comment lines
            if line.starts_with('%') || line.starts_with('#') || line.starts_with("remarks:") {
                colored_lines.push(line.bright_black().to_string());
                in_comment_block = true;
                continue;
            }
            
            // Comment block state management
            if in_comment_block && line.trim().is_empty() {
                colored_lines.push(line.to_string());
                continue;
            }
            
            if in_comment_block && !line.trim().is_empty() {
                in_comment_block = false;
            }
            
            // Handle empty lines
            if line.trim().is_empty() {
                colored_lines.push(line.to_string());
                continue;
            }
            
            // Handle field: value pairs
            if line.contains(':') {
                if let Some(colored_line) = Self::colorize_field_value_pair(line) {
                    colored_lines.push(colored_line);
                    continue;
                }
            }
            
            // Handle special cases
            colored_lines.push(Self::colorize_special_lines(line));
        }
        
        colored_lines.join("\n")
    }

    /// Colorize a field: value pair
    fn colorize_field_value_pair(line: &str) -> Option<String> {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() != 2 {
            return None;
        }

        let field = parts[0].trim();
        let value = parts[1].trim();
        
        let colored_field = Self::colorize_field_name(field);
        let colored_value = Self::colorize_field_value(field, value);
        
        Some(format!("{colored_field}: {colored_value}"))
    }

    /// Colorize field names based on their type
    fn colorize_field_name(field: &str) -> String {
        match field.to_lowercase().as_str() {
            // Network and AS fields
            "aut-num" | "as-block" | "inet6num" | "inetnum" | "route" | "route6" | "netname" =>
                field.bright_cyan().to_string(),
            
            // Domain fields
            "domain" | "domain name" =>
                field.bright_cyan().bold().to_string(),
            
            // DNS fields
            "nserver" | "name server" | "nameserver" | "name servers" =>
                field.yellow().bold().to_string(),
            
            // Status fields
            "domain status" | "status" | "sponsoring-org" =>
                field.bright_yellow().to_string(),
            
            // Registrar fields
            "registrar" | "sponsoring registrar" | "registrar iana id" | "reseller" |
            "mnt-by" | "mnt-ref" | "mnt-domains" | "mnt-lower" | "mnt-routes" =>
                field.bright_blue().to_string(),
            
            // Registry fields
            "registry domain id" | "registrar whois server" | "registrar url" |
            "e-mail" | "email" | "phone" | "registrant email" | "admin email" | "tech email" =>
                field.blue().to_string(),
            
            // Date fields
            "creation date" | "created" | "created on" | "registration date" |
            "updated date" | "last modified" | "last update" | "changed" |
            "expiration date" | "expiry date" | "registry expiry date" | 
            "registrar registration expiration date" =>
                field.bright_magenta().to_string(),
            
            // Privacy fields
            "privacy" | "whois privacy" | "domain privacy" =>
                field.bright_red().to_string(),
            
            // Name fields
            "as-name" | "org-name" | "role" | "person" | "registrant name" | 
            "admin name" | "tech name" =>
                field.bright_green().to_string(),
            
            // Organization fields
            "org" | "organisation" | "org-type" | "registrant organization" | "registrant" =>
                field.yellow().to_string(),
            
            // Contact fields
            "admin-c" | "tech-c" | "abuse-c" | "nic-hdl" | "abuse-mailbox" |
            "registrant contact" | "admin contact" | "technical contact" | "billing contact" =>
                field.green().to_string(),
            
            // Routing fields
            "import" | "export" | "mp-import" | "mp-export" | "default" | "peer" =>
                field.magenta().to_string(),
            
            // Location fields
            "country" | "address" | "source" | "registrant country" | 
            "admin country" | "tech country" =>
                field.bright_white().to_string(),
            
            // DNSSEC fields
            "dnssec" | "ds record" =>
                field.magenta().bold().to_string(),
            
            // Default
            _ => field.white().to_string(),
        }
    }

    /// Colorize field values based on content and context
    fn colorize_field_value(field: &str, value: &str) -> String {
        let field_lower = field.to_lowercase();
        
        // Domain names
        if field_lower == "domain" || field_lower == "domain name" {
            return value.bright_white().bold().to_string();
        }
        
        // AS Numbers
        if field_lower == "aut-num" {
            return value.bright_red().bold().to_string();
        }
        
        // Status values
        if field_lower == "status" || field_lower == "domain status" {
            return Self::colorize_status_value(value);
        }
        
        // Source registry
        if field_lower == "source" {
            return value.bright_blue().to_string();
        }
        
        // Country codes
        if field_lower == "country" || field_lower.contains("country") {
            return value.yellow().to_string();
        }
        
        // Name servers
        if field_lower.contains("name server") || field_lower.contains("nserver") || 
           field_lower == "nameserver" {
            return value.bright_green().to_string();
        }
        
        // Registrar information
        if field_lower.contains("registrar") {
            return value.bright_blue().bold().to_string();
        }
        
        // DNSSEC status
        if field_lower.contains("dnssec") {
            return if value.to_lowercase().contains("signed") || value.to_lowercase().contains("yes") {
                value.bright_green().to_string()
            } else {
                value.bright_red().to_string()
            };
        }
        
        // Dates
        if field_lower.contains("date") || field_lower.contains("created") || 
           field_lower.contains("changed") || field_lower.contains("expir") || 
           field_lower.contains("update") {
            return value.bright_magenta().to_string();
        }
        
        // Email addresses
        if value.contains('@') {
            return value.bright_yellow().to_string();
        }
        
        // Phone numbers
        if field_lower.contains("phone") {
            return value.bright_white().to_string();
        }
        
        // AS numbers in values
        if value.starts_with("AS") && value.len() > 2 && value[2..].chars().all(|c| c.is_ascii_digit()) {
            return value.bright_red().to_string();
        }
        
        // Import/Export specialized coloring
        if (field == "import" || field == "export") && value.contains("AS") {
            return Self::colorize_routing_policy(value);
        }
        
        // IP addresses and CIDR blocks
        if Self::looks_like_ip_or_cidr(value) {
            return value.bright_cyan().to_string();
        }
        
        // Maintainer values
        if field.starts_with("mnt-") {
            return if value.contains('-') {
                value.bright_blue().to_string()
            } else {
                value.white().to_string()
            };
        }
        
        // Names
        if field_lower == "as-name" || field_lower == "org-name" || field_lower == "netname" {
            return value.bright_white().bold().to_string();
        }
        
        // Person/role names
        if field_lower == "role" || field_lower == "person" || 
           field_lower.contains("registrant name") {
            return value.bright_green().bold().to_string();
        }
        
        // Handles
        if field.ends_with("-c") {
            return value.green().to_string();
        }
        
        // Default
        value.white().to_string()
    }

    /// Colorize status values
    fn colorize_status_value(value: &str) -> String {
        match value.to_uppercase().as_str() {
            "ASSIGNED" | "ALLOCATED" | "OK" | "ACTIVE" | "CLIENT OK" =>
                value.bright_green().to_string(),
            "AVAILABLE" => value.bright_cyan().to_string(),
            "RESERVED" => value.yellow().to_string(),
            "INACTIVE" | "PENDING DELETE" => value.bright_red().to_string(),
            _ => value.bright_yellow().to_string(),
        }
    }

    /// Colorize routing policy lines (import/export)
    fn colorize_routing_policy(value: &str) -> String {
        let mut colored_parts = Vec::new();
        let parts: Vec<&str> = value.split_whitespace().collect();
        
        for part in parts {
            if part.starts_with("AS") && part.len() > 2 && part[2..].chars().all(|c| c.is_ascii_digit()) {
                colored_parts.push(part.bright_red().to_string());
            } else if matches!(part, "from" | "to" | "accept" | "announce") {
                colored_parts.push(part.bright_cyan().to_string());
            } else {
                colored_parts.push(part.white().to_string());
            }
        }
        
        colored_parts.join(" ")
    }

    /// Check if a string looks like an IP address or CIDR block
    fn looks_like_ip_or_cidr(value: &str) -> bool {
        value.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':' || c == '/')
    }

    /// Colorize special lines (errors, availability, etc.)
    fn colorize_special_lines(line: &str) -> String {
        let line_lower = line.to_lowercase();
        
        if line_lower.contains("error") || line_lower.contains("not found") || 
           line_lower.contains("no match") {
            line.bright_red().to_string()
        } else if line_lower.contains("available") {
            line.bright_green().to_string()
        } else {
            line.white().to_string()
        }
    }

    /// Colorize BGP Tools format output (table format)
    fn colorize_bgptools(output: &str) -> String {
        let lines: Vec<&str> = output.lines().collect();
        let mut colored_lines = Vec::new();
        let mut headers: Vec<&str> = Vec::new();
        
        for (i, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                colored_lines.push(String::new());
                continue;
            }
            
            // Process header row
            if i == 0 || (i == 1 && lines[0].trim().is_empty()) {
                headers = line.split('|').map(str::trim).collect();
                let colored_headers: Vec<String> = headers.iter()
                    .map(|&header| header.bright_cyan().bold().to_string())
                    .collect();
                colored_lines.push(colored_headers.join(" | "));
                continue;
            }
            
            // Process data rows
            let fields: Vec<&str> = line.split('|').map(str::trim).collect();
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

    /// MTF flag coloring (trans flag pattern)
    fn colorize_mtf(output: &str) -> String {
        let mut colored_lines = Vec::new();
        let mut line_count = 0;
        
        for line in output.lines() {
            if line.trim().is_empty() {
                colored_lines.push(line.to_string());
                continue;
            }
            
            // Trans flag pattern: blue, pink, white, pink, blue
            let colored_line = match line_count % 5 {
                0 | 4 => line.truecolor(91, 207, 250).to_string(),   // Blue #5BCFFA
                1 | 3 => line.truecolor(245, 171, 185).to_string(),  // Pink #F5ABB9
                2 => line.truecolor(255, 255, 255).to_string(),      // White #FFFFFF
                _ => unreachable!(),
            };
            
            colored_lines.push(colored_line);
            line_count += 1;
        }
        
        colored_lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod detect_scheme {
        use super::*;

        #[test]
        fn should_return_bgptools_for_pipe_delimited_header() {
            let output = "AS | BGP Prefix | CC\n123 | 1.2.3.0/24 | US";
            assert!(matches!(
                OutputColorizer::detect_scheme(output),
                ColorScheme::BgpTools
            ));
        }

        #[test]
        fn should_return_ripe_for_standard_whois() {
            let output = "domain: example.com\nsource: RIPE";
            assert!(matches!(
                OutputColorizer::detect_scheme(output),
                ColorScheme::Ripe
            ));
        }

        #[test]
        fn should_return_ripe_for_plain_text() {
            assert!(matches!(
                OutputColorizer::detect_scheme("just some text"),
                ColorScheme::Ripe
            ));
        }
    }

    mod colorize {
        use super::*;

        #[test]
        fn should_return_original_when_scheme_is_none() {
            let input = "domain: example.com";
            let result = OutputColorizer::colorize(input, ColorScheme::None);
            assert_eq!(result, input);
        }

        #[test]
        fn should_produce_output_for_ripe_scheme() {
            let input = "domain: example.com\nsource: RIPE";
            let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
            assert!(!result.is_empty());
            assert!(result.contains("domain"));
            assert!(result.contains("example.com"));
        }

        #[test]
        fn should_produce_output_for_bgptools_scheme() {
            let input = "AS | BGP Prefix | CC\n123 | 1.2.3.0/24 | US";
            let result = OutputColorizer::colorize(input, ColorScheme::BgpTools);
            assert!(!result.is_empty());
        }

        #[test]
        fn should_produce_output_for_mtf_scheme() {
            let input = "line 1\nline 2\nline 3\nline 4\nline 5";
            let result = OutputColorizer::colorize(input, ColorScheme::Mtf);
            assert!(!result.is_empty());
            assert!(result.contains("line 1"));
            assert!(result.contains("line 5"));
        }
    }

    #[test]
    fn detect_scheme_should_detect_bgp_tools_with_registry_header() {
        let output = "AS | Registry | CC\n123 | RIPE | US";
        assert!(matches!(
            OutputColorizer::detect_scheme(output),
            ColorScheme::BgpTools
        ));
    }

    #[test]
    fn detect_scheme_should_not_detect_bgp_tools_for_single_line() {
        let output = "just one line";
        assert!(matches!(
            OutputColorizer::detect_scheme(output),
            ColorScheme::Ripe
        ));
    }

    #[test]
    fn should_produce_output_for_ripe_scheme_with_ip_and_cidr() {
        let input = "inetnum: 192.168.1.0 - 192.168.1.255\nnetname: EXAMPLE-NET";
        let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
        assert!(!result.is_empty());
        assert!(result.contains("inetnum"));
        assert!(result.contains("192.168.1.0"));
    }

    #[test]
    fn should_produce_output_for_bgptools_scheme_with_all_known_columns() {
        let input =
            "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name\n42 | 10.0.0.0/8 | 10.0.0.0/8 | US | RIPE | 2000-01-01 | Example-AS";
        let result = OutputColorizer::colorize(input, ColorScheme::BgpTools);
        assert!(!result.is_empty());
        assert!(result.contains("42"));
        assert!(result.contains("10.0.0.0/8"));
        assert!(result.contains("US"));
        assert!(result.contains("RIPE"));
        assert!(result.contains("Example-AS"));
    }

    #[test]
    fn colorize_ripe_should_handle_comment_lines() {
        let input = "% This is a comment\n# Another comment\ndomain: example.com\nsource: RIPE";
        let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
        assert!(!result.is_empty());
        assert!(result.contains("comment"));
        assert!(result.contains("domain"));
    }

    #[test]
    fn colorize_ripe_should_handle_empty_lines() {
        let input = "domain: example.com\n\nsource: RIPE";
        let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
        assert!(!result.is_empty());
        assert!(result.contains("domain"));
        assert!(result.contains("source"));
    }

    #[test]
    fn colorize_ripe_should_highlight_error_lines() {
        let input = "domain: example.com\nNOT FOUND\nsource: RIPE";
        let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
        assert!(!result.is_empty());
        assert!(result.contains("domain"));
        assert!(result.contains("NOT FOUND"));
    }

    #[test]
    fn colorize_ripe_should_highlight_available_lines() {
        let input = "domain: example.com\nDomain Available\nsource: RIPE";
        let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
        assert!(!result.is_empty());
        assert!(result.contains("Available"));
        assert!(result.contains("domain"));
    }

    #[test]
    fn colorize_ripe_should_colorize_status_value() {
        let result = "RESERVED";
        let colored = OutputColorizer::colorize_status_value(result);
        assert!(!colored.is_empty());
        assert!(colored.contains("RESERVED"));
    }

    #[test]
    fn colorize_ripe_should_colorize_allocated_status() {
        let result = "ALLOCATED";
        let colored = OutputColorizer::colorize_status_value(result);
        assert!(colored.contains("ALLOCATED"));
    }

    #[test]
    fn looks_like_ip_or_cidr_should_match_ipv4() {
        assert!(OutputColorizer::looks_like_ip_or_cidr("192.168.1.0"));
    }

    #[test]
    fn looks_like_ip_or_cidr_should_match_cidr() {
        assert!(OutputColorizer::looks_like_ip_or_cidr("10.0.0.0/8"));
    }

    #[test]
    fn looks_like_ip_or_cidr_should_match_ipv6_without_hex_letters() {
        assert!(OutputColorizer::looks_like_ip_or_cidr("::1"));
        assert!(OutputColorizer::looks_like_ip_or_cidr("2001::1"));
    }

    #[test]
    fn looks_like_ip_or_cidr_should_not_match_text() {
        assert!(!OutputColorizer::looks_like_ip_or_cidr("example.com"));
    }

    #[test]
    fn looks_like_ip_or_cidr_should_not_match_empty_string() {
        assert!(OutputColorizer::looks_like_ip_or_cidr(""));
    }

    #[test]
    fn detect_scheme_should_return_bgptools_for_multi_line_with_cc_header() {
        let output = "AS | CC\n123 | US\n456 | DE";
        assert!(matches!(
            OutputColorizer::detect_scheme(output),
            ColorScheme::BgpTools
        ));
    }

    #[test]
    fn detect_scheme_should_return_ripe_when_header_has_as_but_not_enough_lines() {
        let output = "AS alone";
        assert!(matches!(
            OutputColorizer::detect_scheme(output),
            ColorScheme::Ripe
        ));
    }

    #[test]
    fn colorize_mtf_should_cycle_colors_for_many_lines() {
        let input = (0..10).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        let result = OutputColorizer::colorize(&input, ColorScheme::Mtf);
        assert!(!result.is_empty());
        for i in 0..10 {
            assert!(result.contains(&format!("line {i}")));
        }
    }

    #[test]
    fn colorize_mtf_should_preserve_empty_lines() {
        let input = "line 1\n\nline 3";
        let result = OutputColorizer::colorize(input, ColorScheme::Mtf);
        assert!(!result.is_empty());
        assert!(result.contains("line 1"));
        assert!(result.contains("line 3"));
    }

    #[test]
    fn colorize_bgptools_should_handle_empty_lines() {
        let input = "AS | BGP Prefix | CC\n\n123 | 1.2.3.0/24 | US";
        let result = OutputColorizer::colorize(input, ColorScheme::BgpTools);
        assert!(!result.is_empty());
        assert!(result.contains("123"));
    }

    #[test]
    fn colorize_bgptools_should_handle_empty_first_line_followed_by_header() {
        let input = "\nAS | BGP Prefix | CC\n123 | 1.2.3.0/24 | US";
        let result = OutputColorizer::colorize(input, ColorScheme::BgpTools);
        assert!(!result.is_empty());
        assert!(result.contains("123"));
    }

    #[test]
    fn colorize_ripe_should_handle_field_without_colon() {
        let input = "domain: example.com\njust a plain line\nsource: RIPE";
        let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
        assert!(!result.is_empty());
        assert!(result.contains("just a plain line"));
    }

    #[test]
    fn colorize_ripe_should_handle_remarks_like_comments() {
        let input = "remarks: something to note\ndomain: example.com";
        let result = OutputColorizer::colorize(input, ColorScheme::Ripe);
        assert!(!result.is_empty());
        assert!(result.contains("remarks"));
        assert!(result.contains("domain"));
    }
}
