use colored::*;

#[derive(Debug, Clone, Copy)]
pub enum ColorScheme {
    Ripe,
    BgpTools,
    Mtf,
    None,
}

pub struct OutputColorizer;

impl OutputColorizer {
    /// Detect the appropriate color scheme for the output
    pub fn detect_scheme(output: &str) -> ColorScheme {
        if Self::is_bgp_tools_format(output) {
            ColorScheme::BgpTools
        } else {
            ColorScheme::Ripe
        }
    }

    /// Apply colorization based on the scheme
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
                   first_line.contains("|") && 
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
        
        Some(format!("{}: {}", colored_field, colored_value))
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
            "domain status" | "status" =>
                field.bright_yellow().to_string(),
            
            // Registrar fields
            "registrar" | "sponsoring registrar" | "registrar iana id" | "reseller" =>
                field.bright_blue().to_string(),
            
            // Registry fields
            "registry domain id" | "registrar whois server" | "registrar url" =>
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
            
            // Maintainer fields
            "mnt-by" | "mnt-ref" | "mnt-domains" | "mnt-lower" | "mnt-routes" =>
                field.bright_blue().to_string(),
            
            // Routing fields
            "import" | "export" | "mp-import" | "mp-export" | "default" | "peer" =>
                field.magenta().to_string(),
            
            // Location fields
            "country" | "address" | "source" | "registrant country" | 
            "admin country" | "tech country" =>
                field.bright_white().to_string(),
            
            // Communication fields
            "e-mail" | "email" | "phone" | "registrant email" | "admin email" | "tech email" =>
                field.blue().to_string(),
            
            // DNSSEC fields
            "dnssec" | "ds record" =>
                field.magenta().bold().to_string(),
            
            // Special org field
            "sponsoring-org" =>
                field.bright_yellow().to_string(),
            
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
        if value.starts_with("AS") && value.len() > 2 && value[2..].chars().all(|c| c.is_digit(10)) {
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
            return if value.contains("-") {
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
            "ASSIGNED" | "ALLOCATED" => value.bright_green().to_string(),
            "AVAILABLE" => value.bright_cyan().to_string(),
            "RESERVED" => value.yellow().to_string(),
            "CLIENT DELETE PROHIBITED" | "CLIENT TRANSFER PROHIBITED" | 
            "CLIENT UPDATE PROHIBITED" => value.bright_yellow().to_string(),
            "INACTIVE" | "PENDING DELETE" => value.bright_red().to_string(),
            "OK" | "ACTIVE" | "CLIENT OK" => value.bright_green().to_string(),
            _ => value.bright_yellow().to_string(),
        }
    }

    /// Colorize routing policy lines (import/export)
    fn colorize_routing_policy(value: &str) -> String {
        let mut colored_parts = Vec::new();
        let parts: Vec<&str> = value.split_whitespace().collect();
        
        for part in parts {
            if part.starts_with("AS") && part.len() > 2 && part[2..].chars().all(|c| c.is_digit(10)) {
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
        value.chars().all(|c| c.is_digit(10) || c == '.' || c == ':' || c == '/')
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
                colored_lines.push("".to_string());
                continue;
            }
            
            // Process header row
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
                0 => line.truecolor(91, 207, 250).to_string(),   // Blue #5BCFFA
                1 => line.truecolor(245, 171, 185).to_string(),  // Pink #F5ABB9
                2 => line.truecolor(255, 255, 255).to_string(),  // White #FFFFFF
                3 => line.truecolor(245, 171, 185).to_string(),  // Pink #F5ABB9
                4 => line.truecolor(91, 207, 250).to_string(),   // Blue #5BCFFA
                _ => unreachable!(),
            };
            
            colored_lines.push(colored_line);
            line_count += 1;
        }
        
        colored_lines.join("\n")
    }
} 