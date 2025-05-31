use regex::Regex;
use std::env;
use urlencoding::encode;

/// Represents Regional Internet Registry URLs
pub struct RirUrls;

impl RirUrls {
    /// Get the appropriate URL for a given RIR and search term
    pub fn get_url(rir: &str, search_term: &str) -> String {
        let encoded_term = encode(search_term);
        
        match rir.to_uppercase().as_str() {
            "RIPE" => format!("https://apps.db.ripe.net/db-web-ui/query?searchtext={}", encoded_term),
            "ARIN" => format!("https://search.arin.net/rdap/?query={}", encoded_term),
            "APNIC" => format!("https://wq.apnic.net/apnic-bin/whois.pl?searchtext={}", encoded_term),
            "LACNIC" => {
                // LACNIC uses a different parameter format
                format!("https://query.milacnic.lacnic.net/home?searchtext={}", encoded_term)
            },
            "AFRINIC" => format!("https://afrinic.net/whois?searchtext={}", encoded_term),
            _ => {
                // Fallback to RIPE for unknown RIRs
                format!("https://apps.db.ripe.net/db-web-ui/query?searchtext={}", encoded_term)
            }
        }
    }
}

/// Detect RIR from source field - more accurate than content-based detection
pub fn detect_rir_from_source(response: &str) -> Vec<&'static str> {
    let mut rirs = Vec::new();
    
    // Use regex to find all source fields
    let source_regex = Regex::new(r"(?m)^source:\s*([A-Z-]+)").unwrap();
    
    for caps in source_regex.captures_iter(response) {
        if let Some(source) = caps.get(1) {
            let source_value = source.as_str().trim();
            let rir = match source_value {
                "RIPE" => Some("ripe"),
                "ARIN" => Some("arin"),
                "APNIC" => Some("apnic"),
                "LACNIC" => Some("lacnic"),
                "AFRINIC" => Some("afrinic"),
                _ => None,
            };
            
            if let Some(rir) = rir {
                if !rirs.contains(&rir) {
                    rirs.push(rir);
                }
            }
        }
    }
    
    rirs
}

/// Legacy function - detect which RIR the response is from (fallback method)
pub fn detect_rir(response: &str) -> Option<&'static str> {
    // First try source-based detection
    let rirs = detect_rir_from_source(response);
    if !rirs.is_empty() {
        return Some(rirs[0]);
    }
    
    // Fallback to content-based detection
    if response.contains("% This is the RIPE Database query service") ||
       response.contains("whois.ripe.net") ||
       response.contains("RIPE-NCC") {
        return Some("ripe");
    }

    if response.contains("American Registry for Internet Numbers") ||
       response.contains("ARIN WHOIS data") ||
       response.contains("NetRange:") ||
       response.contains("whois.arin.net") {
        return Some("arin");
    }

    if response.contains("Asia Pacific Network Information Centre") ||
       response.contains("APNIC WHOIS Database") ||
       response.contains("whois.apnic.net") {
        return Some("apnic");
    }

    if response.contains("Latin American and Caribbean IP address Regional Registry") ||
       response.contains("LACNIC WHOIS") ||
       response.contains("whois.lacnic.net") {
        return Some("lacnic");
    }

    if response.contains("African Network Information Centre") ||
       response.contains("AFRINIC WHOIS") ||
       response.contains("whois.afrinic.net") {
        return Some("afrinic");
    }

    None
}

/// Check if the WHOIS response is from any RIR
pub fn is_rir_response(response: &str) -> bool {
    !detect_rir_from_source(response).is_empty() || detect_rir(response).is_some()
}

/// Check if the WHOIS response is from RIPE NCC
pub fn is_ripe_response(response: &str) -> bool {
    detect_rir_from_source(response).contains(&"ripe") || detect_rir(response) == Some("ripe")
}

/// Check if terminal supports hyperlinks (OSC 8) - improved Windows detection
pub fn terminal_supports_hyperlinks() -> bool {
    // Check for Windows Terminal first (most reliable)
    if env::var("WT_SESSION").is_ok() || env::var("WT_PROFILE_ID").is_ok() {
        return true;
    }

    // Check for PowerShell with Windows Terminal
    if env::var("TERM_PROGRAM").map_or(false, |term| term == "vscode") {
        return true;
    }

    // Check common environment variables that indicate hyperlink support
    if let Ok(term) = env::var("TERM") {
        // These terminals are known to support OSC 8
        if term.contains("xterm") || 
           term.contains("screen") || 
           term.contains("tmux") ||
           term == "alacritty" ||
           term == "kitty" ||
           term == "foot" ||
           term.contains("256color") {
            return true;
        }
    }

    // Check for VTE-based terminals (GNOME Terminal, etc.)
    if env::var("VTE_VERSION").is_ok() {
        return true;
    }

    // Check for iTerm2
    if env::var("ITERM_SESSION_ID").is_ok() || env::var("TERM_PROGRAM").map_or(false, |term| term == "iTerm.app") {
        return true;
    }

    // Check for WezTerm
    if env::var("WEZTERM_EXECUTABLE").is_ok() || env::var("TERM_PROGRAM").map_or(false, |term| term == "WezTerm") {
        return true;
    }

    // Check for Hyper
    if env::var("TERM_PROGRAM").map_or(false, |term| term == "Hyper") {
        return true;
    }

    // Additional Windows Terminal detection
    if cfg!(windows) {
        // Check if we're in Windows Terminal by looking for common WT env vars
        if env::var("SESSIONNAME").is_ok() || 
           env::var("COMPUTERNAME").is_ok() {
            // Try to detect modern Windows environments
            if let Ok(term_program) = env::var("TERM_PROGRAM") {
                if term_program.contains("WindowsTerminal") || term_program.contains("wt") {
                    return true;
                }
            }
        }
    }

    // Default to true for modern systems - most terminals support OSC 8 now
    true
}

/// Create OSC 8 hyperlink
pub fn create_hyperlink(url: &str, text: &str) -> String {
    if !terminal_supports_hyperlinks() {
        return text.to_string();
    }

    format!("\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\", url, text)
}

/// Split response into blocks by RIR source
fn split_response_by_source(response: &str) -> Vec<(String, &'static str)> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = response.lines().collect();
    let mut current_block = String::new();
    let mut current_rir = None;
    
    for line in lines {
        // Check if this line contains a source field
        if let Some(caps) = Regex::new(r"^source:\s*([A-Z-]+)").unwrap().captures(line) {
            if let Some(source) = caps.get(1) {
                let source_value = source.as_str().trim();
                let rir = match source_value {
                    "RIPE" => Some("ripe"),
                    "ARIN" => Some("arin"), 
                    "APNIC" => Some("apnic"),
                    "LACNIC" => Some("lacnic"),
                    "AFRINIC" => Some("afrinic"),
                    _ => None,
                };
                
                // If we found a new RIR source and have a current block, save it
                if let Some(current) = current_rir {
                    if rir != Some(current) && !current_block.trim().is_empty() {
                        blocks.push((current_block.clone(), current));
                        current_block.clear();
                    }
                }
                
                current_rir = rir;
            }
        }
        
        current_block.push_str(line);
        current_block.push('\n');
    }
    
    // Add the last block
    if let Some(rir) = current_rir {
        if !current_block.trim().is_empty() {
            blocks.push((current_block, rir));
        }
    } else if !current_block.trim().is_empty() {
        // Fallback: try to detect RIR from content
        if let Some(rir) = detect_rir(&current_block) {
            blocks.push((current_block, rir));
        }
    }
    
    // If no blocks were created, treat entire response as one block
    if blocks.is_empty() {
        if let Some(rir) = detect_rir(response) {
            blocks.push((response.to_string(), rir));
        }
    }
    
    blocks
}

/// Hyperlink processor for RIR database responses
pub struct RirHyperlinkProcessor {
    rir_urls: RirUrls,
}

impl RirHyperlinkProcessor {
    pub fn new() -> Self {
        Self {
            rir_urls: RirUrls,
        }
    }

    /// Process RIR response and add hyperlinks - handles multi-RIR responses
    pub fn process(&self, response: &str) -> String {
        if !terminal_supports_hyperlinks() {
            return response.to_string();
        }
        
        // Split response into blocks by RIR source
        let blocks = split_response_by_source(response);
        
        if blocks.is_empty() {
            return response.to_string();
        }
        
        let mut processed_blocks = Vec::new();
        
        for (block, rir) in blocks {
            let mut processed_block = block;
            
            // Apply RIR-specific patterns
            match rir {
                "ripe" => self.process_ripe(&mut processed_block),
                "arin" => self.process_arin(&mut processed_block),
                "apnic" => self.process_apnic(&mut processed_block),
                "lacnic" => self.process_lacnic(&mut processed_block),
                "afrinic" => self.process_afrinic(&mut processed_block),
                _ => {}
            }
            
            processed_blocks.push(processed_block);
        }
        
        processed_blocks.join("")
    }

    fn apply_patterns(&self, processed: &mut String, patterns: Vec<(&str, &str)>, rir: &str) {
        for (pattern_str, _) in patterns {
            if let Ok(pattern) = Regex::new(pattern_str) {
                *processed = pattern.replace_all(processed, |caps: &regex::Captures| {
                    let full_match = caps.get(0).unwrap().as_str();
                    let prefix = caps.get(1).unwrap().as_str();
                    let value = caps.get(2).unwrap().as_str();
                    
                    // Generate URL for the detected RIR
                    let url = RirUrls::get_url(rir, value);
                    let hyperlinked_value = create_hyperlink(&url, value);
                    
                    format!("{}{}", prefix, hyperlinked_value)
                }).to_string();
            }
        }
    }

    fn process_ripe(&self, processed: &mut String) {
        let patterns = vec![
            // ASN patterns
            (r"(?m)^(aut-num:\s+)(AS\d+)", ""),
            (r"(?m)^(origin:\s+)(AS\d+)", ""),
            
            // IP network patterns
            (r"(?m)^(inetnum:\s+)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s*-\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ""),
            (r"(?m)^(inet6num:\s+)([0-9a-fA-F:]+/\d+)", ""),
            (r"(?m)^(route:\s+)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/\d+)", ""),
            (r"(?m)^(route6:\s+)([0-9a-fA-F:]+/\d+)", ""),
            
            // Organization patterns
            (r"(?m)^(organisation:\s+)(ORG-[A-Z0-9-]+)", ""),
            (r"(?m)^(org:\s+)(ORG-[A-Z0-9-]+)", ""),
            
            // Person/Role patterns
            (r"(?m)^(nic-hdl:\s+)([A-Z0-9-]+)", ""),
            (r"(?m)^(admin-c:\s+)([A-Z0-9-]+)", ""),
            (r"(?m)^(tech-c:\s+)([A-Z0-9-]+)", ""),
            
            // Maintainer patterns
            (r"(?m)^(mntner:\s+)([A-Z][A-Z0-9-]*)", ""),
            (r"(?m)^(mnt-by:\s+)([A-Z][A-Z0-9-]*)", ""),
            
            // Domain patterns
            (r"(?m)^(domain:\s+)([a-zA-Z0-9.-]+\.arpa)", ""),
            
            // AS-block patterns
            (r"(?m)^(as-block:\s+)(AS\d+\s*-\s*AS\d+)", ""),
        ];

        self.apply_patterns(processed, patterns, "RIPE");
    }

    fn process_arin(&self, processed: &mut String) {
        let patterns = vec![
            // ARIN-specific patterns
            (r"(?m)^(NetRange:\s+)([0-9.-]+)", ""),
            (r"(?m)^(CIDR:\s+)([0-9./]+)", ""),
            (r"(?m)^(OriginAS:\s+)(AS\d+)", ""),
            (r"(?m)^(OrgId:\s+)([A-Z0-9-]+)", ""),
            (r"(?m)^(NetName:\s+)([A-Z0-9-]+)", ""),
            
            // Common ASN and IP patterns
            (r"(?m)^(aut-num:\s+)(AS\d+)", ""),
            (r"(?m)^(origin:\s+)(AS\d+)", ""),
            (r"(?m)^(inetnum:\s+)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s*-\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ""),
            (r"(?m)^(inet6num:\s+)([0-9a-fA-F:]+/\d+)", ""),
        ];

        self.apply_patterns(processed, patterns, "ARIN");
    }

    fn process_apnic(&self, processed: &mut String) {
        let patterns = vec![
            // Common patterns for APNIC
            (r"(?m)^(aut-num:\s+)(AS\d+)", ""),
            (r"(?m)^(origin:\s+)(AS\d+)", ""),
            (r"(?m)^(inetnum:\s+)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s*-\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ""),
            (r"(?m)^(inet6num:\s+)([0-9a-fA-F:]+/\d+)", ""),
            (r"(?m)^(nic-hdl:\s+)([A-Z0-9-]+)", ""),
            (r"(?m)^(admin-c:\s+)([A-Z0-9-]+)", ""),
            (r"(?m)^(tech-c:\s+)([A-Z0-9-]+)", ""),
        ];

        self.apply_patterns(processed, patterns, "APNIC");
    }

    fn process_lacnic(&self, processed: &mut String) {
        let patterns = vec![
            // Common patterns for LACNIC
            (r"(?m)^(aut-num:\s+)(AS\d+)", ""),
            (r"(?m)^(origin:\s+)(AS\d+)", ""),
            (r"(?m)^(inetnum:\s+)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s*-\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ""),
            (r"(?m)^(inet6num:\s+)([0-9a-fA-F:]+/\d+)", ""),
            (r"(?m)^(nic-hdl:\s+)([A-Z0-9-]+)", ""),
        ];

        self.apply_patterns(processed, patterns, "LACNIC");
    }

    fn process_afrinic(&self, processed: &mut String) {
        let patterns = vec![
            // Common patterns for AFRINIC
            (r"(?m)^(aut-num:\s+)(AS\d+)", ""),
            (r"(?m)^(origin:\s+)(AS\d+)", ""),
            (r"(?m)^(inetnum:\s+)([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s*-\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ""),
            (r"(?m)^(inet6num:\s+)([0-9a-fA-F:]+/\d+)", ""),
            (r"(?m)^(nic-hdl:\s+)([A-Z0-9-]+)", ""),
        ];

        self.apply_patterns(processed, patterns, "AFRINIC");
    }
}

impl Default for RirHyperlinkProcessor {
    fn default() -> Self {
        Self::new()
    }
}

// For backward compatibility
pub type RipeHyperlinkProcessor = RirHyperlinkProcessor;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_rir_from_source() {
        let multi_rir_response = r#"
as-block: AS137530 - AS138553
descr: APNIC ASN block
source: APNIC

aut-num: AS3333
as-name: RIPE-NCC-AS
source: RIPE
        "#;
        
        let rirs = detect_rir_from_source(multi_rir_response);
        assert!(rirs.contains(&"apnic"));
        assert!(rirs.contains(&"ripe"));
    }

    #[test]
    fn test_split_response_by_source() {
        let multi_rir_response = r#"
as-block: AS137530 - AS138553
source: APNIC

aut-num: AS3333  
source: RIPE
        "#;
        
        let blocks = split_response_by_source(multi_rir_response);
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_create_hyperlink() {
        let url = "https://example.com";
        let text = "Example";
        
        let result = create_hyperlink(url, text);
        assert!(result.contains("Example"));
    }

    #[test]
    fn test_rir_urls() {
        let query_url = RirUrls::get_url("RIPE", "AS3333");
        assert!(query_url.contains("AS3333"));
        assert!(!query_url.contains("types=")); // No types parameter
        assert!(query_url.contains("apps.db.ripe.net"));
        
        // Test different RIRs
        let arin_url = RirUrls::get_url("ARIN", "AS3333");
        assert!(arin_url.contains("search.arin.net"));
        assert!(arin_url.contains("AS3333"));
        
        let apnic_url = RirUrls::get_url("APNIC", "AS3333");
        assert!(apnic_url.contains("wq.apnic.net"));
        assert!(apnic_url.contains("AS3333"));
        
        let lacnic_url = RirUrls::get_url("LACNIC", "AS3333");
        assert!(lacnic_url.contains("query.milacnic.lacnic.net"));
        assert!(lacnic_url.contains("AS3333"));
        
        let afrinic_url = RirUrls::get_url("AFRINIC", "AS3333");
        assert!(afrinic_url.contains("afrinic.net"));
        assert!(afrinic_url.contains("AS3333"));
    }
} 