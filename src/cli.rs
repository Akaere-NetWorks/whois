use clap::Parser;

#[derive(Parser)]
#[command(
    author = "Pysio",
    version = env!("CARGO_PKG_VERSION"),
    about = "A simple WHOIS query tool with advanced features"
)]
pub struct Cli {
    /// Domain name or IP address to query
    pub domain: String,

    /// WHOIS server to use (bypasses IANA lookup)
    #[arg(short, long)]
    pub server: Option<String>,

    /// Port number to use
    #[arg(short, long, default_value_t = 43)]
    pub port: u16,

    /// Display verbose output
    #[arg(short, long)]
    pub verbose: bool,
    
    /// Query DN42 information from lantian.pub
    #[arg(long = "42")]
    pub dn42: bool,
    
    /// Query from bgp.tools
    #[arg(long)]
    pub bgptools: bool,
    
    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
    
    /// Easter egg: MTF flag colors (hidden option)
    #[arg(long, hide = true)]
    pub mtf: bool,

    /// Disable hyperlinks in terminal output (hyperlinks are enabled by default)
    #[arg(long, help = "Disable clickable hyperlinks for RIR database results")]
    pub no_hyperlinks: bool,
}

impl Cli {
    /// Check if colored output should be used
    pub fn use_color(&self) -> bool {
        !self.no_color
    }

    /// Check if MTF colors should be used
    pub fn use_mtf_colors(&self) -> bool {
        self.mtf
    }

    /// Check if DN42 mode should be used
    pub fn use_dn42(&self) -> bool {
        self.dn42 || self.domain.to_uppercase().starts_with("AS42424")
    }

    /// Check if BGP tools mode should be used
    pub fn use_bgptools(&self) -> bool {
        self.bgptools
    }

    /// Check if hyperlinks should be used
    pub fn use_hyperlinks(&self) -> bool {
        !self.no_hyperlinks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cli(domain: &str) -> Cli {
        Cli {
            domain: domain.to_string(),
            server: None,
            port: 43,
            verbose: false,
            dn42: false,
            bgptools: false,
            no_color: false,
            mtf: false,
            no_hyperlinks: false,
        }
    }

    #[test]
    fn test_use_color_default() {
        let cli = create_test_cli("example.com");
        assert!(cli.use_color());
    }

    #[test]
    fn test_use_color_disabled() {
        let mut cli = create_test_cli("example.com");
        cli.no_color = true;
        assert!(!cli.use_color());
    }

    #[test]
    fn test_use_mtf_colors() {
        let mut cli = create_test_cli("example.com");
        assert!(!cli.use_mtf_colors());
        
        cli.mtf = true;
        assert!(cli.use_mtf_colors());
    }

    #[test]
    fn test_use_dn42_explicit_flag() {
        let mut cli = create_test_cli("example.com");
        assert!(!cli.use_dn42());
        
        cli.dn42 = true;
        assert!(cli.use_dn42());
    }

    #[test]
    fn test_use_dn42_auto_detection() {
        let cli = create_test_cli("AS4242420000");
        assert!(cli.use_dn42());
        
        let cli = create_test_cli("as4242420000");
        assert!(cli.use_dn42());
        
        let cli = create_test_cli("AS4242421234");
        assert!(cli.use_dn42());
    }

    #[test]
    fn test_use_dn42_not_triggered() {
        let cli = create_test_cli("AS15169");
        assert!(!cli.use_dn42());
        
        let cli = create_test_cli("example.com");
        assert!(!cli.use_dn42());
    }

    #[test]
    fn test_use_bgptools() {
        let mut cli = create_test_cli("AS15169");
        assert!(!cli.use_bgptools());
        
        cli.bgptools = true;
        assert!(cli.use_bgptools());
    }

    #[test]
    fn test_use_hyperlinks_default() {
        let cli = create_test_cli("example.com");
        assert!(cli.use_hyperlinks());
    }

    #[test]
    fn test_use_hyperlinks_disabled() {
        let mut cli = create_test_cli("example.com");
        cli.no_hyperlinks = true;
        assert!(!cli.use_hyperlinks());
    }

    #[test]
    fn test_port_default() {
        let cli = create_test_cli("example.com");
        assert_eq!(cli.port, 43);
    }

    #[test]
    fn test_domain_assignment() {
        let cli = create_test_cli("test.example.com");
        assert_eq!(cli.domain, "test.example.com");
    }

    #[test]
    fn test_all_flags_together() {
        let mut cli = create_test_cli("AS4242420000");
        cli.dn42 = true;
        cli.bgptools = true;
        cli.no_color = true;
        cli.mtf = true;
        cli.no_hyperlinks = true;
        cli.verbose = true;
        
        // DN42 should be true due to both flag and auto-detection
        assert!(cli.use_dn42());
        assert!(cli.use_bgptools());
        assert!(!cli.use_color());
        assert!(cli.use_mtf_colors());
        assert!(!cli.use_hyperlinks());
        assert!(cli.verbose);
    }
} 