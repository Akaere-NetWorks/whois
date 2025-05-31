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
} 