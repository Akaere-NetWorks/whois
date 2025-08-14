use std::env;

pub const IANA_WHOIS_SERVER: &str = "whois.iana.org";
pub const DEFAULT_WHOIS_SERVER: &str = "whois.ripe.net";
pub const DEFAULT_WHOIS_PORT: u16 = 43;
pub const DN42_WHOIS_SERVER: &str = "lantian.pub";
pub const DN42_WHOIS_PORT: u16 = 43;
pub const BGPTOOLS_WHOIS_SERVER: &str = "bgp.tools";
pub const BGPTOOLS_WHOIS_PORT: u16 = 43;
pub const RADB_WHOIS_SERVER: &str = "whois.radb.net";
pub const RADB_WHOIS_PORT: u16 = 43;

#[derive(Debug, Clone)]
pub struct WhoisServer {
    pub host: String,
    pub port: u16,
    pub name: String,
}

impl WhoisServer {
    pub fn new(host: impl Into<String>, port: u16, name: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            name: name.into(),
        }
    }

    pub fn iana() -> Self {
        Self::new(IANA_WHOIS_SERVER, DEFAULT_WHOIS_PORT, "IANA")
    }

    pub fn default() -> Self {
        Self::new(DEFAULT_WHOIS_SERVER, DEFAULT_WHOIS_PORT, "RIPE")
    }

    pub fn dn42() -> Self {
        Self::new(DN42_WHOIS_SERVER, DN42_WHOIS_PORT, "DN42")
    }

    pub fn bgptools() -> Self {
        Self::new(BGPTOOLS_WHOIS_SERVER, BGPTOOLS_WHOIS_PORT, "BGP.tools")
    }

    pub fn radb() -> Self {
        Self::new(RADB_WHOIS_SERVER, RADB_WHOIS_PORT, "RADB")
    }

    pub fn custom(host: impl Into<String>, port: u16) -> Self {
        Self::new(host.into(), port, "Custom")
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub struct ServerSelector;

impl ServerSelector {
    /// Extract WHOIS server from IANA response
    pub fn extract_whois_server(response: &str) -> Option<String> {
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

    /// Get server from environment variable if available
    pub fn from_env() -> Option<String> {
        env::var("WHOIS_SERVER").ok()
    }

    /// Select appropriate server based on query and options
    pub fn select_server(
        domain: &str,
        use_dn42: bool,
        use_bgptools: bool,
        explicit_server: Option<&str>,
        port: u16,
    ) -> WhoisServer {
        // Priority: special flags > explicit server > environment > default
        if use_dn42 || domain.to_uppercase().starts_with("AS42424") {
            return WhoisServer::dn42();
        }

        if use_bgptools {
            return WhoisServer::bgptools();
        }

        if let Some(server) = explicit_server {
            return WhoisServer::custom(server, port);
        }

        if let Some(env_server) = Self::from_env() {
            return WhoisServer::custom(env_server, port);
        }

        // Default: use IANA for referral
        WhoisServer::iana()
    }
} 