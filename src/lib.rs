pub mod cli;
pub mod query;
pub mod colorize;
pub mod servers;
pub mod hyperlink;

pub use cli::Cli;
pub use query::{WhoisQuery, QueryResult};
pub use colorize::{ColorScheme, OutputColorizer};
pub use servers::{ServerSelector, WhoisServer};
pub use hyperlink::{RirHyperlinkProcessor, RipeHyperlinkProcessor, is_ripe_response, is_rir_response, terminal_supports_hyperlinks}; 