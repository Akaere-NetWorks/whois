//! Crate-level re-exports for the `whois` library.
//!
//! This crate provides a modular WHOIS query tool with support for:
//! - Standard WHOIS queries with IANA referral resolution
//! - Enhanced protocol features (server-side coloring, Markdown, images)
//! - DN42 and BGP.tools specialized queries
//! - Terminal output colorization for RIPE and BGP.tools formats
//! - RIR database hyperlinks (OSC 8) for interactive terminals
//!
//! # Public API
//!
//! The main entry point is [`WhoisQuery`]. Configure queries
//! with [`QueryOptions`] and process results through
//! [`OutputColorizer`] and
//! [`RirHyperlinkProcessor`].
//!
//! # Feature Flags
//!
//! - `images` — enables inline image display via `viuer` (requires terminal support).

pub mod cli;
pub mod query;
pub mod colorize;
pub mod servers;
pub mod hyperlink;
pub mod protocol;
pub mod markdown;

pub use cli::Cli;
pub use query::{WhoisQuery, QueryResult, QueryOptions};
pub use colorize::{ColorScheme, OutputColorizer};
pub use servers::{ServerSelector, WhoisServer};
pub use hyperlink::{RirHyperlinkProcessor, RipeHyperlinkProcessor, is_ripe_response, is_rir_response, terminal_supports_hyperlinks};
pub use protocol::{WhoisColorProtocol, ServerCapabilities};
pub use markdown::MarkdownRenderer; 