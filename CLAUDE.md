# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build Commands
```bash
# Build the project
cargo build

# Build optimized release version
cargo build --release

# Install locally 
cargo install --path .
```

### Testing
```bash
# Run all tests
cargo test

# Run tests with verbose output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Development
```bash
# Check code without building
cargo check

# Format code
cargo fmt

# Run clippy linter
cargo clippy

# Run clippy with all targets
cargo clippy --all-targets
```

## Architecture Overview

This is a Rust-based WHOIS query tool with a modular architecture designed for cross-platform operation and extensible output formatting.

### Core Modules

- **`src/cli.rs`**: Command-line interface using clap with comprehensive argument parsing and feature flags
- **`src/query.rs`**: Network communication layer handling WHOIS protocol, server selection, and query execution
- **`src/servers.rs`**: Server selection logic with IANA resolution, fallback mechanisms, and specialized server support
- **`src/colorize.rs`**: Output formatting with automatic format detection (RIPE vs BGP.tools) and color schemes
- **`src/hyperlink.rs`**: Terminal hyperlink generation for RIR database results using OSC 8 sequences
- **`src/lib.rs`**: Public API interface and module exports
- **`src/main.rs`**: Application entry point orchestrating CLI parsing, query execution, and output processing

### Key Design Patterns

**Query Flow Architecture**: The application follows a pipeline pattern:
1. CLI argument parsing and validation
2. Server selection (IANA lookup → specific server selection)
3. Network query execution with fallback mechanisms
4. Response processing (hyperlink injection → colorization)
5. Terminal output with format detection

**Extensible Output Processing**: Output processors are chained:
- RIR detection and hyperlink injection (format-agnostic)
- Format detection (RIPE standard vs BGP.tools table format)
- Color scheme application based on detected format

**Specialized Server Support**: The tool supports multiple query modes:
- Standard WHOIS with IANA resolution
- DN42 network queries (lantian.pub) with auto-detection of AS42424xxxxx patterns
- BGP.tools enhanced queries for ASN information
- Custom server specification bypassing auto-detection

### Testing Strategy

The codebase includes comprehensive unit tests focused on:
- CLI argument parsing and flag combinations
- Auto-detection logic (DN42 ASN patterns, RIR response formats)
- Color scheme detection and application
- Hyperlink generation for different RIR sources

Tests are located inline with modules using `#[cfg(test)]` blocks and follow Rust testing conventions with descriptive test names and comprehensive coverage of edge cases.