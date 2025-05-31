# WHOIS Query Tool

A simple, cross-platform WHOIS query tool with colorized output and advanced features.

## Features

- **Modular Architecture**: Clean, maintainable code structure with separate modules for CLI, query handling, server selection, and colorization
- **Improved Colorization**: Enhanced color schemes with better detection and more accurate field-specific coloring
- **Automatic WHOIS server resolution** through IANA
- **Smart Server Selection**: Intelligent server selection based on query type and configuration
- **Color Output**: Beautiful, readable output with syntax highlighting
- **Environment Variable Support**: Configure default server via `WHOIS_SERVER`
- **Multi-platform**: Works on Linux, macOS, and Windows
- **DN42 Support**: Special handling for DN42 ASN queries with `--dn42` flag
- **BGP Tools Integration**: Enhanced ASN queries with `--bgptools` flag
- **Terminal Hyperlinks**: Clickable links for all RIR database results (enabled by default)
- Query WHOIS information for domains or IP addresses
- Support for custom WHOIS servers (bypassing IANA lookup)
- Support for DN42 network queries via lantian.pub
- Auto-detection of DN42 ASNs (AS42424xxxxx)
- Support for BGP.tools queries
- Intelligent format detection and colorization for RIPE and BGP.tools formats
- Custom port number support
- Verbose output mode

## Code Structure

The codebase is organized into the following modules:

- **`src/cli.rs`**: Command-line interface and argument parsing
- **`src/query.rs`**: WHOIS query logic and network communication
- **`src/servers.rs`**: Server selection and configuration
- **`src/colorize.rs`**: Output colorization with multiple schemes
- **`src/lib.rs`**: Library interface and module exports
- **`src/main.rs`**: Main application entry point

## How It Works

1. The tool first queries the IANA WHOIS server to find the appropriate WHOIS server for the domain
2. Then it queries the referred WHOIS server to get the actual information
3. If a referral server cannot be found, it falls back to RIPE's WHOIS server (whois.ripe.net)
4. Special flags can be used to query specific servers for specialized information
5. ASNs starting with "AS42424" are automatically detected and queried using the DN42 server
6. Results are colorized intelligently based on the detected format (RIPE or BGP.tools)

## Installation

```bash
cargo install --path .
```

## Usage

### Basic Usage

```bash
# Query a domain
whois example.com

# Query an IP address  
whois 8.8.8.8

# Query an ASN
whois AS15169

# Use specific server
whois -s whois.ripe.net AS3333

# DN42 queries
whois --dn42 AS4242420000

# BGP Tools enhanced queries
whois --bgptools AS15169

# Hyperlinks are enabled by default for RIR results  
whois AS3333

# Disable hyperlinks if needed
whois --no-hyperlinks AS3333
```

### Advanced Features

#### Terminal Hyperlinks

Hyperlinks are **enabled by default** for all Regional Internet Registry (RIR) database results. The tool automatically detects RIR responses using the `source:` field and creates appropriate hyperlinks using RIPE's Global Resources Service:

```bash
# Hyperlinks are enabled by default
whois AS3333

# Combine with verbose mode for detailed output
whois --verbose AS3333

# Disable hyperlinks if needed
whois --no-hyperlinks AS3333
```

**Key Features:**
- **Multi-RIR Support**: Handles responses containing data from multiple RIRs
- **Source-based Detection**: Uses `source:` fields for accurate RIR identification
- **Global Resources**: All hyperlinks use RIPE's Global Resources Service for unified access
- **Block Processing**: Splits multi-RIR responses into appropriate blocks for targeted linking

**Supported RIRs:**
- **RIPE NCC** (Europe, Middle East, Central Asia) - `source: RIPE`
- **ARIN** (North America) - `source: ARIN`
- **APNIC** (Asia Pacific) - `source: APNIC`
- **LACNIC** (Latin America and Caribbean) - `source: LACNIC`
- **AFRINIC** (Africa) - `source: AFRINIC`

**Supported Terminals:**
- Most modern terminals support OSC 8 hyperlinks
- Automatically detected: GNOME Terminal, iTerm2, Windows Terminal, Alacritty, Kitty, WezTerm, foot
- VTE-based terminals (most Linux terminals)
- Works on both Linux/macOS and Windows (including PowerShell)

**Clickable Elements:**
- ASN numbers (aut-num, origin fields)
- IP networks (inetnum, inet6num, route, route6)
- Organizations (organisation, org)
- Contacts (nic-hdl, admin-c, tech-c)  
- Maintainers (mntner, mnt-by)
- Domain objects
- RIR-specific identifiers (NetRange, CIDR, OrgId)

## Format-Specific Colorization

The tool automatically detects the output format and applies appropriate colorization:

### RIPE Format Colorization

For RIPE and standard WHOIS responses (field: value format):

- AS Numbers: **Bright Red**
- Network Information Fields: **Bright Cyan**
- Organization and Contact Fields: **Bright Green**
- Import/Export and Peering Fields: **Bright Blue**
- Status Fields: **Bright Yellow**
- Date and Timestamp Fields: **Bright Magenta**
- Location and IP Address Values: **Bright Cyan**
- Comments and Remarks: **Dark Gray**
- Error Messages: **Bright Red**

### BGP.tools Format Colorization

For BGP.tools table format (columns separated by |):

- Table Headers: **Bright Cyan Bold**
- AS Numbers: **Bright Red**
- IP Addresses and BGP Prefixes: **Bright Cyan**
- Country Codes: **Bright Yellow**
- Registry Information: **Bright Blue**
- Allocation Dates: **Bright Magenta**
- AS Names: **Bright White Bold**

## Building

```bash
cargo build --release
```

The compiled executable can be found at `target/release/whois`. 