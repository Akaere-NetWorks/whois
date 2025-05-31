# WHOIS Query Tool

A simple, cross-platform WHOIS query tool with colorized output and advanced features.

## Features

- Automatic WHOIS server resolution through IANA
- Query WHOIS information for domains or IP addresses
- Support for custom WHOIS servers (bypassing IANA lookup)
- Support for DN42 network queries via lantian.pub
- Auto-detection of DN42 ASNs (AS42424xxxxx)
- Support for BGP.tools queries
- Intelligent format detection and colorization for RIPE and BGP.tools formats
- Custom port number support
- Verbose output mode
- **NEW:** Support for specifying the default WHOIS server via environment variable

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

```bash
# Basic usage (with automatic IANA lookup)
whois example.com

# Using a custom WHOIS server (bypassing IANA lookup)
whois example.com --server whois.verisign-grs.com

# Query DN42 network information
whois 172.22.0.1 --42

# Automatic DN42 detection
whois AS4242420000
# ^ This will automatically use the DN42 server without needing the --42 flag

# Query BGP information from bgp.tools
whois AS64496 --bgptools

# Using a custom port
whois example.com --port 4343

# Display verbose output (shows lookup process)
whois example.com --verbose

# Disable colored output
whois example.com --no-color

# Show help information
whois --help
```

### Specify WHOIS server via CLI
```bash
whois -s whois.example.net example.com
```

### Specify WHOIS server via environment variable
If `-s/--server` is not provided, the tool will check the `WHOIS_SERVER` environment variable.

#### Linux/macOS:
```bash
export WHOIS_SERVER=whois.example.net
whois example.com
```

#### Windows (cmd):
```bat
set WHOIS_SERVER=whois.example.net
whois example.com
```

#### Windows (PowerShell):
```powershell
$env:WHOIS_SERVER="whois.example.net"
whois example.com
```

If neither is set, the tool uses the default behavior (IANA referral or built-in default).

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