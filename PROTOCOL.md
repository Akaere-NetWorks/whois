# WHOIS-COLOR Protocol v1.0 Specification

This document describes a server-side coloring private protocol for WHOIS servers.

## Design Goals

1. **Backward Compatibility**: Does not affect the normal operation of standard WHOIS servers
2. **Server-side Coloring**: Supporting servers can return pre-colored output
3. **Default Server Rendering**: Server-side rendering is enabled by default when supported
4. **Extensibility**: Supports multiple coloring schemes

## Protocol Flow

### 1. Capability Detection Phase

Client sends capability probe request:
```
X-WHOIS-COLOR-PROBE: v1.0\r\n\r\n
```

**Supporting server response**:
```
X-WHOIS-COLOR-SUPPORT: v1.0 schemes=ripe,bgptools,mtf\r\n
```

**Non-supporting servers**:
- Ignore the request or return standard error
- Client uses server-side rendering by default if supported

### 2. Query Phase

If server supports coloring protocol, client sends:
```
X-WHOIS-COLOR: scheme=ripe\r\n
example.com\r\n
```

If server doesn't support protocol, client sends standard query:
```
example.com\r\n
```

### 3. Response Handling

- **Server Coloring**: Server returns response containing ANSI color sequences
- **Client Detection**: Checks if response contains `\x1b[` color sequences
- **Fallback Behavior**: If server doesn't provide colors, automatically falls back to client-side coloring

## Protocol Headers

### Capability Probe
- `X-WHOIS-COLOR-PROBE: v1.0` - Probe if server supports coloring protocol

### Server Capability Response
- `X-WHOIS-COLOR-SUPPORT: v1.0 schemes=ripe,bgptools,mtf` - Server supported schemes

### Coloring Request
- `X-WHOIS-COLOR: scheme=ripe` - Request specific coloring scheme

## Supported Coloring Schemes

1. **ripe** - RIPE format standard coloring (field:value pairs)
2. **bgptools** - BGP.tools table format coloring
3. **mtf** - Rainbow flag color scheme

## Backward Compatibility Guarantees

### Compatibility with Standard WHOIS Servers
1. **Timeout Mechanism**: Capability probe uses 2-second timeout
2. **Error Handling**: All protocol errors fall back to standard WHOIS queries
3. **Transparent Operation**: Seamless protocol switching

### Compatibility with Existing Clients
1. **Default Server Rendering**: Server-side rendering is attempted by default
2. **Automatic Fallback**: Falls back to client-side coloring when server doesn't provide colors
3. **Standard Output**: Maintains same output format
4. **Graceful Degradation**: Falls back to standard WHOIS when protocol fails

## Implementation Details

### Capability Probe Implementation
```rust
pub fn probe_capabilities(&self, server_address: &str) -> Result<ServerCapabilities> {
    // Connect to server
    let mut stream = TcpStream::connect(server_address)?;
    
    // Set short timeout
    stream.set_read_timeout(Some(Duration::from_millis(2000)))?;
    
    // Send probe request
    stream.write_all(b"X-WHOIS-COLOR-PROBE: v1.0\r\n\r\n")?;
    
    // Read and parse response
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    
    Ok(parse_capability_response(&response))
}
```

### Query Implementation
```rust
pub fn query_with_color(&self, query: &str, capabilities: &ServerCapabilities) -> Result<String> {
    let query_string = if capabilities.supports_color {
        format!("X-WHOIS-COLOR: scheme=ripe\r\n{}\r\n", query)
    } else {
        format!("{}\r\n", query)
    };
    
    // Standard TCP connection and query...
}
```

### Response Detection
```rust
pub fn is_server_colored(&self, response: &str) -> bool {
    // Check for ANSI color sequences
    response.contains("\x1b[") || 
    // Check for protocol markers (optional)
    response.contains("X-WHOIS-COLOR-APPLIED:")
}
```

## Usage Examples

### Server-side Coloring (Default)
```bash
# Server-side rendering is enabled by default
whois example.com

# Verbose output shows protocol status
whois --verbose example.com
```

### Output Examples

#### Server Supports Coloring
```
$ whois --verbose example.com
Query: example.com
Probing color capabilities for: whois.iana.org:43
Server capabilities: ServerCapabilities { supports_color: true, schemes: ["ripe"] }
Requesting server-side coloring with scheme: ripe
Querying IANA at: whois.iana.org:43
IANA referred to: whois.verisign-grs.com
Final server used: whois.verisign-grs.com
Server-side coloring: enabled
Using server-provided coloring
```

#### Server Doesn't Support Coloring (Fallback)
```
$ whois --verbose example.com
Query: example.com
Probing color capabilities for: whois.iana.org:43
No capability response, assuming standard WHOIS
Querying IANA at: whois.iana.org:43
IANA referred to: whois.verisign-grs.com
Final server used: whois.verisign-grs.com
Server coloring not available, using client-side coloring
```

## Server-side Implementation Guide

### Basic Support
1. Recognize `X-WHOIS-COLOR-PROBE` requests
2. Respond with server capabilities
3. Handle `X-WHOIS-COLOR` coloring requests
4. Return ANSI-colored responses

### Example Server Response
```
# Capability response
X-WHOIS-COLOR-SUPPORT: v1.0 schemes=ripe\r\n

# Colored query response  
domain:      \x1b[1;37mexample.com\x1b[0m
registrar:   \x1b[1;36mExample Registrar\x1b[0m
status:      \x1b[1;32mACTIVE\x1b[0m
```

## Security Considerations

1. **Input Validation**: Servers should validate protocol header formats
2. **Resource Limits**: Prevent malicious clients from consuming server resources
3. **Safe Degradation**: Protocol failures should safely fall back to standard behavior
4. **Injection Protection**: Prevent command injection through protocol headers

## Test Coverage

The protocol implementation includes comprehensive unit tests:
- Capability response parsing tests
- Color scheme selection tests
- Degradation mechanism tests
- Backward compatibility tests

All tests pass, ensuring protocol stability and compatibility.