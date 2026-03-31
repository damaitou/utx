# UTX Project - Agent Documentation

## Project Overview

UTX (Unidirectional Transmission) is a high-performance unidirectional data transfer gateway (air-gap) system designed for secure one-way data transmission between isolated networks. It operates at the Ethernet layer using raw sockets to transfer data from a TX (transmit) side to an RX (receive) side through a physical unidirectional link.

**Version**: 1.2.2  
**Author**: damaitou  
**Language**: Rust (Edition 2018) with C components  
**License**: Proprietary

### Core Purpose

UTX provides secure unidirectional data ferrying capabilities supporting:
- File transfers via FTP/SFTP protocols
- UDP datagram transmission
- Raw Ethernet packet-based custom protocol (UTX protocol)
- Content filtering and virus scanning
- Comprehensive audit logging

## Technology Stack

### Primary Languages
- **Rust** (Edition 2018) - Main application logic
- **C** - Low-level network operations (raw socket handling, packet crafting)

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `mio` (0.6) | Async I/O and event polling |
| `rocket` (0.5.0-rc.2) | Web API framework |
| `serde`/`serde_json` | Configuration and data serialization |
| `mysql` (17) | Audit database connectivity |
| `openssl` (0.10) | Encryption (AES-128-CBC) |
| `ssh2` | SFTP client functionality |
| `inotify` | File system monitoring |
| `ringbuf` | Lock-free ring buffers for data transfer |
| `flexi_logger` | Logging infrastructure |
| `error-chain` | Error handling |
| `lazy_static` | Static initialization |
| `chrono` | Date/time handling |
| `md5` | Checksum computation |
| `rand` | Random number generation |
| `regex` | Pattern matching |
| `base64` | Encoding/decoding |
| `encoding` | Character encoding (UTF-8/GBK) |
| `radix_trie` | Trie data structures |
| `daemonize` | Daemon process creation |
| `async-std` | Async runtime (for aftpd) |
| `socket2` | Advanced socket operations |
| `docopt` | CLI argument parsing |

### External C Libraries
- `libmagic` - File type detection
- Custom C libraries: `libutx.a`, `libtrie.a`, `libfilemagic.a`

### System Dependencies
- Linux kernel with raw socket support
- MySQL/MariaDB for audit logging
- ClamAV (optional) for virus scanning
- libmagic-dev (for file type detection)

## Project Structure

```
utx/
├── Cargo.toml          # Main project configuration
├── build.rs            # Custom build script for C compilation
├── src/
│   ├── lib/            # Library modules (mylib)
│   │   ├── lib.rs      # Library entry point
│   │   ├── config.rs   # Configuration parsing and management
│   │   ├── utx.rs      # UTX protocol Rust bindings
│   │   ├── ftp.rs      # FTP client implementation
│   │   ├── sftp.rs     # SFTP client implementation
│   │   ├── audit.rs    # Audit logging system
│   │   ├── context.rs  # Thread context definitions
│   │   ├── def.rs      # Core trait definitions (FileTransfer)
│   │   ├── errors.rs   # Error types
│   │   ├── util.rs     # Utility functions
│   │   ├── virus.rs    # Virus scanning (ClamAV integration)
│   │   ├── word_checker.rs  # Keyword filtering
│   │   ├── file_list_history.rs  # File tracking
│   │   ├── license.rs  # License validation
│   │   └── version.rs  # Version information
│   ├── binprog/        # Binary programs
│   │   ├── ds.rs       # Datagram Sender (TX side UDP service)
│   │   ├── es.rs       # Endpoint Server (RX side main service)
│   │   ├── aftpd.rs    # Async FTP daemon
│   │   ├── fpull.rs    # File pull utility
│   │   ├── uproxy.rs   # UDP proxy
│   │   ├── btx.rs      # TCP bridge (TX side)
│   │   ├── agent.rs    # Agent service
│   │   ├── ctrl.rs     # Control utility
│   │   ├── util/       # Binary utilities
│   │   │   ├── mod.rs
│   │   │   ├── utx.rs  # UTX helper utilities
│   │   │   ├── iptables.rs
│   │   │   ├── mychannel.rs
│   │   │   ├── poller.rs
│   │   │   └── errors.rs
│   │   └── config/     # Configuration modules
│   ├── c/              # C source code
│   │   ├── cutx.c      # UTX sender implementation
│   │   ├── cutx.h      # UTX sender header
│   │   ├── sutx.c      # UTX receiver implementation
│   │   ├── utx.h       # UTX protocol definitions
│   │   ├── radix_trie.c # Trie implementation for keyword matching
│   │   ├── file_magic.c # File type detection
│   │   └── ...
│   ├── checker/        # Additional checkers
│   └── test/           # Test code
├── magic/              # Magic number database files
├── release_centos7/    # Release builds
└── target/             # Cargo build output
```

## Build System

### Build Commands

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Build specific binary
cargo build --release --bin ds
cargo build --release --bin es
cargo build --release --bin aftpd
cargo build --release --bin fpull
```

### Build Configuration

The `build.rs` script:
1. Compiles C source files into static libraries:
   - `src/c/cutx.c` + `src/c/sutx.c` → `libutx.a` (UTX protocol)
   - `src/c/radix_trie.c` → `libtrie.a` (Keyword matching)
   - `src/c/file_magic.c` → `libfilemagic.a` (File type detection)
2. Sets build timestamp environment variable
3. Links against system `libmagic`

### Release Profile

```toml
[profile.release]
opt-level = 3        # Maximum optimization
lto = true           # Link Time Optimization
codegen-units = 1    # Single codegen unit for better optimization
```

## 2025 Compatibility Fixes

This project was originally developed in 2021 and required updates to compile with modern Rust toolchain (2025):

### Dependency Version Adjustments

| Dependency | Old Version | New Version | Reason |
|------------|-------------|-------------|--------|
| `time` | 0.3 | 0.1.45 | `get_time()` API removed in 0.3 |
| `mysql` | 23 | 17 | `prepare()`/`prep_exec()` APIs changed |
| `socket2` | 0.5 | 0.3 | `Domain::ipv4()` → `Domain::IPV4`, etc. |
| `des` | 0.3.0 | removed | Crate yanked, replaced with OpenSSL |
| `block-cipher-trait` | 0.6 | removed | All versions yanked |
| `generic-array` | 0.12.3 | removed | No longer needed |
| `xxhash-rust` | - | 0.8 | Added XXH3 hashing for file integrity check |

### Code Changes

1. **`src/lib/license.rs`**: Replaced DES encryption from `des` crate with OpenSSL's `symm::Cipher`
2. **`src/binprog/aftpd.rs`**: Updated `rand::gen_range(a, b)` to `rand::gen_range(a..b)`
3. **`src/binprog/agent_thread.rs`**: Fixed infinite loop return type issue
4. **`src/c/cutx.c`**: Added `static` to `inline` functions (`get_file_size`)
5. **`src/c/sutx.c`**: Added `static` to `inline` functions (`guess_block_size`, `handle_frame`)
6. **`src/lib/audit.rs`**: Added `mysql::prelude::*` import
7. **`src/lib/ftp.rs`**: Refactored file extension filtering and history tracking
   - Moved extension filtering from `ftp_list()`/`ftp_mlsd()` to `fetch_dir()` for unified handling
   - Changed return type of `ftp_list()`/`ftp_mlsd()` to `Vec<(u8, String, String)>` to include raw line for history tracking
   - Added `audit_fileext_check_failed()` method for consistent audit logging
   - Use `FILTERED:` prefix marker in history to avoid duplicate audit logs for filtered files
   - Use `FETCHED:` prefix marker for normal file deduplication
8. **`src/binprog/ftp_thread.rs`**: Enhanced `track_peer_files` condition
   - Added `ctx.fcc.file_ext_checker.is_some()` to enable history tracking when file extension filtering is configured
   - Prevents duplicate audit logs for filtered files in Client Pull mode
8. **`src/binprog/es.rs`**: Added XXH3 file hash calculation in RX file receiving process
9. **`src/c/sutx.c`**: Enhanced `loop()` function robustness - control channel failures no longer terminate data reception
10. **`src/binprog/es.rs`**: Added error logging for `c_write()` failures in `timer_thread_handler()` and `ctrl_thread_handler()`

### XXH3 File Hash (RX Side)

Added real-time file hash calculation during file reception in `es` (RX side):

- **Algorithm**: XXH3 (extremely fast, non-cryptographic hash)
- **Purpose**: File integrity verification
- **Implementation**: Streaming hash updated with each packet, final hash computed on tail packet
- **Log Output**: `INFO 文件通道{}接收文件'{}'完毕,丢包={},xxh3={}`

### Robustness Improvements (2025-03)

Improved error handling and fault tolerance in RX side (`es` binary):

1. **Control Channel Resilience (`src/c/sutx.c`)**:
   - Modified `loop()` function to continue data reception even when control channel (pipe) is closed by peer
   - Added `ctrl_fd_closed` flag to track control channel state
   - When control channel fails or is closed, the receiver continues to poll socket-only mode
   - Prevents control thread crashes from affecting core data ferrying functionality

2. **Error Logging Enhancements (`src/binprog/es.rs`)**:
   - Added error logging for `c_write()` failures in `timer_thread_handler()` - helps diagnose pipe write issues
   - Added error handling and logging for `c_write()` failures in `ctrl_thread_handler()` - prevents blocking on failed writes

### Build Configuration

- Disabled `lto = true` in release profile due to Rust compiler ICE (Internal Compiler Error)
- Set `codegen-units = 16` to reduce memory pressure during compilation

## Available Binaries

| Binary | Purpose | Side |
|--------|---------|------|
| `ds` | Datagram Sender - UDP packet transmission service | TX |
| `es` | Endpoint Server - Main receive service for files/datagrams | RX |
| `aftpd` | Async FTP daemon - FTP server for client mode | TX/RX |
| `fpull` | File pull utility - One-shot file transfer | TX/RX |

## Runtime Architecture

### UTX Protocol

UTX uses a custom Ethernet-level protocol (ETH_P_UTX = 0x0900) for unidirectional transmission:

**Packet Structure:**
- Ethernet header (14 bytes)
- UTX header (16 bytes):
  - `len:13` - Packet length
  - `abort:1` - Emergency stop flag
  - `tail:1` - End of transmission marker
  - `head:1` - Start of transmission marker
  - `seq:16` - Sequence number (per-channel)
  - `check:16` - Checksum
  - `type:8` - Packet type (SYS/DATAGRAM/BLOCK/FILE/AGENT)
  - `channel:8` - Channel ID (0-255)
  - `session_id:16` - TCP session ID (for BTX)
  - `packet_opt:2` - Stream vs Datagram mode
  - `packet_head:1` - Start of block
  - `packet_tail:1` - End of block

**Packet Types:**
- `UTX_TYPE_SYS (0)` - System/management
- `UTX_TYPE_DATAGRAM (1)` - UDP datagrams
- `UTX_TYPE_BLOCK (2)` - File blocks
- `UTX_TYPE_FILE (3)` - Complete files
- `UTX_TYPE_AGENT (4)` - Agent protocol data

### Channel Model

UTX supports up to 256 channels (0-255) for each data type:
- **File Channels**: FTP/SFTP file transfers
- **Datagram Channels**: UDP packet forwarding
- **TCP Channels**: TCP proxy (via BTX protocol)

Each channel has independent:
- Physical interface binding (pi_index)
- Virtual channel mapping (vchannel)
- Content filtering rules
- Audit configuration
- Flow limits

### TX Side (Transmit)

The TX side operates in various modes:

1. **Client Push Mode**: Actively pushes files to remote FTP/SFTP server
2. **Client Pull Mode**: Pulls files from remote FTP/SFTP server
3. **Server Mode**: Accepts incoming FTP connections from applications
4. **Internal Mode**: Local file system monitoring
5. **Agent Mode**: TCP proxy through custom agent protocol

### RX Side (Receive)

The RX side (`es` binary) receives UTX packets and:
- Reassembles file blocks
- Forwards datagrams via UDP or Agent TCP
- Stores files to local filesystem
- Handles BLOC mode (block-based file reconstruction)

## Configuration

UTX uses JSON configuration files with the following structure:

```json
{
  "side": "tx",
  "mtu": 1500,
  "physical_interfaces": [
    {
      "pi_index": 1,
      "interface": "eth0",
      "tx_mac": "6c:b3:11:51:4c:d7",
      "rx_mac": "6c:b3:11:51:4c:d8"
    }
  ],
  "file_channels": [
    {
      "channel": 0,
      "vchannel": 100,
      "pi_index": 1,
      "ftp_mode": "client_push",
      "client_setting": {
        "remote_ftp_host_address": "192.168.1.100:21",
        "remote_ftp_user": "user",
        "remote_ftp_password": "pass",
        "remote_ftp_root_path": "/remote/path",
        "local_root_path": "/local/path",
        "threads_number": 5,
        "scan_interval": 1000
      },
      "scan_virus": true,
      "audit": true
    }
  ],
  "datagram_channels": [
    {
      "channel": 0,
      "vchannel": 200,
      "pi_index": 1,
      "host": "192.168.1.200",
      "port": 5000,
      "audit": true
    }
  ],
  "audit_db_conn_string": "mysql://user:pass@localhost/utx_audit"
}
```

### Configuration Parameters

**Global Settings:**
- `side`: `"tx"` or `"rx"`
- `mtu`: 1500 or 8000
- `tx_busy_sleep_nanos`: Traffic control delay
- `rx_buffer_size_mb`: Receive buffer size (128-2048 MB)
- `log_level`: error/warn/info/debug/trace

**Channel Modes:**
- `internal`: Local filesystem only
- `server`: FTP server mode
- `client_push`/`client_push_ftp`: Push to remote FTP
- `client_pull`/`client_pull_ftp`: Pull from remote FTP
- `client_push_sftp`/`client_pull_sftp`: SFTP modes
- `client_push_agent`/`client_pull_agent`: Agent proxy modes

## Security Features

### Content Filtering
- **Keyword filtering**: Trie-based pattern matching on file content and datagrams
- **File extension filtering**: Allow/deny lists
- **File type filtering**: libmagic-based MIME type detection

### Encryption
- AES-128-CBC encryption for FTP control connections
- Configurable per-channel encryption keys

### Virus Scanning
- ClamAV integration via Unix socket
- Optional per-channel virus scanning

### Audit Logging
Comprehensive audit trail to MySQL:
- `file_audit_log`: File transfer events
- `datagram_audit_log`: UDP traffic statistics
- `alert_log`: Security alerts (keyword violations, viruses, etc.)

## Development Conventions

### Code Style
- Rust standard formatting (rustfmt)
- Chinese comments for business logic
- English for technical documentation
- Error handling via `error-chain` crate

### Error Handling Pattern
```rust
use mylib::errors::*;

fn example() -> Result<()> {
    some_operation().chain_err(|| "context message")?;
    Ok(())
}
```

### Thread Safety
- `lazy_static!` for global state
- `Mutex` for shared mutable state
- Channel-based communication between threads
- Ring buffers for lock-free data transfer

### Logging
Use the `log` crate macros:
```rust
log::{error, warn, info, debug, trace};
```

Log levels follow standard conventions:
- `ERROR`: Fatal errors requiring intervention
- `WARN`: Anomalies that don't stop operation
- `INFO`: Normal operational events
- `DEBUG`: Detailed debugging information
- `TRACE`: Very verbose protocol-level details

## Testing

### Test Commands
```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name
```

### Test Structure
- Unit tests in `src/test/test.rs`
- Integration tests via separate binaries (test, test_watch)

## Deployment

### Directory Structure (Runtime)
```
/utx/
├── audit/          # Audit log files
├── log/            # Application logs
├── unix/           # Unix domain sockets
├── cache/          # Temporary files
└── config.json     # Main configuration
```

### System Requirements
- Linux kernel 3.10+
- Root privileges (for raw socket access)
- SELinux configuration (if enabled)
- Network interface binding capabilities

### Service Management
Typical systemd service setup:
```ini
[Unit]
Description=UTX Datagram Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ds /utx/config.json
Restart=always

[Install]
WantedBy=multi-user.target
```

## Common Tasks

### Adding a New Binary
1. Create `src/binprog/newbin.rs`
2. Add entry to `Cargo.toml`:
```toml
[[bin]]
name = "newbin"
path = "src/binprog/newbin.rs"
```

### Adding C Code
1. Add `.c` file to `src/c/`
2. Update `build.rs` to compile it:
```rust
cc::Build::new()
    .file("src/c/newfile.c")
    .compile("libnew.a");
```

### Database Schema Updates
Modify the `create_table_*` functions in `src/lib/audit.rs`.

## Troubleshooting

### Common Issues

1. **Permission denied on raw sockets**: Ensure running as root or with CAP_NET_RAW
2. **MySQL connection failures**: Check `audit_db_conn_string` format
3. **MAC address not found**: Verify `tx_mac`/`rx_mac` match actual interfaces
4. **Build failures**: Install `libmagic-dev`, `libssl-dev`, `libclang-dev`

### Debug Flags
- Enable debug logging: `"log_level": "debug"` in config
- Use `RUST_BACKTRACE=1` for panic traces
- Check `/utx/log/` for application logs

## License

Proprietary - All rights reserved by damaitou
