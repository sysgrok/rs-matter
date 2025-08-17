# rs-matter
A pure-Rust, `no_std`, no-alloc, async-first implementation of the Matter protocol for IoT devices.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### System Dependencies
Install required system dependencies first:
- `sudo apt update && sudo apt install -y libdbus-1-dev pkg-config libavahi-client-dev libavahi-common-dev`

### Build Commands
- **Basic check**: `cargo check` -- takes 48 seconds. NEVER CANCEL. Set timeout to 2+ minutes.
- **Build with default features**: `cargo build` -- takes 49 seconds. NEVER CANCEL. Set timeout to 2+ minutes.
- **Build with zeroconf (recommended)**: `cargo build --features zeroconf` -- takes 68 seconds. NEVER CANCEL. Set timeout to 2+ minutes.
- **Build with avahi (Linux)**: `cargo build --features avahi` -- takes 2.3 minutes. NEVER CANCEL. Set timeout to 4+ minutes.
- **Build examples**: `cd examples && cargo build --features zeroconf` -- takes 63 seconds. NEVER CANCEL. Set timeout to 2+ minutes.
- **CI-style build**: `cargo build --no-default-features --features rustcrypto,os,log` -- takes 49 seconds. NEVER CANCEL. Set timeout to 2+ minutes.
- **Minimal build**: `cargo build --no-default-features --features rustcrypto` -- takes 31 seconds. NEVER CANCEL. Set timeout to 2+ minutes.

### Test Commands
- **Run tests**: `cargo test -- --test-threads 1` -- takes 2.4 minutes. NEVER CANCEL. Set timeout to 5+ minutes.
- **Run benchmarks**: `cd rs-matter && cargo bench --no-default-features --features rustcrypto,os,log` -- takes 1.2 minutes. NEVER CANCEL. Set timeout to 3+ minutes.

### Lint and Format Commands
- **Format check**: `cargo fmt -- --check` -- takes 1 second.
- **Clippy (warnings only)**: `cargo clippy --no-deps --no-default-features --features rustcrypto,os,log` -- takes 25 seconds. Set timeout to 1+ minutes.
- **Note**: Clippy with `-Dwarnings` will fail due to lifetime warning issues in the codebase. Use without `-Dwarnings` for warnings-only mode.

### Feature Sets
Platform-specific mDNS implementations (choose based on target platform):
- **Linux**: `--features avahi` or `--features zeroconf` 
- **MacOS**: `--features astro-dnssd`
- **Windows**: `--features astro-dnssd` or `--features zeroconf`
- **Embedded**: `--features builtin` or `--features resolve`

Crypto backends:
- **rustcrypto** (default): Pure Rust crypto implementation
- **openssl**: Uses OpenSSL (requires OpenSSL dev libraries)
- **mbedtls**: Uses mbedTLS (currently broken according to Cargo.toml comment)

## Validation

### Manual Testing Scenarios
Always test examples after making changes:
1. **Basic functionality**: Run `./target/debug/onoff_light` for 10-30 seconds to verify:
   - Shows Matter pairing codes (format: XXXX-XXXX-XXX)
   - Displays QR code in ASCII format
   - Reports memory usage statistics
   - Simulates device functionality (lamp toggle every 5 seconds)
   - Creates mDNS services (may show permission warnings in sandboxed environments)

2. **Build validation**: Always run both check and build commands before committing changes.

3. **Test validation**: Run the full test suite when modifying core functionality.

### Expected Behavior
- Examples output pairing codes like "3497-0112-332"
- QR codes display as ASCII art blocks
- Device functionality is simulated with periodic status updates
- mDNS warnings about "Operation not permitted" are expected in sandboxed environments and don't indicate failure

## Common Tasks

### Build Issues
- **Missing dbus**: Install `libdbus-1-dev pkg-config`
- **Missing avahi**: Install `libavahi-client-dev libavahi-common-dev`
- **Clippy errors with -Dwarnings**: Known issue with lifetime warnings. Use clippy without `-Dwarnings`.

### Running Examples
Built examples are located in `target/debug/`:
- `onoff_light` - Basic on/off light device
- `speaker` - Smart speaker device  
- `bridge` - Matter bridge device
- `media_player` - Media player device
- `onoff_light_bt` - Bluetooth variant (requires `zbus` feature)

### Project Structure
- `rs-matter/` - Core Matter protocol implementation
- `rs-matter-macros/` - Procedural macros for IDL code generation
- `examples/` - Example Matter devices
- `.github/workflows/ci.yml` - CI configuration with matrix builds

### Timeout Guidelines
**CRITICAL**: Build and test commands can take significant time. Always use adequate timeouts:
- Basic builds: 2+ minutes
- Feature builds: 2-4+ minutes  
- Tests: 5+ minutes
- NEVER CANCEL builds or tests early - they will complete successfully

### Platform Notes
- Linux: Requires dbus and avahi system libraries
- Network permissions: Examples may show mDNS permission warnings in sandboxed environments
- Memory usage: Examples report memory allocation details for embedded optimization

Fixes #3.