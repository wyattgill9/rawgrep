# rawgrep

The fastest grep-like tool for searching text directly on raw block devices.

## Why is `rawgrep` the fastest?

- `rawgrep` reads files DIRECTLY from your partition.
- `rawgrep` is incredibly straightforward, cache-friendly and zero-copy, simply streaming through your device and outputting the matches.

## Installation

### Option 1: One-Time Setup with Capabilities (Recommended)

```bash
# Build the release binary
cargo build --profile=release-fast

# If you want maximum speed possible:
# cargo +nightly build --profile=release-fast --target=<your_target> --features=use_nightly

# Run the one-time setup command. Why? Read "Why rawgrep Needs Elevated Permissions" section
sudo setcap cap_dac_read_search=eip ./target/<your_target>/release-fast/rawgrep
```

Now you can run it directly with:
```bash
rawgrep "search pattern"
```

### Option 2: Use `sudo` Every Time

If you prefer not to use capabilities, just build and run with `sudo`:

```bash
# Build the release binary
cargo build --release

# Again, if you want maximum speed possible:
# cargo +nightly build --profile=release-fast --target=<your_target> --features=use_nightly

# Run with sudo each time
sudo ./target/release-fast/rawgrep "search pattern"
```

## Usage

```bash
rawgrep "search pattern"

# Search in any directory, any pattern, on any device
rawgrep "foo|bar.*|baz" .. --device=<device>
```

## Why rawgrep Needs Elevated Permissions

`rawgrep` needs to read raw block devices, which are normally protected by the operating system. Instead of requiring you to run it with `sudo` every time (which would give it full root access), we use Linux capabilities to grant it **only** the specific permission it needs.

We use the `CAP_DAC_READ_SEARCH` Linux capability, which grants exactly one permission: bypass file read permission checks.

**This tool needs elevated permissions specifically to open and read these protected device files.** Once opened, it only reads data - it never writes anything to disk.

### Verifying Capabilities

You can verify what capabilities the binary has:

```bash
getcap ./target/release/rawgrep
# Output: ./target/release/rawgrep = cap_dac_read_search+eip
```

### Removing Capabilities

If you want to revoke the capability and go back to using `sudo`:

```bash
sudo setcap -r ./target/release/rawgrep
```

## Development

**Note:** Capabilities are tied to the binary file itself, so you'll need to re-run `setcap` after each rebuild.

Why don't we ship a script to automate that? I find scripts (especially that require `sudo`) unsafe, if you want to have such a script, write it yourself, it's basically 5 lines of bash code.
