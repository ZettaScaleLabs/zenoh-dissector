build_dir := "_tmp/cmake-build"

# Build both the Rust cdylib and the C Wireshark plugin
build:
    cargo build -p zenoh-codec-ffi -j4
    cmake -B {{build_dir}} -S .
    cmake --build {{build_dir}} -j4

# Build in release mode
build-release:
    cargo build -p zenoh-codec-ffi --release -j4
    cmake -B {{build_dir}} -S . -DCMAKE_BUILD_TYPE=Release
    cmake --build {{build_dir}} --config Release -j4

# Rebuild only the Rust cdylib (decoding logic / field changes)
build-codec:
    cargo build -p zenoh-codec-ffi -j4

# Rebuild only the C plugin (epan interactions / no Rust changes)
build-plugin:
    cmake --build {{build_dir}} -j4

# Install to the personal Wireshark plugin directory (symlinks, so rebuild is enough)
install: build
    #!/usr/bin/env bash
    set -euo pipefail
    plugin_base=$(tshark -G folders 2>/dev/null | awk -F'\t' '/Personal Plugins/{print $NF}')
    epan_dir="$plugin_base/epan"
    mkdir -p "$epan_dir"
    ln -sf "$(pwd)/{{build_dir}}/packet-zenoh.so" "$epan_dir/packet-zenoh.so"
    # cdylib goes one level above epan/ so Wireshark's plugin scanner ignores it
    ln -sf "$(pwd)/target/debug/libzenoh_codec_ffi.so" "$plugin_base/libzenoh_codec_ffi.so"
    echo "Installed to $epan_dir"

# Run unit tests (no Wireshark needed)
test-unit:
    cargo test -p zenoh-codec-ffi --lib -j4

# Run integration tests (requires Wireshark + tshark)
test-integration:
    cargo test -p zenoh-codec-ffi --test dissector -- --test-threads=1

# Run all tests
test: test-unit test-integration

# Check formatting and lints
check:
    cargo fmt -p zenoh-codec-ffi -- --check
    cargo clippy -p zenoh-codec-ffi --all-targets -- --deny warnings

# Clean all build artifacts
clean:
    cargo clean
    rm -rf {{build_dir}}
