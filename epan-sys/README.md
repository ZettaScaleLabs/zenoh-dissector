# Rust FFI Bindings for Wireshark's Epan Library

Epan, Enhanced Packet ANalyzer, is the packet analyzing engine in Wireshark. It provides rich APIs to let users develop their dissectors.
We use bindgen to generate a Rust FFI bindings based on its c library.

## Usage

Link and build the library

```bash
cargo build --release
```

## Re-generate the _bindings.rs_ or _bindings_windows.rs_ depending on the platform

```bash
cargo build --release -F bindgen
```

## Acknowledgment

This crate is adapted from [immanuelhume](https://github.com/immanuelhume)'s works in this [project](https://github.com/ghpr-asia/wsdf/tree/main/epan-sys)
