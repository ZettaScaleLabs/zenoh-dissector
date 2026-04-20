{
  description = "zenoh-dissector devShell (C+Rust cdylib architecture)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable?shallow=1";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        commonPkgs = with pkgs; [
          # Rust toolchain
          rust

          # C build
          cmake
          gcc
          pkg-config
          glib

          # Wireshark (provides libwireshark-dev headers + tshark)
          wireshark

          # Dev utilities
          openssl
          libpcap
          eza
          fd
          cargo-machete
          cargo-expand
          lldb
          lld
          sccache
        ];

        LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (with pkgs; [
          openssl
          libpcap
          stdenv.cc.cc.lib
        ]);

        shellHook = ''
          export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig:${pkgs.wireshark}/lib/pkgconfig"
          export LIBCLANG_PATH="${pkgs.llvmPackages.libclang.lib}/lib"
          export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}

          mkdir -p $HOME/.cargo
          cat > $HOME/.cargo/config.toml <<EOF
          [build]
          rustc-wrapper = "sccache"
          jobs = 4
          EOF
        '';

      in {
        devShells.default = pkgs.mkShell {
          name = "zenoh-dissector-c-cdylib";
          buildInputs = commonPkgs;
          inherit LD_LIBRARY_PATH;
          shellHook = shellHook;
        };
      }
    );
}
