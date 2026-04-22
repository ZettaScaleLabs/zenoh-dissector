{
  description = "zenoh-dissector devShell (C+Rust cdylib architecture)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable?shallow=1";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      flake-utils,
      git-hooks,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        pre-commit-check = git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            rustfmt.enable = true;
            taplo.enable = true;
            markdownlint-cli2.enable = true;
          };
        };

        commonPkgs =
          with pkgs;
          [
            rust
            cmake
            gcc
            pkg-config
            glib
            wireshark
            openssl
            libpcap
            eza
            fd
            just
            cargo-machete
            cargo-expand
            lldb
            lld
            sccache
          ]
          ++ pre-commit-check.enabledPackages;

        LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (
          with pkgs;
          [
            openssl
            libpcap
            stdenv.cc.cc.lib
          ]
        );

        shellHook = ''
          ${pre-commit-check.shellHook}
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

      in
      {
        checks = {
          inherit pre-commit-check;
        };
        devShells.default = pkgs.mkShell {
          name = "zenoh-dissector-c-cdylib";
          buildInputs = commonPkgs;
          inherit LD_LIBRARY_PATH;
          shellHook = shellHook;
        };
      }
    );
}
