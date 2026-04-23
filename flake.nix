{
  description = "zenoh tshark dissector (Rust cdylib + C wrapper) as a Nix package";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable?shallow=1";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, rust-overlay, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rust = pkgs.rust-bin.stable."1.93.0".default;
        rustPlatform = pkgs.makeRustPlatform {
          cargo = rust;
          rustc = rust;
        };

        wireshark = pkgs.wireshark-cli;

        # Wireshark plugin ABI — derived from the actual wireshark package, so
        # we stay in sync when a consuming flake follows a different nixpkgs
        # revision (e.g. scalability's nix-ros-overlay pins an older tshark
        # and a different plugins/<ver>/epan path).
        wiresharkMajorMinor =
          let v = pkgs.lib.versions; in "${v.major wireshark.version}.${v.minor wireshark.version}";

        # .so on Linux, .dylib on macOS (for the Rust cdylib).
        # Wireshark MODULE plugins stay .so on both via cmake defaults.
        dylibExt = pkgs.stdenv.hostPlatform.extensions.sharedLibrary;

        # ---- Rust cdylib ----------------------------------------------------
        # Builds libzenoh_codec_ffi.so. The workspace has git-sourced zenoh-*
        # deps pinned to a specific commit in Cargo.lock; cargoLock.outputHashes
        # keeps the derivation reproducible.
        libzenoh_codec_ffi = rustPlatform.buildRustPackage {
          pname = "libzenoh_codec_ffi";
          version = "1.9.0";
          src = pkgs.lib.cleanSource ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
            # Hashes for git dependencies. First build will fail with the
            # expected hash; paste it in and the build is reproducible from
            # then on.
            outputHashes = {
              "zenoh-buffers-1.9.0" = "sha256-Wixnu6CgcH2+hSCK55cBJuR87NoyC975QrvEkSLq7bo=";
            };
          };

          # Only build the cdylib crate; skip tests which need live network
          cargoBuildFlags = [ "-p" "zenoh-codec-ffi" ];
          doCheck = false;

          # Expose the .so as the primary artifact
          postInstall = ''
            mkdir -p $out/lib
            cp target/*/release/libzenoh_codec_ffi${dylibExt} $out/lib/ \
              || cp target/*/debug/libzenoh_codec_ffi${dylibExt} $out/lib/
          '';

          meta.description = "Rust cdylib that decodes zenoh protocol messages into tshark field spans";
        };

        # ---- C plugin (packet-zenoh.so) -------------------------------------
        packet-zenoh = pkgs.stdenv.mkDerivation {
          pname = "packet-zenoh";
          version = "1.9.0";
          src = pkgs.lib.cleanSource ./.;

          nativeBuildInputs = with pkgs; [ cmake pkg-config ];
          buildInputs = [ wireshark pkgs.glib ];

          # Point cmake at the Rust cdylib produced above
          cmakeFlags = [
            "-DZENOH_CODEC_FFI_LIB=${libzenoh_codec_ffi}/lib/libzenoh_codec_ffi${dylibExt}"
          ];

          installPhase = ''
            pluginDir=$out/lib/wireshark/plugins/${wiresharkMajorMinor}/epan
            mkdir -p $pluginDir
            # cmake MODULE libraries produce packet-zenoh.so on both Linux and
            # macOS (wireshark's expected plugin extension).
            cp packet-zenoh.so $pluginDir/
            # Co-locate the cdylib so dlopen of the C plugin can find it by SONAME
            cp ${libzenoh_codec_ffi}/lib/libzenoh_codec_ffi${dylibExt} $pluginDir/
          '';

          meta.description = "tshark C plugin for the zenoh protocol";
        };

        # ---- Combined plugin bundle -----------------------------------------
        # `packet-zenoh` above already installs both .so files; expose it as
        # the default package. Downstream flakes consume `packages.default`
        # and set WIRESHARK_PLUGIN_DIR=<pkg>/lib/wireshark/plugins.
        zenoh-dissector = packet-zenoh;
      in
      {
        packages = {
          inherit libzenoh_codec_ffi packet-zenoh;
          default = zenoh-dissector;
        };

        # devShell that puts wireshark + the dissector plugin on PATH and env
        devShells.default = pkgs.mkShell {
          name = "zenoh-dissector-dev";
          buildInputs = [
            wireshark
            rust
            pkgs.cmake
            pkgs.pkg-config
            pkgs.glib
            pkgs.just
            pkgs.clang
            pkgs.mold
          ];
          shellHook = ''
            # Point tshark at the built plugin without touching the system
            # wireshark plugin dir. Re-run `nix build .#packet-zenoh` after
            # source changes to refresh.
            export WIRESHARK_PLUGIN_DIR="${zenoh-dissector}/lib/wireshark/plugins"
            echo "WIRESHARK_PLUGIN_DIR=$WIRESHARK_PLUGIN_DIR"
          '';
        };
      }
    );
}
