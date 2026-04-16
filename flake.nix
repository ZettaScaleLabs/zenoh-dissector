{
  description = "zenoh-dissector devShell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable?shallow=1";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgsDefault = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        # nixpkgs nixos-unstable ships wireshark 4.6.x; reuse it directly
        # rather than building from source via an overlay.
        pkgsWireshark46 = pkgsDefault;

        commonPkgs = with pkgsDefault; [
          openssl
          pkg-config
          eza
          fd
          libpcap
          cargo-machete
          cargo-expand
          glib
          lldb
          lld
          sccache
        ];

        basePkgsDefault = [ pkgsDefault.wireshark ] ++ commonPkgs;
        basePkgsWireshark46 = [ pkgsWireshark46.wireshark ] ++ commonPkgs;

        commonShellHook = ''
          export PKG_CONFIG_PATH="${pkgsDefault.openssl.dev}/lib/pkgconfig"
          export LIBCLANG_PATH="${pkgsDefault.llvmPackages.libclang.lib}/lib"
          export RUST_SRC_PATH=${pkgsDefault.rustPlatform.rustLibSrc}

          mkdir -p $HOME/.cargo
          cat > $HOME/.cargo/config.toml <<EOF
          [build]
          rustc-wrapper = "sccache"
          jobs = 4
          EOF
        '';

        LD_LIBRARY_PATH =
          with pkgsDefault;
          lib.makeLibraryPath [
            openssl
            libpcap
            stdenv.cc.cc.lib
          ];

        mkRustShell =
          pkgs: basePkgs: version: shellName:
          pkgs.mkShell {
            name = shellName;
            buildInputs =
              basePkgs
              ++ [ pkgsDefault.rust-bin.stable.${version}.default ];
            inherit LD_LIBRARY_PATH;
            shellHook = commonShellHook;
          };

        # Test that verifies the dissector works with tshark
        dissectorTest = pkgs:
          pkgs.rustPlatform.buildRustPackage {
            pname = "zenoh-dissector-test";
            version = "1.6.1";
            src = ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            buildInputs = with pkgs; [
              wireshark
              openssl
              libpcap
              glib
            ];

            LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
            PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";

            # Override the check phase to test with tshark
            checkPhase = ''
              runHook preCheck

              # Get Wireshark version (e.g., 4.4.0 -> 4.4)
              WIRESHARK_VERSION=$(${pkgs.wireshark}/bin/tshark --version | head -n1 | grep -oP '\d+\.\d+' | head -n1)

              # Create plugin directory in the build environment
              PLUGIN_DIR="$TMPDIR/wireshark-plugins/$WIRESHARK_VERSION/epan"
              mkdir -p "$PLUGIN_DIR"

              # Find and link the built plugin
              PLUGIN_SO=$(find target -name "libzenoh_dissector.so" | head -n1)
              ln -sf $PWD/$PLUGIN_SO "$PLUGIN_DIR/libzenoh_dissector.so"

              # Set HOME to use our plugin directory
              export HOME=$TMPDIR

              # Run tshark and verify Zenoh packets are detected
              ZENOH_COUNT=$(${pkgs.wireshark}/bin/tshark -r assets/sample-data.pcap 2>/dev/null | grep -c Zenoh || true)

              if [ "$ZENOH_COUNT" -eq 7 ]; then
                echo "✓ Test passed: Found 7 Zenoh packets"
              else
                echo "✗ Test failed: Expected 7 Zenoh packets, found $ZENOH_COUNT"
                exit 1
              fi

              runHook postCheck
            '';

            doCheck = true;
          };

      in {
        devShells = {
          # Rust 1.85.0 with default Wireshark 4.4
          default = mkRustShell pkgsDefault basePkgsDefault "1.85.0" "ws44";

          # Rust 1.85.0 with Wireshark 4.6 overlay
          wireshark46 = mkRustShell pkgsWireshark46 basePkgsWireshark46 "1.85.0" "ws46";
        };

        checks = {
          # Test with default Wireshark version
          default = dissectorTest pkgsDefault;

          # Test with Wireshark 4.6
          wireshark46 = dissectorTest pkgsWireshark46;
        };
      }
    );
}
