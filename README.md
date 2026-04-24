![zenoh dissector banner](./assets/zenoh-dissector.svg)

# Zenoh Dissector

[Zenoh](http://zenoh.io/) protocol dissector for Wireshark.

> [!WARNING]
> For Zenoh protocol versions older than 0.10.0, use the [Lua plugin](https://github.com/eclipse-zenoh/zenoh-dissector/tree/v0.7.2-rc).
>
> The plugin currently requires Wireshark 4.6.

The dissector is split into two components:

- **`zenoh_codec_ffi`** — Rust cdylib with no Wireshark dependency. Contains all decoding logic.
- **`packet-zenoh`** — Standard C Wireshark plugin. Handles field registration, TCP reassembly, and tree building by calling into the Rust cdylib.

Both files must be present in the Wireshark plugin directory.

## Prerequisites

- [Rust toolchain](https://rustup.rs) (for building `zenoh_codec_ffi`)
- CMake 3.15+ (for building `packet-zenoh`)
- Wireshark 4.6 with development headers

### Install Wireshark + headers

- **Linux (Ubuntu)**

    ```bash
    sudo apt install -y software-properties-common
    sudo add-apt-repository -y ppa:wireshark-dev/stable
    sudo apt install -y libwireshark-dev wireshark tshark cmake
    ```

- **macOS**

    ```bash
    brew install wireshark cmake
    ```

- **Windows**

    Install Wireshark via [Chocolatey](https://docs.chocolatey.org/en-us/choco/setup):

    ```powershell
    choco install wireshark -y
    ```

    Then run the helper script to download headers and generate import libraries:

    ```powershell
    .\scripts\build-wireshark-windows.ps1 -WiresharkVersion 4.6.4
    ```

## Using with Nix

No need to install Wireshark headers, Rust, or CMake — the flake has everything. Works on Linux and macOS.

**Easiest way** — one command gives you a shell where `tshark` already knows about the plugin:

```bash
nix develop github:eclipse-zenoh/zenoh-dissector
tshark -r capture.pcap      # decode Zenoh traffic
```

**Use with your own Wireshark** — build the plugin, then tell Wireshark where it is:

```bash
nix build github:eclipse-zenoh/zenoh-dissector
export WIRESHARK_PLUGIN_DIR="$PWD/result/lib/wireshark/plugins"
wireshark                   # or: tshark -r capture.pcap
```

That's it. The `WIRESHARK_PLUGIN_DIR` variable only lives in your current shell, so nothing is installed system-wide.

## Build from source

```bash
just build          # build everything (debug)
just build-release  # build everything (release)
just build-codec    # Rust cdylib only
just build-plugin   # C plugin only (cmake already configured)
just install        # build + install to Wireshark plugin dir (Linux/macOS)
just test           # unit + integration tests
just check          # fmt + clippy
just clean          # remove all build artifacts
```

Or step by step:

```bash
cargo build -p zenoh-codec-ffi -j4   # Rust cdylib
cmake -B _tmp/cmake-build -S .        # C plugin configure
cmake --build _tmp/cmake-build -j4   # C plugin build
```

**When to rebuild each component:**

| Changed | Rebuild needed |
| --- | --- |
| Decoding logic, field definitions, span recording | `just build-codec` |
| Wireshark API interactions (reassembly, tree building, heuristics) | `just build-plugin` |
| Wireshark version upgrade | `just build` — cmake reconfigures against new headers |
| Added or renamed a field exposed via the FFI (`CFieldDef`) | `just build` — C ABI changed |

## Install

On Linux and macOS:

```bash
just install
```

This builds both components and copies them to the Wireshark personal plugin directory automatically.

On Windows, or to install manually:

- **Linux**

    ```bash
    PLUGIN_DIR=~/.local/lib/wireshark/plugins/4.6/epan
    mkdir -p "$PLUGIN_DIR"
    cp _tmp/cmake-build/packet-zenoh.so "$PLUGIN_DIR/"
    cp target/debug/libzenoh_codec_ffi.so "$PLUGIN_DIR/"
    ```

- **macOS**

    ```bash
    PLUGIN_DIR=$(tshark -G folders | awk -F'\t' '/Personal Plugins/{print $NF}')/epan
    mkdir -p "$PLUGIN_DIR"
    cp _tmp/cmake-build/packet-zenoh.so "$PLUGIN_DIR/"
    cp target/debug/libzenoh_codec_ffi.dylib "$PLUGIN_DIR/"
    ```

- **Windows**

    ```powershell
    $plugin_dir = "$Env:APPDATA\Wireshark\plugins\4.6\epan"
    New-Item -ItemType Directory -Force -Path $plugin_dir | Out-Null
    Copy-Item _tmp\cmake-build\Release\packet-zenoh.dll $plugin_dir
    Copy-Item target\debug\zenoh_codec_ffi.dll $plugin_dir
    # Also place the FFI DLL next to tshark.exe so LoadLibrary can find it
    Copy-Item target\debug\zenoh_codec_ffi.dll "C:\Program Files\Wireshark\"
    ```

## Usage

### Sample data

```bash
tshark -r ./assets/sample-data.pcap
```

```text
1 0.000000000    127.0.0.1 → 127.0.0.1    TCP 74 60698 → 7447 [SYN] ...
4 0.000342409    127.0.0.1 → 127.0.0.1    Zenoh 88
6 0.000488613    127.0.0.1 → 127.0.0.1    Zenoh 138
8 0.000602256    127.0.0.1 → 127.0.0.1    Zenoh 124
...
```

### Pub/Sub example

![demo-pubsub](./assets/demo-pubsub.png)

### Heuristic dissector

By default the dissector only decodes traffic on port 7447. To decode Zenoh on any port, enable the heuristic dissectors via `Analyze > Enabled Protocols > Zenoh`:

- `zenoh_tcp_heur` — Zenoh over TCP
- `zenoh_udp_heur` — Zenoh over UDP

> [!IMPORTANT]
> When enabled, the dissector attempts to decode all TCP/UDP traffic as Zenoh. This may be performance-intensive and can misidentify non-Zenoh packets.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
