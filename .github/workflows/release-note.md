## Info

- Zenoh Dissector: ${PKG_VER}
- Zenoh Protocol: [${ZENOH_VER}](https://docs.rs/zenoh/${ZENOH_VER}/zenoh/index.html)
- Wireshark Version: ${WIRESHARK_VER}

## Installation

Download and extract the zip file for your platform. It holds two files that work together: the Wireshark plugin `packet-zenoh` and the codec library `zenoh_codec_ffi`. Put both in the Wireshark plugin directory. The directory name uses the major and minor Wireshark version, `${WIRESHARK_MM}`. The plugin only loads in that Wireshark version.

### Linux

```bash
mkdir -p ~/.local/lib/wireshark/plugins/${WIRESHARK_MM}/epan
cp packet-zenoh.so libzenoh_codec_ffi.so ~/.local/lib/wireshark/plugins/${WIRESHARK_MM}/epan/
```

### macOS

macOS uses a dash in the directory name. Ask tshark for the directory:

```bash
PLUGIN_DIR=$(tshark -G folders | awk -F'\t' '/Personal Plugins/{print $NF}')/epan
mkdir -p "$PLUGIN_DIR"
cp packet-zenoh.so libzenoh_codec_ffi.dylib "$PLUGIN_DIR/"
```

### Windows

Windows does not search the plugin directory for the plugin's own libraries. Copy `zenoh_codec_ffi.dll` to the plugin directory and also next to `tshark.exe`:

```powershell
$epan_dir = "$Env:APPDATA\Wireshark\plugins\${WIRESHARK_MM}\epan"
New-Item -ItemType Directory -Force -Path $epan_dir | Out-Null
Copy-Item packet-zenoh.dll, zenoh_codec_ffi.dll $epan_dir
Copy-Item zenoh_codec_ffi.dll "C:\Program Files\Wireshark\"
```

## SHA256 Checksums

```txt
${SHA256SUM}
```
