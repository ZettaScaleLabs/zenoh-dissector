## Info

- Zenoh Dissector: ${PKG_VER}
- Zenoh Protocol: [${ZENOH_VER}](https://docs.rs/zenoh/${ZENOH_VER}/zenoh/index.html)
- Wireshark Version: ${WIRESHARK_VER}

## Installation

Download and extract the corresponding zip file for your platform. The plugin path uses the Wireshark major.minor version format.

### Linux

For Wireshark ${WIRESHARK_VER}:

```bash
mkdir -p ~/.local/lib/wireshark/plugins/${WIRESHARK_VER}/epan
cp libzenoh_dissector.so ~/.local/lib/wireshark/plugins/${WIRESHARK_VER}/epan/libzenoh_dissector.so
```

### macOS

For Wireshark ${WIRESHARK_VER} (macOS uses dash format):

```bash
WIRESHARK_VER_MACOS=$(echo "${WIRESHARK_VER}" | tr '.' '-')
mkdir -p ~/.local/lib/wireshark/plugins/$WIRESHARK_VER_MACOS/epan
cp libzenoh_dissector.so ~/.local/lib/wireshark/plugins/$WIRESHARK_VER_MACOS/epan/libzenoh_dissector.so
```

### Windows

For Wireshark ${WIRESHARK_VER}:

```powershell
$${empty}wireshark_ver = "${WIRESHARK_VER}"
$${empty}epan_dir = "$${empty}Env:APPDATA\Wireshark\plugins\$${empty}wireshark_ver\epan"
if (-Not (Test-Path $${empty}epan_dir)) {
    mkdir -p $${empty}epan_dir
}
cp zenoh_dissector.dll $${empty}epan_dir
```

## SHA256 Checksums

```txt
$SHA256SUM
```
