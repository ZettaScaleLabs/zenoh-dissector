```
Zenoh Dissector: ${PKG_VER}
Zenoh Protocol: ${ZENOH_VER}
```

## Installation

Download and extract the corresponding zip file

### Linux

```bash
mkdir -p ~/.local/lib/wireshark/plugins/4.0/epan
cp libzenoh_dissector.so ~/.local/lib/wireshark/plugins/4.0/epan/libzenoh_dissector.so
```

### macOS

```bash
mkdir -p ~/.local/lib/wireshark/plugins/4-0/epan
cp libzenoh_dissector.so ~/.local/lib/wireshark/plugins/4-0/epan/libzenoh_dissector.so
```

### Windows

```powershell
$${empty}epan_dir = "$${empty}Env:APPDATA\Wireshark\plugins\4.0\epan"
if (-Not (Test-Path $${empty}epan_dir)) {
    mkdir -p $${empty}epan_dir
}
cp zenoh_dissector.dll $${empty}epan_dir
```
