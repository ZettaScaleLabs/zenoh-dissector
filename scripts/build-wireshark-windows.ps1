# Obtain Wireshark headers and import libraries on Windows for compiling
# packet-zenoh.dll.
#
# Strategy:
#   1. Install Wireshark via choco - provides tshark + wireshark.lib et al.
#      under C:\Program Files\Wireshark\.
#   2. Download the matching source tarball - provides the header tree
#      (epan/, wsutil/, ws_version.h, ...) without a full cmake build.
#
# CMakeLists.txt finds:
#   Headers  : C:\wsbuild\wireshark-<Ver>\   (source tree)
#   Libraries: C:\Program Files\Wireshark\  (installed)
#
param(
    [string]$WiresharkVersion = "4.6.0",
    [string]$BuildConfig = "Release"   # kept for API compat; unused
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Step 1: install Wireshark application (includes wireshark.lib, wiretap.lib,
# wsutil.lib under C:\Program Files\Wireshark\)
# ---------------------------------------------------------------------------
Write-Host "Installing Wireshark $WiresharkVersion via choco..."
choco install wireshark --version $WiresharkVersion -y --no-progress 2>&1
if ($LASTEXITCODE -ne 0) {
    # Fall back to latest available version
    Write-Host "Pinned version not in choco cache - installing latest..."
    choco install wireshark -y --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Error "choco install wireshark failed (exit $LASTEXITCODE)"
        exit 1
    }
}

# Refresh PATH so tshark is discoverable in later steps
$_machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
$_user    = [System.Environment]::GetEnvironmentVariable("Path", "User")
$env:Path = "$_machine;$_user"

Write-Host "Verifying Wireshark installation..."
Get-Command tshark -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  tshark: $($_.Source)" }

$WsInstallDir = "C:\Program Files\Wireshark"
if (-not (Test-Path $WsInstallDir)) {
    Write-Error "Wireshark install directory not found at $WsInstallDir"
    exit 1
}
Write-Host "Wireshark installed at $WsInstallDir"
Get-ChildItem $WsInstallDir -Filter "*.lib" | ForEach-Object { Write-Host "  $($_.Name)" }

# ---------------------------------------------------------------------------
# Step 2: download source tarball for headers only (no cmake build needed)
# ---------------------------------------------------------------------------
$BaseDir = "C:\wsbuild"
$SrcDir  = Join-Path $BaseDir "wireshark-$WiresharkVersion"

if (-not (Test-Path $BaseDir)) {
    New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
}

if (-not (Test-Path (Join-Path $SrcDir "CMakeLists.txt"))) {
    Write-Host "Downloading Wireshark $WiresharkVersion source for headers..."

    $tools = @("7zip")
    foreach ($tool in $tools) {
        if (-not (choco list -l | Select-String "^$tool")) {
            choco install $tool -y --no-progress
        }
    }
    $_machine = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $_user    = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$_machine;$_user"

    $archivePath = Join-Path $BaseDir "wireshark-$WiresharkVersion.tar.xz"
    if (-not (Test-Path $archivePath)) {
        Invoke-WebRequest `
            -Uri "https://1.eu.dl.wireshark.org/src/all-versions/wireshark-$WiresharkVersion.tar.xz" `
            -OutFile $archivePath
    }

    Write-Host "Extracting source..."
    $tarPath = Join-Path $BaseDir "wireshark-$WiresharkVersion.tar"
    & 7z.exe x $archivePath "-o$BaseDir" -y | Out-Null
    & 7z.exe x $tarPath     "-o$BaseDir" -y | Out-Null
    Remove-Item $tarPath -ErrorAction SilentlyContinue
}

if (-not (Test-Path (Join-Path $SrcDir "epan\proto.h"))) {
    Write-Error "Wireshark source headers not found at $SrcDir\epan\proto.h"
    exit 1
}
Write-Host "Wireshark headers available at $SrcDir"

# ---------------------------------------------------------------------------
# Step 3: generate import libraries (.lib) from installed DLLs using MSVC tools.
# The choco Wireshark package is a runtime install with no .lib files.
# ---------------------------------------------------------------------------
Write-Host "Generating import libraries from installed DLLs..."

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vsWhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>&1 | Select-Object -First 1
$vcVer = (Get-Content (Join-Path $vsInstall "VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt")).Trim()
$vcBin = Join-Path $vsInstall "VC\Tools\MSVC\$vcVer\bin\Hostx64\x64"
$dumpbinExe = Join-Path $vcBin "dumpbin.exe"
$libExe     = Join-Path $vcBin "lib.exe"

foreach ($entry in @(@("wireshark", "libwireshark"), @("wsutil", "libwsutil"))) {
    $libName = $entry[0]   # canonical name cmake searches for (wireshark, wsutil)
    $dllBase = $entry[1]   # actual DLL basename on Windows (libwireshark, libwsutil)

    $dllPath = Join-Path $WsInstallDir "$dllBase.dll"
    if (-not (Test-Path $dllPath)) {
        Write-Host "  $dllBase.dll not found, skipping"
        continue
    }
    $defPath = Join-Path $WsInstallDir "$libName.def"
    $libPath = Join-Path $WsInstallDir "$libName.lib"

    $exports = (& $dumpbinExe /EXPORTS $dllPath) -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)' | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)') { $Matches[1] }
    }
    "LIBRARY $dllBase`r`nEXPORTS" | Out-File $defPath -Encoding ASCII
    $exports | Out-File $defPath -Encoding ASCII -Append

    & $libExe /DEF:$defPath /OUT:$libPath /MACHINE:X64 /NOLOGO
    if (Test-Path $libPath) {
        Write-Host "  Generated $libPath from $dllBase.dll ($($exports.Count) exports)"
    } else {
        Write-Error "Failed to generate $libPath"
    }
}

# ---------------------------------------------------------------------------
# Step 4: install GLib headers and generate glib-2.0.lib for MSVC linking.
# MSYS2 (pre-installed on windows-2022) provides GLib binaries and headers.
# We generate a MSVC-format import library from the MinGW GLib DLL.
# ---------------------------------------------------------------------------
Write-Host "Installing GLib dev headers via MSYS2 pacman..."
$pacman = "C:\msys64\usr\bin\pacman.exe"
if (Test-Path $pacman) {
    & $pacman -S --noconfirm --needed mingw-w64-x86_64-glib2 mingw-w64-x86_64-pkgconf 2>&1 | ForEach-Object { Write-Host "  $_" }
    Write-Host "GLib installed via MSYS2."
} else {
    Write-Error "MSYS2 not found at C:\msys64 - cannot install GLib headers"
    exit 1
}

# Generate glib-2.0.lib (MSVC import lib) from MSYS2's GLib DLL.
# MSVC linker cannot use MinGW .dll.a files; generate a .lib from the DLL exports.
$glibDll = "C:\msys64\mingw64\bin\libglib-2.0-0.dll"
$glibLib = Join-Path $WsInstallDir "glib-2.0.lib"
# Persist Wireshark install dir to GitHub Actions PATH so tshark is available in bash steps.
if ($env:GITHUB_PATH) {
    "C:\Program Files\Wireshark" | Out-File -FilePath $env:GITHUB_PATH -Encoding utf8 -Append
    Write-Host "Added Wireshark to GITHUB_PATH for subsequent steps."
}

if (Test-Path $glibDll) {
    $glibDef = Join-Path $WsInstallDir "glib-2.0.def"
    $glibExports = (& $dumpbinExe /EXPORTS $glibDll) -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)' | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)') { $Matches[1] }
    }
    # lib.exe only auto-appends .dll when the name has no dots; glib-2.0-0 has dots so we
    # must write the full filename explicitly to get the correct PE import table entry.
    "LIBRARY glib-2.0-0.dll`r`nEXPORTS" | Out-File $glibDef -Encoding ASCII
    $glibExports | Out-File $glibDef -Encoding ASCII -Append
    & $libExe /DEF:$glibDef /OUT:$glibLib /MACHINE:X64 /NOLOGO
    if (Test-Path $glibLib) {
        Write-Host "  Generated $glibLib from MSYS2 GLib DLL ($($glibExports.Count) exports)"
    } else {
        Write-Warning "Failed to generate $glibLib -- GLib symbols will be unresolved at link time"
    }
} else {
    Write-Warning "MSYS2 GLib DLL not found at $glibDll -- skipping glib-2.0.lib generation"
}
