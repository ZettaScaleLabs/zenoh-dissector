# Obtain Wireshark headers and import libraries on Windows for compiling
# packet-zenoh.dll.
#
# Strategy:
#   1. Install Wireshark via choco — provides tshark + wireshark.lib et al.
#      under C:\Program Files\Wireshark\.
#   2. Download the matching source tarball — provides the header tree
#      (epan/, wsutil/, ws_version.h, …) without a full cmake build.
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
    Write-Host "Pinned version not in choco cache — installing latest..."
    choco install wireshark -y --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Error "choco install wireshark failed (exit $LASTEXITCODE)"
        exit 1
    }
}

# Refresh PATH so tshark is discoverable in later steps
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host "Verifying Wireshark installation..."
& where.exe tshark 2>$null | ForEach-Object { Write-Host "  tshark: $_" }

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
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")

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
