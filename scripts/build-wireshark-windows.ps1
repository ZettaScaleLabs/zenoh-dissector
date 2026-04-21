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

Write-Host "DLLs in $WsInstallDir matching wireshark|wsutil:"
Get-ChildItem $WsInstallDir -Filter "*.dll" | Where-Object { $_.Name -match "wireshark|wsutil" } | ForEach-Object { Write-Host "  $($_.Name)" }
Write-Host "All DLLs in $WsInstallDir (first 30):"
Get-ChildItem $WsInstallDir -Filter "*.dll" | Select-Object -First 30 | ForEach-Object { Write-Host "  $($_.Name)" }

$vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstall = & $vsWhere -latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>&1 | Select-Object -First 1
$vcVer = (Get-Content (Join-Path $vsInstall "VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt")).Trim()
$vcBin = Join-Path $vsInstall "VC\Tools\MSVC\$vcVer\bin\Hostx64\x64"
$dumpbinExe = Join-Path $vcBin "dumpbin.exe"
$libExe     = Join-Path $vcBin "lib.exe"

foreach ($dllName in @("wireshark", "wsutil")) {
    # Try exact name first, then versioned variants (e.g. wireshark4.dll)
    $dllPath = Join-Path $WsInstallDir "$dllName.dll"
    if (-not (Test-Path $dllPath)) {
        # Look for any DLL whose name starts with $dllName (e.g. wireshark4.dll)
        $candidates = Get-ChildItem $WsInstallDir -Filter "${dllName}*.dll" | Select-Object -First 1
        if ($candidates) {
            $dllPath = $candidates.FullName
            Write-Host "  Using versioned DLL: $($candidates.Name)"
        } else {
            Write-Host "  $dllName.dll not found, skipping"
            continue
        }
    }
    $defPath = Join-Path $WsInstallDir "$dllName.def"
    $libPath = Join-Path $WsInstallDir "$dllName.lib"

    $exports = (& $dumpbinExe /EXPORTS $dllPath) -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)' | ForEach-Object {
        if ($_ -match '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)') { $Matches[1] }
    }
    "LIBRARY $dllName`r`nEXPORTS" | Out-File $defPath -Encoding ASCII
    $exports | Out-File $defPath -Encoding ASCII -Append

    & $libExe /DEF:$defPath /OUT:$libPath /MACHINE:X64 /NOLOGO
    if (Test-Path $libPath) {
        Write-Host "  Generated $libPath ($($exports.Count) exports)"
    } else {
        Write-Error "Failed to generate $libPath"
    }
}
