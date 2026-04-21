#
# Copyright (c) 2026 ZettaScale Technology
#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
# which is available at https://www.apache.org/licenses/LICENSE-2.0.
#
# SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
#
# Contributors:
#   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
#
# Build Wireshark from source on Windows to obtain the headers and import
# libraries needed to compile packet-zenoh.dll.
#
# Outputs (for use by CMake via -DWIRESHARK_LIB_DIR / find_path/find_library):
#   C:\wsbuild\build\run\<Config>\  — wireshark.lib, wiretap.lib, wsutil.lib
#   C:\wsbuild\wireshark-<Ver>\     — header tree (epan/, wsutil/, ws_version.h …)
#
param(
    [string]$WiresharkVersion = "4.6.0",
    [string]$BuildConfig = "Release"
)

$ErrorActionPreference = "Stop"

$BaseDir = "C:\wsbuild"
$SrcDir  = Join-Path $BaseDir "wireshark-$WiresharkVersion"
$BuildDir = Join-Path $BaseDir "build"

if (-not (Test-Path $BaseDir)) {
    New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
}

# Install build tools
$tools = @("cmake", "nuget.commandline", "strawberryperl", "python3", "7zip")
foreach ($tool in $tools) {
    if (-not (choco list -l | Select-String "^$tool")) {
        choco install $tool -y --no-progress
    }
}

# Refresh PATH so freshly installed tools (perl, cmake, python) are findable
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
            [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host "Diagnostics after PATH refresh:"
& where.exe perl   2>$null | ForEach-Object { Write-Host "  perl:   $_" }
& where.exe cmake  2>$null | ForEach-Object { Write-Host "  cmake:  $_" }
& where.exe python 2>$null | ForEach-Object { Write-Host "  python: $_" }
& where.exe 7z     2>$null | ForEach-Object { Write-Host "  7z:     $_" }

# Download and extract Wireshark source
if (-not (Test-Path (Join-Path $SrcDir "CMakeLists.txt"))) {
    Write-Host "Downloading Wireshark $WiresharkVersion source..."
    $archivePath = Join-Path $BaseDir "wireshark-$WiresharkVersion.tar.xz"

    if (-not (Test-Path $archivePath)) {
        Invoke-WebRequest `
            -Uri "https://1.eu.dl.wireshark.org/src/all-versions/wireshark-$WiresharkVersion.tar.xz" `
            -OutFile $archivePath
    }

    Write-Host "Extracting..."
    $tarPath = Join-Path $BaseDir "wireshark-$WiresharkVersion.tar"
    & 7z.exe x $archivePath "-o$BaseDir" -y | Out-Null
    & 7z.exe x $tarPath     "-o$BaseDir" -y | Out-Null
    Remove-Item $tarPath -ErrorAction SilentlyContinue

    # Apply DocBook URL patch (required for some WS versions to configure cleanly)
    $PatchUrl  = "https://gitlab.com/wireshark/wireshark/-/commit/2be6899941c73a4406a459b6677d0aa0929477a0.patch"
    $PatchFile = Join-Path $PWD "docbook-url-fix.patch"
    Invoke-WebRequest -Uri $PatchUrl -OutFile $PatchFile -UseBasicParsing
    Push-Location $SrcDir
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    git apply --check "$PatchFile" 2>$null
    $checkExit = $LASTEXITCODE
    $ErrorActionPreference = $prev
    if ($checkExit -eq 0) {
        git apply "$PatchFile"
    }
    Pop-Location
}

if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

$env:WIRESHARK_BASE_DIR = $BaseDir

# Configure: disable all executables, only build the libraries we link against
Push-Location $BuildDir
cmake $SrcDir `
    -G "Visual Studio 17 2022" -A x64 `
    -DBUILD_wireshark=OFF `
    -DBUILD_tshark=OFF `
    -DBUILD_wireshark_cli=OFF `
    -DENABLE_KERBEROS=OFF `
    -DENABLE_SPANDSP=OFF `
    -DENABLE_BCG729=OFF `
    -DENABLE_AMRNB=OFF `
    -DENABLE_ILBC=OFF `
    -DCMAKE_INSTALL_PREFIX="$BuildDir\install"
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "cmake configure failed (exit $LASTEXITCODE)"
    exit 1
}

cmake --build . --config $BuildConfig --target epan wiretap wsutil
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Write-Error "cmake build failed (exit $LASTEXITCODE)"
    exit 1
}
Pop-Location

$OutDir = Join-Path $BuildDir "run\$BuildConfig"
if (-not (Test-Path $OutDir)) {
    Write-Error "Build output not found at $OutDir - cmake succeeded but produced no output in expected location"
    exit 1
}
Write-Host "Wireshark libraries built at $OutDir"
Get-ChildItem $OutDir -Filter "*.lib" | ForEach-Object { Write-Host "  $($_.Name)" }
