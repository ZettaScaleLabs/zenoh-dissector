param(
    [string]$WiresharkVersion = "4.6.0",
    [string]$BuildConfig = "Debug"
)

$ErrorActionPreference = "Stop"

# Parameters
$BaseDir = "C:\wsbuild"
$SrcDir = Join-Path $BaseDir "wireshark-$WiresharkVersion"
$BuildDir = Join-Path $BaseDir "build"

# Create base directory if it doesn't exist
if (-not (Test-Path $BaseDir)) {
    New-Item -ItemType Directory -Path $BaseDir -Force | Out-Null
}

# Install required tools if not present (excluding msbuild as it comes with Visual Studio)
$tools = @("cmake", "nuget.commandline", "strawberryperl", "python3", "7zip")
foreach ($tool in $tools) {
    if (-not (choco list -l | Select-String "^$tool")) {
        choco install $tool -y --no-progress
    }
}

# Download Wireshark source if not exists
if (-not (Test-Path (Join-Path $SrcDir "CMakeLists.txt"))) {
    Write-Host "Downloading Wireshark $WiresharkVersion source..."
    $archivePath = Join-Path $BaseDir "wireshark-$WiresharkVersion.tar.xz"

    if (-not (Test-Path $archivePath)) {
        Invoke-WebRequest -Uri "https://1.eu.dl.wireshark.org/src/all-versions/wireshark-$WiresharkVersion.tar.xz" -OutFile $archivePath
    }

    # Extract .xz to .tar
    Write-Host "Extracting .xz archive..."
    $tarPath = Join-Path $BaseDir "wireshark-$WiresharkVersion.tar"
    & 7z.exe x $archivePath "-o$BaseDir" -y | Out-Null

    # Extract .tar to source directory
    Write-Host "Extracting .tar archive..."
    & 7z.exe x $tarPath "-o$BaseDir" -y | Out-Null

    # Clean up intermediate .tar file
    Remove-Item $tarPath -ErrorAction SilentlyContinue

    # Apply patch to Wireshark to correct docbook URL
    Write-Host "Patching DocBook location..."
    $PatchFile = Join-Path $PSScriptRoot "docbook-url-fix.patch"
    if (-not (Test-Path $PatchFile)) {
        Write-Error "DocBook patch file not found at $PatchFile"
        exit 1
    }

    Push-Location $SrcDir

    $FetchArtifactsFile = Join-Path $SrcDir "cmake/modules/FetchArtifacts.cmake"
    $OldDocbookUrl = "https://docbook.org/xml/5.0.1/docbook-5.0.1.zip"
    $NewDocbookUrl = "https://archive.docbook.org/xml/5.0.1/docbook-5.0.1.zip"
    $docbookHandled = $false

    if (Test-Path $FetchArtifactsFile) {
        $fetchArtifactsContent = Get-Content -Raw $FetchArtifactsFile
        if ($fetchArtifactsContent.Contains($NewDocbookUrl)) {
            Write-Host "DocBook URL already updated in Wireshark $WiresharkVersion, skipping patch."
            $docbookHandled = $true
        }
        elseif ($fetchArtifactsContent.Contains($OldDocbookUrl)) {
            if ($updatedContent -ne $fetchArtifactsContent) {
                [System.IO.File]::WriteAllText($FetchArtifactsFile, $updatedContent, (New-Object System.Text.UTF8Encoding $false))
                Write-Host "Updated DocBook URL in FetchArtifacts.cmake directly."
                $docbookHandled = $true
            }
        }
    }

    if (-not $docbookHandled) {
        # Apply the patch if not already included in this Wireshark version.
        # Use SilentlyContinue locally so non-zero exit from git apply --check
        # doesn't trigger the global Stop preference before we inspect $LASTEXITCODE.
        if (Get-Command git -ErrorAction SilentlyContinue) {
            $prev = $ErrorActionPreference
            $ErrorActionPreference = 'SilentlyContinue'
            git apply --check "$PatchFile" 2>$null
            $checkExit = $LASTEXITCODE
            $ErrorActionPreference = $prev

            if ($checkExit -eq 0) {
                git apply "$PatchFile"
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "Applying the DocBook URL patch failed."
                    exit 1
                }
            }
            else {
                # Check if already applied (patch already included in this version)
                $prev = $ErrorActionPreference
                $ErrorActionPreference = 'SilentlyContinue'
                git apply --check -R "$PatchFile" 2>$null
                $reverseExit = $LASTEXITCODE
                $ErrorActionPreference = $prev

                if ($reverseExit -eq 0) {
                    Write-Host "DocBook URL patch already included in Wireshark $WiresharkVersion, skipping."
                }
                else {
                    Write-Error "Applying the DocBook URL patch failed (patch does not apply forward or reverse)."
                    exit 1
                }
            }
        }
        else {
            & patch -p1 --forward -i "$PatchFile"
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
                Write-Error "Applying the DocBook URL patch failed."
                exit 1
            }
        }
    }
    Pop-Location
}

# Create build directory
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

# Set environment variable for Wireshark base directory
$env:WIRESHARK_BASE_DIR = $BaseDir

# Configure with CMake
Push-Location $BuildDir
cmake $SrcDir `
    -G "Visual Studio 17 2022" `
    -A x64 `
    -DBUILD_wireshark=OFF `
    -DBUILD_tshark=OFF `
    -DBUILD_wireshark_cli=OFF `
    -DENABLE_KERBEROS=OFF `
    -DENABLE_SPANDSP=OFF `
    -DENABLE_BCG729=OFF `
    -DENABLE_AMRNB=OFF `
    -DENABLE_ILBC=OFF `
    -DCMAKE_INSTALL_PREFIX="$BuildDir\install"

# Build all with the specified config
Write-Host "Building Wireshark with config: $BuildConfig"
cmake --build . --config $BuildConfig --target ALL_BUILD

Pop-Location

Write-Host "Wireshark build completed in $BuildDir"

# At the end of build.ps1, verify libraries were created
$DebugDir = Join-Path $BuildDir "run\$BuildConfig"
if (Test-Path $DebugDir) {
    Write-Host "Build output directory exists: $DebugDir"
    Get-ChildItem $DebugDir -Filter "*.lib" | ForEach-Object { Write-Host "  Found: $($_.Name)" }
}
else {
    Write-Host "ERROR: Build output directory not found at $DebugDir"
    Write-Host "Contents of $($BuildDir):"
    Get-ChildItem $BuildDir | ForEach-Object { Write-Host "  $_" }
    exit 1
}

Write-Host "Wireshark build completed"
