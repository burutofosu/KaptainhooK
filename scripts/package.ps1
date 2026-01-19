param(
    [string]$TargetDir = "",
    [string]$PackageDir = ""
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($TargetDir)) {
    $TargetDir = Join-Path $Root "target\release"
}
if ([string]::IsNullOrWhiteSpace($PackageDir)) {
    $PackageDir = Join-Path $Root "package"
}

if (-not (Test-Path $TargetDir)) {
    Write-Error "Target directory not found: $TargetDir"
    exit 1
}

$exeFiles = Get-ChildItem -Path $TargetDir -Filter "kh-*.exe" -File -ErrorAction SilentlyContinue
if (-not $exeFiles) {
    Write-Error "No kh-*.exe found in $TargetDir. Build release first."
    exit 1
}

$PackageRoot = Join-Path $PackageDir "KaptainhooK"
$BinDir = Join-Path $PackageRoot "bin"

New-Item -ItemType Directory -Path $PackageDir -Force | Out-Null
if (Test-Path $PackageRoot) {
    Remove-Item $PackageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $BinDir -Force | Out-Null

Copy-Item -Path $exeFiles.FullName -Destination $BinDir -Force

$readmeSrc = Join-Path $Root "README.md"
if (Test-Path $readmeSrc) {
    Copy-Item -Path $readmeSrc -Destination (Join-Path $PackageRoot "README.md") -Force
} else {
    Write-Warning "README.md not found: $readmeSrc"
}

$setupExe = Join-Path $BinDir "kh-setup.exe"
$shortcutPath = Join-Path $PackageRoot "KaptainhooK Setup.lnk"
if (Test-Path $setupExe) {
    try {
        if ($env:OS -eq "Windows_NT") {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = $setupExe
            $shortcut.WorkingDirectory = $BinDir
            $shortcut.IconLocation = $setupExe
            $shortcut.WindowStyle = 1
            $shortcut.Save()
        } else {
            Write-Warning "Shortcut creation skipped: not running on Windows."
        }
    } catch {
        Write-Warning "Failed to create shortcut: $shortcutPath"
    }
} else {
    Write-Warning "kh-setup.exe not found in $BinDir; shortcut not created."
}

$assetsSrc = Join-Path $Root "assets"
if (Test-Path $assetsSrc) {
    $assetsDst = Join-Path $BinDir "assets"
    if (Test-Path $assetsDst) {
        Remove-Item $assetsDst -Recurse -Force
    }
    Copy-Item -Path $assetsSrc -Destination $assetsDst -Recurse -Force
} else {
    Write-Warning "Assets folder not found: $assetsSrc"
}

Write-Host "Package ready: $PackageRoot"
