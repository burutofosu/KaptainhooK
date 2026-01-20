param(
  [ValidateSet("debug", "release")]
  [string]$Profile = "debug",
  [string]$Target = "",
  [ValidateSet("respect", "takeover", "quarantine", "abort", "auto")]
  [string]$Action = "auto",
  [switch]$SkipBuild,
  [switch]$Cleanup,
  [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run this script in an elevated (Administrator) PowerShell."
  }
}

function Assert-RepoRoot {
  param([string]$Path)
  if (-not (Test-Path (Join-Path $Path "Cargo.toml"))) {
    throw "Please run this script from the repository root."
  }
}

function Get-IfeoKeyPath {
  param(
    [string]$TargetName,
    [ValidateSet("64", "32")]
    [string]$View
  )
  if ($View -eq "64") {
    return "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$TargetName"
  }
  return "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$TargetName"
}

function Get-DebuggerValue {
  param([string]$KeyPath)
  $prop = Get-ItemProperty -Path $KeyPath -Name Debugger -ErrorAction SilentlyContinue
  if ($null -ne $prop) {
    return $prop.Debugger
  }
  return $null
}

function Set-DebuggerValue {
  param(
    [string]$KeyPath,
    [string]$Value
  )
  New-Item -Path $KeyPath -Force | Out-Null
  Set-ItemProperty -Path $KeyPath -Name Debugger -Value $Value | Out-Null
}

function Restore-DebuggerValue {
  param(
    [string]$KeyPath,
    [bool]$KeyExisted,
    [string]$OriginalValue
  )
  if ($KeyExisted) {
    if ([string]::IsNullOrEmpty($OriginalValue)) {
      Remove-ItemProperty -Path $KeyPath -Name Debugger -ErrorAction SilentlyContinue
    } else {
      Set-ItemProperty -Path $KeyPath -Name Debugger -Value $OriginalValue | Out-Null
    }
  } else {
    Remove-Item -Path $KeyPath -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Read-ConfigTargetEnabled {
  param(
    [string]$ConfigPath,
    [string]$TargetName
  )
  if (-not (Test-Path $ConfigPath)) {
    return $null
  }
  try {
    $json = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
    if ($null -eq $json.targets) {
      return $null
    }
    foreach ($t in $json.targets) {
      if ($t.exe_name -and $t.exe_name.ToString().ToLower() -eq $TargetName.ToLower()) {
        return [bool]$t.enabled
      }
    }
  } catch {
    return $null
  }
  return $null
}

Assert-Admin
$repo = (Get-Location).Path
Assert-RepoRoot -Path $repo

$binDir = Join-Path $repo ("target\" + $Profile)
$setupExe = Join-Path $binDir "kh-setup.exe"

$packages = @(
  "kh-bootstrap",
  "kh-guard",
  "kh-service",
  "kh-service-restart",
  "kh-restore",
  "kh-uninstall",
  "kh-cli",
  "kh-settings",
  "kh-setup",
  "kh-tray"
)
$binaries = @(
  "kh-bootstrap.exe",
  "kh-guard.exe",
  "kh-service.exe",
  "kh-service-restart.exe",
  "kh-restore.exe",
  "kh-uninstall.exe",
  "kh-cli.exe",
  "kh-settings.exe",
  "kh-setup.exe",
  "kh-tray.exe"
)

if (-not $SkipBuild) {
  $missing = @()
  foreach ($bin in $binaries) {
    if (-not (Test-Path (Join-Path $binDir $bin))) {
      $missing += $bin
    }
  }
  if ($missing.Count -gt 0) {
    $args = @("build")
    foreach ($pkg in $packages) {
      $args += @("-p", $pkg)
    }
    if ($Profile -eq "release") {
      $args += "--release"
    }
    Write-Host "Building: $($packages -join ', ')"
    & cargo @args | Out-Host
    if ($LASTEXITCODE -ne 0) {
      throw "cargo build failed (exit $LASTEXITCODE)."
    }
  }
}

if (-not (Test-Path $setupExe)) {
  throw "kh-setup.exe not found: $setupExe"
}

$defaultTargets = @(
  "powershell.exe",
  "pwsh.exe",
  "cmd.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "certutil.exe",
  "bitsadmin.exe",
  "wmic.exe",
  "installutil.exe",
  "msdt.exe",
  "powershell_ise.exe"
)

if ([string]::IsNullOrWhiteSpace($Target)) {
  foreach ($t in $defaultTargets) {
    $k64 = Get-IfeoKeyPath -TargetName $t -View "64"
    $k32 = Get-IfeoKeyPath -TargetName $t -View "32"
    $dbg64 = Get-DebuggerValue -KeyPath $k64
    $dbg32 = Get-DebuggerValue -KeyPath $k32
    if ([string]::IsNullOrEmpty($dbg64) -and [string]::IsNullOrEmpty($dbg32)) {
      $Target = $t
      break
    }
  }
  if ([string]::IsNullOrWhiteSpace($Target)) {
    throw "No available default target found. Specify one with -Target."
  }
} else {
  if ($defaultTargets -notcontains $Target.ToLower()) {
    throw "Target must be one of the default targets. Provided: $Target"
  }
}

$key64 = Get-IfeoKeyPath -TargetName $Target -View "64"
$key32 = Get-IfeoKeyPath -TargetName $Target -View "32"
$orig64Exists = Test-Path $key64
$orig32Exists = Test-Path $key32
$orig64 = Get-DebuggerValue -KeyPath $key64
$orig32 = Get-DebuggerValue -KeyPath $key32

if (-not $Force) {
  if (-not [string]::IsNullOrEmpty($orig64) -or -not [string]::IsNullOrEmpty($orig32)) {
    throw "Existing Debugger detected. Use -Force to override for testing."
  }
}

$conflictDebugger = Join-Path $env:SystemRoot "System32\cmd.exe"
Set-DebuggerValue -KeyPath $key64 -Value $conflictDebugger
Set-DebuggerValue -KeyPath $key32 -Value $conflictDebugger

Write-Host "Conflict target: $Target"
Write-Host "Debugger (conflict): $conflictDebugger"
Write-Host "Starting kh-setup (MessageBox wizard)."
Write-Host "When the conflict dialog appears, choose an action. Verification runs after exit."

$proc = Start-Process -FilePath $setupExe -PassThru
$proc.WaitForExit()

$expectedDebugger = Join-Path $Env:ProgramFiles "KaptainhooK\bin\kh-bootstrap.exe"
$after64 = Get-DebuggerValue -KeyPath $key64
$after32 = Get-DebuggerValue -KeyPath $key32

Write-Host "Post-install Debugger (64): $after64"
Write-Host "Post-install Debugger (32): $after32"

if ($Action -eq "auto") {
  if ($after64 -eq $expectedDebugger -and $after32 -eq $expectedDebugger) {
    $Action = "takeover"
    Write-Host "Observed: debugger replaced (takeover/quarantine)."
  } elseif ($after64 -eq $conflictDebugger -and $after32 -eq $conflictDebugger) {
    $configPath = Join-Path $env:ProgramData "KaptainhooK\final\config\config.json"
    $enabled = Read-ConfigTargetEnabled -ConfigPath $configPath -TargetName $Target
    if ($enabled -eq $false) {
      $Action = "respect"
      Write-Host "Observed: debugger kept + target disabled (respect)."
    } else {
      $Action = "abort"
      Write-Host "Observed: debugger kept + config unchanged (abort/cancel)."
    }
  } else {
    $Action = "abort"
    Write-Host "Observed: mixed state; treating as abort/cancel."
  }
}

switch ($Action) {
  "takeover" { 
    if ($after64 -ne $expectedDebugger -or $after32 -ne $expectedDebugger) {
      Write-Host "FAIL: takeover expected debugger=$expectedDebugger"
    } else {
      Write-Host "OK: takeover applied."
    }
  }
  "quarantine" { 
    if ($after64 -ne $expectedDebugger -or $after32 -ne $expectedDebugger) {
      Write-Host "FAIL: quarantine expected debugger=$expectedDebugger"
    } else {
      Write-Host "OK: quarantine applied (debugger replaced)."
    }
  }
  "respect" {
    if ($after64 -ne $conflictDebugger -or $after32 -ne $conflictDebugger) {
      Write-Host "FAIL: respect expected debugger=$conflictDebugger"
    } else {
      Write-Host "OK: respect kept foreign debugger."
    }
  }
  "abort" {
    if ($after64 -ne $conflictDebugger -or $after32 -ne $conflictDebugger) {
      Write-Host "WARN: abort expected debugger to remain $conflictDebugger"
    } else {
      Write-Host "OK: abort left debugger unchanged."
    }
  }
  default {
    Write-Host "Verification skipped."
  }
}

if ($Action -eq "respect") {
  $configPath = Join-Path $env:ProgramData "KaptainhooK\final\config\config.json"
  $enabled = Read-ConfigTargetEnabled -ConfigPath $configPath -TargetName $Target
  if ($null -eq $enabled) {
    Write-Host "NOTE: config check skipped (config not found or parse failed)."
  } elseif ($enabled) {
    Write-Host "WARN: target is still enabled in config (expected disabled)."
  } else {
    Write-Host "OK: target disabled in config."
  }
}

if ($Cleanup) {
  Restore-DebuggerValue -KeyPath $key64 -KeyExisted $orig64Exists -OriginalValue $orig64
  Restore-DebuggerValue -KeyPath $key32 -KeyExisted $orig32Exists -OriginalValue $orig32
  Write-Host "Cleanup: restored original IFEO debugger values."
} else {
  Write-Host "Cleanup skipped. If needed, rerun with -Cleanup."
}
