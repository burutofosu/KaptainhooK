param(
  [ValidateSet("debug", "release")]
  [string]$Profile = "debug"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "このスクリプトは管理者権限で実行してください。"
  }
}

function Invoke-Exe {
  param(
    [string]$Path,
    [string[]]$Args,
    [string]$Label
  )
  if (-not $Label) {
    $Label = $Path
  }
  & $Path @Args | Out-Host
  if ($LASTEXITCODE -ne 0) {
    throw "$Label に失敗しました (exit $LASTEXITCODE)。"
  }
}

function Invoke-Json {
  param(
    [string]$Path,
    [string[]]$Args,
    [string]$Label
  )
  if (-not $Label) {
    $Label = $Path
  }
  $raw = & $Path @Args
  if ($LASTEXITCODE -ne 0) {
    throw "$Label に失敗しました (exit $LASTEXITCODE)。"
  }
  if ($null -eq $raw) {
    return @()
  }
  $jsonText = $raw -join "`n"
  return @($jsonText | ConvertFrom-Json)
}

function New-TestTargetName {
  $suffix = ([Guid]::NewGuid().ToString("N")).Substring(0, 8)
  return "kaptainhook_integration_test_$suffix.exe"
}

function Assert-StatusEntries {
  param(
    [object[]]$Entries,
    [string]$Target,
    [bool]$ExpectedEnabled,
    [string]$ExpectedDebugger
  )
  $targetEntries = $Entries | Where-Object { $_.target -ieq $Target }
  if ($null -eq $targetEntries -or $targetEntries.Count -ne 2) {
    throw "ステータス $Target の件数は2件が期待値ですが $($targetEntries.Count) 件でした。"
  }
  foreach ($entry in $targetEntries) {
    if ($ExpectedEnabled -and -not $entry.enabled) {
      throw "$Target ($($entry.view)) は enabled=true が期待値です。"
    }
    if (-not $ExpectedEnabled -and $entry.enabled) {
      throw "$Target ($($entry.view)) は enabled=false が期待値です。"
    }
    if ([string]::IsNullOrEmpty($ExpectedDebugger)) {
      if ($entry.debugger) {
        throw "$Target ($($entry.view)) は debugger が空であるべきです。"
      }
    } elseif ($entry.debugger -ne $ExpectedDebugger) {
      throw "$Target ($($entry.view)) の debugger が期待値と一致しません: $($entry.debugger)"
    }
  }
}

function Assert-ConfigEntry {
  param(
    [object[]]$Entries,
    [string]$Target,
    [bool]$ExpectPresent,
    [bool]$ExpectedEnabled
  )
  $entry = $Entries | Where-Object { $_.target -ieq $Target }
  if ($ExpectPresent) {
    if ($null -eq $entry -or $entry.Count -ne 1) {
      throw "設定の $Target は1件が期待値ですが $($entry.Count) 件でした。"
    }
    if ($entry[0].enabled -ne $ExpectedEnabled) {
      $expected = if ($ExpectedEnabled) { "true" } else { "false" }
      throw "設定の $Target は enabled=$expected が期待値です。"
    }
  } else {
    if ($null -ne $entry -and $entry.Count -gt 0) {
      throw "設定に $Target が残っています。"
    }
  }
}

function Cleanup-Target {
  param(
    [string]$Cli,
    [string]$Target
  )
  $saved = $ErrorActionPreference
  $ErrorActionPreference = "Continue"
  & $Cli targets disable $Target | Out-Null
  & $Cli targets remove $Target | Out-Null
  $ErrorActionPreference = $saved
}

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot

$cli = $null
$target = $null

try {
  Assert-Admin

  $buildArgs = @("build", "-p", "kh-cli", "-p", "kh-bootstrap", "-p", "kh-guard")
  if ($Profile -eq "release") {
    $buildArgs += "--release"
  }
  Write-Host "ビルド開始 ($Profile)..."
  Invoke-Exe "cargo" $buildArgs "cargo build"

  $binDir = Join-Path $repoRoot ("target\\" + $Profile)
  $cli = Join-Path $binDir "kh-cli.exe"
  $bootstrap = Join-Path $binDir "kh-bootstrap.exe"
  $guard = Join-Path $binDir "kh-guard.exe"
  foreach ($path in @($cli, $bootstrap, $guard)) {
    if (-not (Test-Path $path)) {
      throw "バイナリが見つかりません: $path"
    }
  }

  $installBin = Join-Path $env:ProgramFiles "KaptainhooK\\bin"
  New-Item -ItemType Directory -Force -Path $installBin | Out-Null
  Copy-Item -Force $bootstrap (Join-Path $installBin "kh-bootstrap.exe")
  Copy-Item -Force $guard (Join-Path $installBin "kh-guard.exe")

  $target = New-TestTargetName
  Write-Host "テスト対象: $target"

  Write-Host "有効化: $target"
  Invoke-Exe $cli @("targets", "enable", $target) "kh-cli targets enable"

  $entries = Invoke-Json $cli @("status", "--json") "kh-cli status"
  $expectedDebugger = Join-Path $installBin "kh-bootstrap.exe"
  Assert-StatusEntries $entries $target $true $expectedDebugger
  $configTargets = Invoke-Json $cli @("targets", "list", "--json") "kh-cli targets list"
  Assert-ConfigEntry $configTargets $target $true $true

  Write-Host "無効化: $target"
  Invoke-Exe $cli @("targets", "disable", $target) "kh-cli targets disable"
  $entries = Invoke-Json $cli @("status", "--json") "kh-cli status"
  Assert-StatusEntries $entries $target $false $null
  $configTargets = Invoke-Json $cli @("targets", "list", "--json") "kh-cli targets list"
  Assert-ConfigEntry $configTargets $target $true $false

  Write-Host "削除: $target"
  Invoke-Exe $cli @("targets", "remove", $target) "kh-cli targets remove"
  $targets = Invoke-Json $cli @("targets", "list", "--json") "kh-cli targets list"
  Assert-ConfigEntry $targets $target $false $false

  Write-Host "統合テスト完了: 成功"
} finally {
  if ($null -ne $cli -and $null -ne $target -and (Test-Path $cli)) {
    Cleanup-Target $cli $target
  }
  Pop-Location
}
