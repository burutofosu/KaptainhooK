# KaptainhooK

English | [日本語](README.md)

Process execution control and monitoring system for Windows

## Overview

KaptainhooK is a personal learning project that controls and monitors the execution of risky scripting tools (PowerShell, cmd.exe, etc.) on Windows.
As an example of IFEO operations and mitigation, it visualizes necessary countermeasures and challenges in this form.
It detects the launch of specified processes and allows, notifies, prompts, or blocks based on policy.

## What is IFEO

IFEO (Image File Execution Options) is a Windows registry mechanism for debugging. When a specific executable launches, Windows can automatically start a different program (a debugger) instead.

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe name>
```

If you set a value named `Debugger` there, Windows launches that debugger instead of the original executable.

KaptainhooK uses this mechanism so the target EXE always passes through KaptainhooK first, enabling origin checks and warning prompts.

## Key Features

### Reaction (Log / Notify / Friction)

There are three reaction modes:

- **Log**: allow and record only
- **Notify**: show a warning MessageBox and allow
- **Friction**: show a confirmation UI (friction) and allow

Separately, policy conditions can block execution (non-interactive sessions, timeouts, Windows Hello failures, etc.).

### Automatic origin classification

Categories are assigned using parent/grandparent process names and argument patterns:

**Examples considered Mail**

- Parent/grandparent is `outlook.exe` / `olk.exe` / `thunderbird.exe`
- Arguments include `\Content.Outlook\` / `\INetCache\` / `mailto:`

**Examples considered Macro**

- Parent/grandparent is `winword.exe` / `excel.exe` / `powerpnt.exe` / `visio.exe`
- Arguments end with `.docm` / `.xlsm` / `.pptm` / `.dotm`

**Examples considered Relay**

- Parent/grandparent is `powershell.exe` / `pwsh.exe` / `cmd.exe` / `wscript.exe` / `cscript.exe` / `mshta.exe` / `rundll32.exe` / `regsvr32.exe` / `certutil.exe` / `bitsadmin.exe` / `wmic.exe` / `installutil.exe` / `msdt.exe` / `powershell_ise.exe` / `wt.exe` / `msiexec.exe` / `schtasks.exe`
- The target itself is one of those executables

If multiple categories are assigned, the strongest reaction applies (Friction > Notify > Log).

### Presets (4)

Reaction rules can be selected from presets:

|Preset   |Mail    |Macro   |Relay   |Always  |
|---------|--------|--------|--------|--------|
|`all_log`|Log     |Log     |Log     |Log     |
|`strong` |Friction|Friction|Friction|Friction|
|`medium` |Friction|Friction|Notify  |Friction|
|`weak`   |Notify  |Notify  |Log     |Notify  |

Default is `all_log`.

### Path hint warnings

If the path contains the following, it is treated as suspicious:

**Suspicious locations**

- `\users\public\`
- `\temp\`
- `\appdata\local\temp\`
- `\downloads\`
- `\desktop\`

**Safe locations (reference only)**

- `\program files\`
- `\program files (x86)\`
- `\windows\system32\`
- `\windows\syswow64\`

### Friction settings

Defaults for Friction mode:

|Setting               |Default |Range               |
|----------------------|--------|--------------------|
|Hold required         |Enabled |-                   |
|Hold duration         |1,500ms |500-30,000ms        |
|Pointer move required |Enabled |-                   |
|Move distance         |80px    |10-500px            |
|Emergency bypass      |Enabled |-                   |
|Emergency hold time   |5,000ms |1,000-10,000ms      |

Emergency bypass succeeds by holding Ctrl + Shift + Alt for the specified duration.

### Policy settings

|Setting                      |Default        |
|----------------------------|----------------|
|Allow non-interactive session|Deny (false)    |
|Timeout seconds              |60 seconds (0 disables)|
|Auth mode                    |Friction UI     |

### Nudge messages

You can show a custom message on execution. Default message:

> If you are unsure, contact your IT administrator.

### Logs (JSONL)

Execution events are recorded in JSONL. Logs rotate (rename) when they exceed 5 MB.

- **Per user**: `C:\Users\<User>\AppData\Local\KaptainhooK\final\logs\guard.log.jsonl`
- **Admin/service**: `C:\ProgramData\KaptainhooK\final\logs\operation.log.jsonl`
- **Lifecycle**: `C:\ProgramData\KaptainhooK\final\logs\kh-lifecycle.log`

Example log (allowed via Friction):

```json
{
  "timestamp": "2026-01-09T10:30:45.123Z",
  "normalized_target": "powershell.exe",
  "args": ["-encodedcommand", "…"],
  "username": "tanaka",
  "session": "Console",
  "reason": "reaction friction (origin: mail)",
  "action": "allowed",
  "reaction": "friction",
  "origin_categories": ["mail"],
  "allowed": true,
  "emergency": false,
  "nudge_message_id": "default-nudge",
  "exit_code": 0,
  "duration_ms": 3245,
  "enabled_targets": 14,
  "parent_pid": 1234,
  "parent_process": "outlook.exe",
  "parent_path": "C:\\Program Files\\Microsoft Office\\…",
  "grandparent_pid": 5678,
  "grandparent_process": "explorer.exe",
  "grandparent_path": "C:\\Windows\\explorer.exe"
}
```

### IFEO conflict detection

If another Debugger is already set in IFEO, it is detected as a conflict. Signature info (Signed/Trust/Revocation, etc.) for the existing debugger is also shown.

Options during setup:

- **Respect (skip)**: keep existing settings
- **Take over (overwrite)**: replace with KaptainhooK
- **Quarantine**: overwrite and label the backup as risky

### Backup and rollback

There are two backup tracks:

- **Rollback**: `C:\ProgramData\KaptainhooK\final\backups\backups.json`
  - Used by `kh-cli rollback`
- **Uninstall**: `HKLM\SOFTWARE\KaptainhooK\UninstallState\IfeoBackups`
  - Enables restoration by uninstaller even after binaries are removed

### Service hijack prevention

KaptainhooK temporarily removes IFEO when a launch is allowed. To protect that flow, two safety layers are used:

1. **Allow-list**: `HKLM\SOFTWARE\KaptainhooK\Targets` limits what the service can handle
1. **IPC validation**: the named pipe (`\\.\pipe\KaptainhooKService`) validates:
   - process is `kh-guard.exe`
   - path equals `C:\Program Files\KaptainhooK\bin\kh-guard.exe`
   - SHA256 matches `SOFTWARE\KaptainhooK\TrustedHashes` value `GuardHash`

## Default targets (15)

|# |Target             |Description                 |Default |
|--|-------------------|----------------------------|--------|
|1 |powershell.exe     |Windows PowerShell          |Enabled |
|2 |pwsh.exe           |PowerShell Core             |Enabled |
|3 |cmd.exe            |Command Prompt              |Enabled |
|4 |wscript.exe        |Windows Script Host         |Enabled |
|5 |cscript.exe        |Console Script Host         |Enabled |
|6 |mshta.exe          |HTML Application Host       |Enabled |
|7 |rundll32.exe       |DLL execution utility       |Enabled |
|8 |regsvr32.exe       |COM registration utility    |Enabled |
|9 |certutil.exe       |Certificate utility         |Enabled |
|10|bitsadmin.exe      |BITS file transfer          |Enabled |
|11|wmic.exe           |WMI command-line            |Enabled |
|12|installutil.exe    |.NET installer tool         |Enabled |
|13|msdt.exe           |Microsoft diagnostics tool  |Enabled |
|14|powershell_ise.exe |PowerShell ISE              |Enabled |
|15|wt.exe             |Windows Terminal            |**Disabled** |

These are common LOLBins (Living Off The Land Binaries), so they are protected by default.

## System Requirements

- **OS**: Windows 11
- **Privileges**: admin rights required
- **Rust**: 1.85.0 or later (for build)
- **C++ toolchain**: Visual Studio "Desktop development with C++" (MSVC + Windows SDK)

## Installation

### Install from release package (recommended)

Run the shortcut in the extracted folder; it starts `bin/kh-setup.exe` and asks for admin permission.

```
kh-setup.exe
```

### Install from command line

```powershell
# Interactive CLI
kh-setup.exe --cli

# Dry run (no changes)
kh-setup.exe --cli --dry-run

# Defaults, non-interactive
kh-setup.exe --cli --defaults
```

### Uninstall

```powershell
# Settings -> Apps -> KaptainhooK
# or
kh-setup.exe --uninstall
# or
kh-uninstall.exe
```

### Build from source

```bash
git clone https://github.com/burutofosu/KaptainhooK
cd KaptainhooK

# Release build
cargo build --release

# Binaries are generated under target/release/
```

## Usage

### Command line operations (kh-cli.exe)

```powershell
# Install (dry run)
kh-cli.exe install --dry-run

# Status
kh-cli.exe status

# Conflict detection
kh-cli.exe conflicts

# Target management
kh-cli.exe targets list
kh-cli.exe targets enable powershell.exe
kh-cli.exe targets disable mshta.exe
kh-cli.exe targets remove wmic.exe

# Cleanup
kh-cli.exe cleanup
kh-cli.exe cleanup --scan

# Rollback
kh-cli.exe rollback

# Uninstall (cleanup only)
kh-cli.exe uninstall
kh-cli.exe uninstall --remove-data  # also remove data

# Task status
kh-cli.exe task-info

# Refresh TrustedHashes
kh-cli.exe trusted-hashes refresh
```

For a full uninstall, use `kh-uninstall.exe` or `kh-setup.exe --uninstall`.

### Settings UI (kh-settings.exe)

WebView2-based settings UI supports:

- enable/disable targets
- reaction rules (presets and per-target overrides)
- friction settings
- policy (non-interactive allow, timeout, auth mode)
- nudge messages
- language (Japanese/English)
- search paths (user-added `search_paths`)
- background image (skin) and opacity

Background is applied only in the Settings UI.

### System tray (kh-tray.exe)

Resident system tray app that launches Settings UI and shows service status.

## How It Works

### During installation

1. Place binaries and assets under `C:\Program Files\KaptainhooK\bin\`
1. Create config / logs / backups under `C:\ProgramData\KaptainhooK\final\`
1. Detect conflicts and prompt for action
1. Write `HKLM\SOFTWARE\KaptainhooK\Targets` and `TrustedHashes`
1. Register restore task `KaptainhooKRestore`
1. Back up IFEO state for uninstall
1. Install and start the service `KaptainhooKService`
1. Apply IFEO to both 64-bit and 32-bit views
1. Save `config.json`
1. Register in Apps & Features, register startup, launch tray

### During execution

1. Target (e.g. `cmd.exe`) runs
1. Windows IFEO launches `kh-bootstrap.exe`
1. `kh-bootstrap` launches `kh-guard`
1. `kh-guard` reads config.json, collects parent/grandparent info, and categorizes
1. Evaluate reaction and policy, show warning/confirmation if needed
1. Log to `guard.log.jsonl`
1. If allowed, request bypass from the service
1. Service temporarily removes IFEO (TTL: `auto_restore_seconds` × 1000ms, default 2s)
1. `kh-guard` launches the original executable
1. Service restores IFEO

## Architecture

Mix of hexagonal and layered architecture:

```
Domain (innermost, std only)
  ↓
Engine (Domain only)
  ↓
Application (Domain + Engine)
  ↓
Composition (DI root)
  ↓
Infrastructure / UI (port implementations)
  ↓
Apps (executables)
```

## Project Structure

```
KaptainhooK/
├── assets/                          # Icons / background images
├── domain/kh-domain/                # Domain layer
├── engine/kh-engine/                # Engine layer
├── application/kh-app/              # Application layer
├── composition/kh-composition/      # DI / composition root
├── infrastructure/                  # Infrastructure adapters
│   ├── kh-adapter-registry/         # Registry access
│   ├── kh-adapter-signature/        # Digital signature verification
│   ├── kh-adapter-fs/               # File system
│   ├── kh-adapter-task/             # Task Scheduler
│   ├── kh-adapter-clock/            # Time source
│   ├── kh-adapter-service-ipc/      # Inter-process communication
│   ├── kh-adapter-paths/            # Path resolution
│   ├── kh-adapter-guard/            # Guard-related
│   └── kh-adapter-uninstall-state/  # Uninstall state
├── ui/                              # UI layer
│   ├── kh-ui-common/                # Common UI
│   └── kh-ui-guard/                 # Guard UI
├── shared/                          # Shared utilities
│   └── kh-log-utils/                # Log utilities
├── apps/                            # Executables
│   ├── bootstrap/                   # IFEO entrypoint
│   ├── guard/                       # Main guard
│   ├── service/                     # Windows service
│   ├── service-restart/             # Service restart
│   ├── restore/                     # Restore tool
│   ├── setup/                       # Setup wizard
│   ├── cli/                         # Command-line tool
│   ├── settings/                    # Settings UI
│   ├── tray/                        # System tray
│   └── uninstall/                   # Uninstaller
└── scripts/                         # Build/test scripts
    ├── package.ps1                  # Package builder
    └── run_integration_tests.ps1    # Integration tests
```

## External Dependencies

### Core (used widely)

- windows
- serde / serde_json
- clap
- sha2

### Settings UI (kh-settings)

- wry / tao (WebView2 host)

### Setup (kh-setup)

- embed-resource (build-time resource embedding)

## Configuration File

### Paths

|Type            |Path                                                                  |
|----------------|------------------------------------------------------------------------|
|Data            |`C:\ProgramData\KaptainhooK\final`                                      |
|Binaries        |`C:\Program Files\KaptainhooK\bin`                                      |
|Config          |`C:\ProgramData\KaptainhooK\final\config\config.json`                   |
|Logs (user)     |`C:\Users\<User>\AppData\Local\KaptainhooK\final\logs\guard.log.jsonl`   |
|Logs (admin)    |`C:\ProgramData\KaptainhooK\final\logs\operation.log.jsonl`             |

### Settings

|Key                      |Description                                              |
|-------------------------|----------------------------------------------------------|
|`targets`                |monitored targets list                                   |
|`policy`                 |allow non-interactive, timeout, auth mode                |
|`reaction`               |reaction rules (preset, default_rule, overrides)         |
|`friction`               |user confirmation UI settings                            |
|`nudge_messages`         |nudge messages                                            |
|`language`               |language (ja / en)                                       |
|`auto_restore_seconds`   |auto restore timeout (1-300 sec, default 2 sec)          |
|`search_paths`           |extra executable search paths (local absolute only)      |
|`background`             |background (image, opacity: 0-100)                       |

### Executable resolution order

1. **If an absolute path is passed**: only local drive-letter absolute paths are allowed
   - Allowed: `C:\Windows\System32\cmd.exe`
   - Not allowed: UNC (`\\server\share\...`), no drive letter
1. **Otherwise**: if the name has no path separator, search safe default paths + `search_paths`
1. **Relative paths (with separators)**: not allowed

## Out of Scope

- Execution that bypasses IFEO
- Processes outside the target list
- ConsentFix-style attacks (OAuth token theft, etc.)
- If HKLM itself is compromised
- Other processes starting during the brief IFEO-disable window

## Development

### Build

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Build a specific binary
cargo build --release -p kh-guard
```

### Package

```powershell
scripts/package.ps1
```

### Tests

```bash
# Run all tests
cargo test

# Test a specific package
cargo test -p kh-domain
```

### Integration tests (Windows / admin)

```powershell
scripts/run_integration_tests.ps1 -Profile debug
```

### Lint and format

```bash
cargo clippy
cargo fmt
```

## Troubleshooting

### Installation fails

- Confirm you are running as administrator
- Check conflicts with existing IFEO settings
- Check backup files and try restore

### Target won't start

- Check IFEO registry keys
- Check the paths to `kh-bootstrap.exe` and `kh-guard.exe`
- Check log files for errors

### Need rollback

```powershell
kh-restore.exe
# or
kh-cli.exe rollback
```

### Manually remove registry entries (last resort)

> **Warning**: incorrect deletion can affect the system. Always back up first.
> Try `kh-restore` / `kh-cli` / `kh-uninstall` before manual removal.

**Steps**

1. Run Registry Editor (regedit) as administrator
1. Remove IFEO entries whose `Debugger` points to KaptainhooK `kh-bootstrap.exe`
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
- On 64-bit OS, also check 32-bit view: `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
1. Remove KaptainhooK management keys
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\Targets`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\TrustedHashes`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\LeaseState`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\UninstallState`

**How to identify KaptainhooK entries**: `Debugger` contains:

```
C:\Program Files\KaptainhooK\bin\kh-bootstrap.exe
```

(`--ifeo-view=32/64` may be appended.)

## Security Notes

- This software runs with admin privileges
- It modifies IFEO registry entries and can affect the system
- Test in a non-production environment before use
- Check compatibility with other security software

## License

This project is licensed under the Apache License 2.0. See [LICENSE](./LICENSE).

## Version

Current version: **0.95.0**
