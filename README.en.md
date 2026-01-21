# KaptainhooK

English | [日本語](README.md)

A process execution control and monitoring system for Windows environments

## Overview

KaptainhooK is a personal, learning-oriented project that controls and monitors the execution of dangerous scripting tools (PowerShell, cmd.exe, etc.) on Windows.
As one example of countermeasures against IFEO manipulation and abuse, I summarized it in this form to visualize the necessary measures and challenges.
It detects the launch of specified processes and, based on policy, allows, notifies, asks for confirmation, or blocks.

Since this is only a learning project, please use it in a test environment.

## What is IFEO

IFEO (Image File Execution Options) is a registry mechanism provided by Windows for debugging. When a specific executable is launched, Windows can automatically start another program (a debugger) instead.

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<executable name>
```

If you set the value `Debugger` here, that debugger will be launched instead of the original executable.

KaptainhooK uses this mechanism to make sure the target exe “always passes through here once,” enabling verification of the launch origin and warning displays.

## Key features

### Reactions (Log / Notify / Friction)

KaptainhooK has three kinds of reactions:

- **Log**: Allow with logging only
- **Notify**: Show a warning MessageBox and allow
- **Friction**: Show a confirmation UI (friction) and allow

Separately from these, blocking can occur due to policy conditions (reject non-interactive sessions, timeout, Windows Hello failure, etc.).

### Automatic origin category classification

It assigns categories based on parent/grandparent process names and argument patterns:

**Examples considered Mail (email)**

- Parent/grandparent is `outlook.exe` / `olk.exe` / `thunderbird.exe`
- Arguments include `\Content.Outlook\` / `\INetCache\` / `mailto:`

**Examples considered Macro**

- Parent/grandparent is `winword.exe` / `excel.exe` / `powerpnt.exe` / `visio.exe`
- Arguments end with `.docm` / `.xlsm` / `.pptm` / `.dotm`

**Examples considered Relay**

- Parent/grandparent is `powershell.exe` / `pwsh.exe` / `cmd.exe` / `wscript.exe` / `cscript.exe` / `mshta.exe` / `rundll32.exe` / `regsvr32.exe` / `certutil.exe` / `bitsadmin.exe` / `wmic.exe` / `installutil.exe` / `msdt.exe` / `powershell_ise.exe` / `wt.exe` / `msiexec.exe` / `schtasks.exe`
- If the target itself is one of these exe files, it is also treated as a relay

If multiple categories are assigned, the strongest reaction order (Friction > Notify > Log) is applied.

### Presets (4 types)

Reaction rules can be selected from presets:

|Preset     |Mail    |Macro   |Relay   |Always  |
|-----------|--------|--------|--------|--------|
|`all_log`  |Log     |Log     |Log     |Log     |
|`strong`   |Friction|Friction|Friction|Friction|
|`medium`   |Friction|Friction|Notify  |Friction|
|`weak`     |Notify  |Notify  |Log     |Notify  |

The default setting is `all_log`.

### Execution location warning (Path Hint)

If the path contains any of the following, it is warned as a suspicious location:

**Suspicious locations**

- `\users\public\`
- `\temp\`
- `\appdata\local\temp\`
- `\downloads\`
- `\desktop\`

**Safe locations (reference display)**

- `\program files\`
- `\program files (x86)\`
- `\windows\system32\`
- `\windows\syswow64\`

### Friction settings

Default values for Friction mode:

|Setting              |Default   |Range              |
|---------------------|----------|-------------------|
|Long-press required  |Enabled   |-                  |
|Long-press time      |1,500ms   |500–30,000ms       |
|Mouse movement required|Enabled |-                  |
|Move distance        |80px      |10–500px           |
|Emergency bypass     |Enabled   |-                  |
|Emergency bypass time|5,000ms   |1,000–10,000ms     |

Emergency bypass is satisfied when Ctrl + Shift + Alt are held for the specified time.

### Policy settings

|Setting                          |Default            |
|---------------------------------|-------------------|
|Allow non-interactive sessions   |Reject (false)     |
|Timeout seconds                  |60 seconds (0 disables) |
|Authentication method            |Friction UI        |

### Nudge message

You can show a specified message at execution time. Default message:

> If you are unsure, contact your IT administrator.

### Logs (JSONL)

Execution events are recorded in JSONL format. When it exceeds 5MB, it rotates (renames).

- **Per user**: `C:\Users\<User>\AppData\Local\KaptainhooK\final\logs\guard.log.jsonl`
- **Administrative**: `C:\ProgramData\KaptainhooK\final\logs\operation.log.jsonl`
- **Lifecycle**: `C:\ProgramData\KaptainhooK\final\logs\kh-lifecycle.log`

Log example (a case allowed with Friction):

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

If another Debugger is already set in IFEO, it is detected as a conflict. Signature information (Signed/Trust/Revocation, etc.) of the existing debugger is also displayed.

Setup options:

- **Respect (skip)**: Keep the existing settings
- **Inherit (overwrite)**: Overwrite with KaptainhooK
- **Quarantine**: Overwrite and label the backup as dangerous

### Backup and rollback

There are two backup systems:

- **For rollback**: `C:\ProgramData\KaptainhooK\final\backups\backups.json`
  - Used by `kh-cli rollback`
- **For uninstall**: `HKLM\SOFTWARE\KaptainhooK\UninstallState\IfeoBackups`
  - Even after binaries are deleted, restoration is possible using only the uninstaller

### Service hijack prevention

Since KaptainhooK “removes IFEO briefly when allowed,” it implements two safety layers:

1. **Allow-list**: Manage the list of targets the service is allowed to handle in `HKLM\SOFTWARE\KaptainhooK\Targets`
1. **IPC validation**: Validate the connection source over a Named Pipe (`\\.\pipe\KaptainhooKService`)
- The process is `kh-guard.exe`
- The path matches `C:\Program Files\KaptainhooK\bin\kh-guard.exe`
- The SHA256 matches `GuardHash` in `SOFTWARE\KaptainhooK\TrustedHashes`

## Monitored targets (default 15)

|#  |Target            |Description                 |Default |
|---|------------------|----------------------------|--------|
|1  |powershell.exe    |Windows PowerShell          |Enabled |
|2  |pwsh.exe          |PowerShell Core             |Enabled |
|3  |cmd.exe           |Command Prompt              |Enabled |
|4  |wscript.exe       |Windows Script Host         |Enabled |
|5  |cscript.exe       |Console script host         |Enabled |
|6  |mshta.exe         |HTML Application Host       |Enabled |
|7  |rundll32.exe      |DLL execution utility       |Enabled |
|8  |regsvr32.exe      |COM registration utility    |Enabled |
|9  |certutil.exe      |Certificate utility         |Enabled |
|10 |bitsadmin.exe     |BITS file transfer          |Enabled |
|11 |wmic.exe          |WMI command-line            |Enabled |
|12 |installutil.exe   |.NET installer tool         |Enabled |
|13 |msdt.exe          |Microsoft diagnostic tool   |Enabled |
|14 |powershell_ise.exe|PowerShell ISE              |Enabled |
|15 |wt.exe            |Windows Terminal            |**Disabled** |

These are standard targets because they can be abused as LOLBins (Living Off The Land Binaries) in some cases.

## System requirements

- **OS**: Windows 11
- **Privileges**: Administrator privileges required
- **Rust**: 1.85.0 or later (for building)
- **C++ build environment**: Visual Studio “Desktop development with C++” (MSVC + Windows SDK)

## Installation

Binaries are not distributed. You create the built package yourself from the script.

### Build from source

```bash
git clone https://github.com/burutofosu/KaptainhooK
cd KaptainhooK

# Release build
cargo build --release

# Executables are generated under target/release/
```

### Build from ZIP

Open a terminal in the folder where you extracted the ZIP file, and build with the following:

```
cargo build --release
```

### Create a distribution package

After the build completes, run the following to create a full set of executables and shortcuts in the package folder.

```powershell
scripts/package.ps1
```

### Install from the package folder

Running the shortcut starts `bin/kh-setup.exe`. Grant administrator privileges via UAC and run it.

### Install from the command line

```powershell
# Interactive mode
kh-setup.exe --cli

# Dry-run (no changes)
kh-setup.exe --cli --dry-run

# Run automatically with default settings
kh-setup.exe --cli --defaults
```

### Uninstall

```powershell
# Uninstall from Settings → Apps → KaptainhooK
# or
kh-setup.exe --uninstall
# or
kh-uninstall.exe
```

For a complete uninstall, use `kh-uninstall.exe` or `kh-setup.exe --uninstall`.

## Usage

### Command-line operations (kh-cli.exe)

```powershell
# Install (dry-run)
kh-cli.exe install --dry-run

# Status check
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

# Uninstall (for cleanup purposes)
kh-cli.exe uninstall
kh-cli.exe uninstall --remove-data  # also remove data

# Task status
kh-cli.exe task-info

# Update TrustedHashes
kh-cli.exe trusted-hashes refresh
```

### Settings UI (kh-settings.exe)

A WebView2-based settings UI where you can change:

- Enable/disable targets
- Reaction rules (preset / custom overrides)
- Friction settings
- Policy (allow non-interactive sessions, timeout seconds, authentication method)
- Nudge messages
- Language (ja / en)
- Search paths (user-added search_paths)
- Background image (skin) and opacity

The background applies only to the settings screen.

### System tray (kh-tray.exe)

A resident system tray application. It can launch the settings UI and check the service status.

## How it works

### During installation

1. Place binaries and assets into `C:\Program Files\KaptainhooK\bin\`
1. Create config / logs / backups under `C:\ProgramData\KaptainhooK\final\`
1. Detect conflicts and select handling
1. Write `HKLM\SOFTWARE\KaptainhooK\Targets` and `TrustedHashes`
1. Register the restore task `KaptainhooKRestore`
1. Back up IFEO state for uninstall
1. Register and start the service `KaptainhooKService`
1. Apply IFEO to both 64-bit and 32-bit views
1. Save `config.json`
1. Register to “Apps & features,” register for startup, start tray

### During execution

1. A target (e.g., `cmd.exe`) is executed
1. Windows IFEO finds `Debugger=kh-bootstrap.exe` and launches it
1. `kh-bootstrap` launches `kh-guard`
1. `kh-guard` reads config.json, collects parent/grandparent info, and determines categories
1. Evaluate reaction and policy; show warning/confirmation UI as needed
1. Record to `guard.log.jsonl`
1. If allowed, request bypass from the service
1. The service temporarily removes IFEO (TTL: `auto_restore_seconds` × 1000ms, default 2 seconds)
1. `kh-guard` launches the real exe
1. The service restores IFEO

## Architecture

A design combining hexagonal architecture and layered architecture:

```
Domain (innermost layer, std only)
  ↓
Engine (Domain only)
  ↓
Application (Domain + Engine)
  ↓
Composition (composition root / DI)
  ↓
Infrastructure / UI (port implementations)
  ↓
Apps (executables)
```

## Project structure

```
KaptainhooK/
├── assets/                          # Icons / background images
├── domain/kh-domain/                # Domain layer
├── engine/kh-engine/                # Engine layer
├── application/kh-app/              # Application layer
├── composition/kh-composition/      # DI / composition root
├── infrastructure/                  # Infrastructure adapters
│   ├── kh-adapter-registry/         # Registry operations
│   ├── kh-adapter-signature/        # Digital signature verification
│   ├── kh-adapter-fs/               # File system
│   ├── kh-adapter-task/             # Task scheduler
│   ├── kh-adapter-clock/            # Time provider
│   ├── kh-adapter-service-ipc/      # Inter-process communication
│   ├── kh-adapter-paths/            # Path resolution
│   ├── kh-adapter-guard/            # Guard-related
│   └── kh-adapter-uninstall-state/  # Uninstall state
├── ui/                              # User interface layer
│   ├── kh-ui-common/                # Common UI
│   └── kh-ui-guard/                 # Guard UI
├── shared/                          # Shared utilities
│   └── kh-log-utils/                # Log utilities
├── apps/                            # Executables
│   ├── bootstrap/                   # IFEO entry point
│   ├── guard/                       # Main guard
│   ├── service/                     # Windows service
│   ├── service-restart/             # Service restart
│   ├── restore/                     # Restore tool
│   ├── setup/                       # Setup wizard
│   ├── cli/                         # Command-line tool
│   ├── settings/                    # Settings UI
│   ├── tray/                        # System tray
│   └── uninstall/                   # Uninstaller
└── scripts/                         # Build / test scripts
    └── package.ps1                  # Distribution package creation

```

## External dependencies

### Core (common across many crates)

- windows
- serde / serde_json
- clap
- sha2

### Settings UI (kh-settings)

- wry / tao (WebView2 host)

### Setup (kh-setup)

- embed-resource (resource embedding at build time)

## Configuration file

### Paths

|Type            |Path                                                                  |
|----------------|----------------------------------------------------------------------|
|Data            |`C:\ProgramData\KaptainhooK\final`                                    |
|Binaries        |`C:\Program Files\KaptainhooK\bin`                                    |
|Config          |`C:\ProgramData\KaptainhooK\final\config\config.json`                 |
|Logs (user)     |`C:\Users\<User>\AppData\Local\KaptainhooK\final\logs\guard.log.jsonl`|
|Logs (admin)    |`C:\ProgramData\KaptainhooK\final\logs\operation.log.jsonl`           |

### Configuration items

|Item                    |Description                                      |
|------------------------|------------------------------------------------|
|`targets`               |List of monitored targets                        |
|`policy`                |Allow non-interactive sessions, timeout, authentication method |
|`reaction`              |Reaction rules (preset, default_rule, overrides)|
|`friction`              |User confirmation UI settings                    |
|`nudge_messages`        |Awareness messages                               |
|`language`              |Language setting (ja / en)                       |
|`auto_restore_seconds`  |Auto-restore timeout (1–300 seconds, default 2 seconds) |
|`search_paths`          |Paths added to executable search (local absolute paths only) |
|`background`            |Background setting (image, opacity: 0–100)       |

### Executable resolution order

1. **If an absolute path is passed**: Only local drive-letter absolute paths are allowed
- Allowed: `C:\Windows\System32\cmd.exe`
- Not allowed: UNC (`\\server\share\...`), no drive letter
1. **Otherwise**: Only executable names without path separators are searched from safe default paths + `search_paths`
1. **Relative path (contains separators)**: Not allowed

## Out of scope

- Execution that does not go through IFEO
- Processes outside the monitored targets
- ConsentFix-type attacks (OAuth token theft, etc.)
- If HKLM itself is tampered with
- Other processes launched during the service’s short IFEO-disable window for bypass

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

### Create a distribution package

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

### Integration tests (Windows / Administrator)

```powershell
scripts/run_integration_tests.ps1 -Profile debug
```

### Lint / format

```bash
cargo clippy
cargo fmt
```

## Troubleshooting

### Installation fails

- Confirm you are running with administrator privileges
- Check for conflicts with existing IFEO settings
- Check backup files and try restoration

### Targets do not start

- Check the IFEO registry keys
- Check the paths to `kh-bootstrap.exe` and `kh-guard.exe`
- Check the log files for error messages

### If rollback is needed

```powershell
kh-restore.exe
# or
kh-cli.exe rollback
```

### Manually delete registry entries (last resort)

> **Warning**: Incorrect deletion affects the system. Always take a backup before doing this.
> If possible, try `kh-restore` / `kh-cli` / `kh-uninstall` first.

**Steps**

1. Launch Registry Editor (regedit) with administrator privileges
1. Delete IFEO entries (only subkeys whose `Debugger` points to KaptainhooK’s `kh-bootstrap.exe`)
- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
- On 64-bit OS, also check the 32-bit side: `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
1. Delete KaptainhooK management keys
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\Targets`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\TrustedHashes`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\LeaseState`
- `HKEY_LOCAL_MACHINE\SOFTWARE\KaptainhooK\UninstallState`

**A guideline to identify KaptainhooK**: The `Debugger` value contains the following

```
C:\Program Files\KaptainhooK\bin\kh-bootstrap.exe
```

(It may include `--ifeo-view=32/64`.)

## Security notes

- This software runs with administrator privileges
- Because it modifies the IFEO registry, it may affect the system
- This is only a learning project. Always verify behavior in a test environment
- Check compatibility with other security software that may conflict

## License

This project is licensed under the Apache License 2.0. For details, see the [LICENSE](./LICENSE) file.

## Version

Current version: **0.95.0**