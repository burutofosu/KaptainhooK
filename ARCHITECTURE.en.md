# Architecture

English | [日本語](ARCHITECTURE.md)

## Overview

KaptainhooK combines hexagonal architecture (ports & adapters) with layered architecture.  
Domain logic is kept free of external dependencies, while Windows-specific behavior is implemented at the outer layers.

## Layered structure (actual layout)

```
Domain (std only)
  ↓
Engine (Domain only)
  ↓
Application (Domain + Engine)
  ↓
Composition (DI / wiring root)
  ↓
Infrastructure / UI (port implementations)
  ↓
Apps (executables)
```

## Responsibilities by layer (summary)

- **Domain (`domain/kh-domain`)**
  - Rules and value objects (Target/Policy/Reaction/Signature/PathHint, etc.)
  - Port definitions (IFEO/Config/Targets/Signature/Clock/Log/Task/IPC/Launcher, etc.)
  - Pure decision logic (reaction/threat/ownership)

- **Engine (`engine/kh-engine`)**
  - Workflows for IFEO install/cleanup/conflict detection/backup restore

- **Application (`application/kh-app`)**
  - Guard/admin use cases assembled on top of ports

- **Composition (`composition/kh-composition`)**
  - Dependency injection
  - Runtime wiring for service/guard/restore tasks

- **Infrastructure (`infrastructure/*`)**
  - Windows-specific implementations (registry/signature/fs/task/ipc/path, etc.)

- **UI (`ui/*`)**
  - Guard UI, common messages, i18n, WebView2 settings UI helpers

- **Apps (`apps/*`)**
  - Executables (bootstrap/guard/service/restore/setup/cli/settings/tray/uninstall)

## Key flows (short)

### Install
1. `kh-setup` places binaries under Program Files / ProgramData
1. Detect conflicts → register IFEO (both 32/64 views)
1. Register `KaptainhooKRestore` task
1. Install and start `KaptainhooKService`
1. Save `config.json`, write Targets/TrustedHashes to HKLM

### Runtime (IFEO)
1. Target exe starts → IFEO launches `kh-bootstrap`
1. `kh-bootstrap` launches `kh-guard` from the same directory (no PATH dependency)
1. `kh-guard` reads config, collects parent/grandparent info, classifies
1. Reaction/policy evaluation, warning/prompt if needed
1. If allowed: service bypass → temporary IFEO removal
1. Launch original executable → restore IFEO

### Restore / Uninstall
1. Service TTL + restore task provide redundant IFEO recovery
1. Uninstall can restore from UninstallState backups

## Security boundaries (key points)

- **IPC validation**: `\\.\pipe\KaptainhooKService` validates guard identity (path + hash)
- **Owned/Foreign classification**: IFEO Debugger values are classified to avoid unsafe actions
- **UNC rejection / path normalization**: UNC and relative paths are rejected
- **No PATH lookup**: bootstrap → guard uses same-directory fixed path

## Purpose of this document

- Provide a concise view of layering and responsibilities
- Help locate where implementations live
- For details, see README or source code
