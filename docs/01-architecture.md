# 01 — Architecture & Data Flow

## Overview

AgentGuard is an OS-level security layer for Windows that controls what AI agents
(Claude Code, Cursor, OpenCode, Aider, Goose, etc.) can do on a machine or project.

It is **not** a wrapper, proxy, or IDE extension. It applies real Windows ACLs
(DENY ACEs + Mandatory Integrity Control) so the OS itself returns `ACCESS_DENIED`
to the agent.

## Stack

| Layer | Technology |
|-------|-----------|
| Core types & errors | Rust (zero external deps) |
| Manifest parsing | Rust (serde, toml, globset) |
| Policy engine | Rust (globset O(1) matching) |
| Persistence | SQLite via rusqlite (bundled) |
| Agent detection | Heuristic classifier (S1-S5) |
| OS enforcement | `SetNamedSecurityInfoW`, `AddMandatoryAce` (windows-sys) |
| IPC | Named pipes (Windows) / Unix domain sockets |
| Notifications | `MessageBoxW` (Windows) / terminal prompt |
| Daemon | Rust async (tokio) |
| CLI | clap derive |
| TUI | ratatui + crossterm |

## Crate Workspace

```
crates/
├── agentguard-core/         # Base types, errors, zero deps
├── agentguard-manifest/     # phylax.toml parser + GlobSet compiler
├── agentguard-policy/       # CompiledPolicy: global > project > default
├── agentguard-store/        # SQLite: crud, migrations, thread-safe
├── agentguard-probe/        # SubjectClassifier (5 signals) + SessionTracker
├── agentguard-enforce/      # DENY ACEs + MIC labels + Enforcer walkdir
├── agentguard-ipc/          # Named pipe bidirectional + codec
├── agentguard-notify/       # MessageBoxW (Win) / terminal prompt (Unix)
├── agentguard-audit/        # Writes AuditEvents to store
├── agentguard-daemon/       # Windows Service: orchestrates everything
├── agentguard-cli/          # CLI: init, status, project, global, audit, daemon
└── agentguard-tui/          # ratatui dashboard: 4 tabs

modules/
├── agentguard-scanner/      # Phase 3: AI code analysis
└── agentguard-team/         # Phase 4: team sync, dashboard

driver/
└── agentguard.sys           # Phase 2: C++ kernel minifilter
```

## Dependency Graph

```
core ← manifest ← policy ← (enforce, audit, probe, notify, ipc) ← daemon
                                                                    ← cli
                                                                    ← tui
```

Rules:
- `agentguard-core` depends on nothing from the workspace.
- `agentguard-manifest` and `agentguard-policy` are platform-agnostic.
- `agentguard-store` is platform-agnostic (rusqlite is cross-platform).
- `agentguard-probe` and `agentguard-enforce` are Windows-only.
- No crate imports `rusqlite` directly except `agentguard-store`.
- Module crates (Phase 3/4) cannot import `agentguard-enforce`, `agentguard-probe`, or `agentguard-daemon`.

## End-to-End Flow

```
User runs: agentguard init
  │
  ├─ 1. CLI creates phylax.toml (if missing)
  ├─ 2. CLI → IPC → daemon: RegisterProject
  ├─ 3. Daemon parses toml → CompiledManifest (GlobSets)
  ├─ 4. Daemon applies DENY ACEs to [deny] files (SetNamedSecurityInfoW)
  ├─ 5. Daemon applies MIC High + NO_WRITE_UP (AddMandatoryAce)
  ├─ 6. Daemon stores project in SQLite (watched_projects)
  └─ 7. Daemon starts ReadDirectoryChangesW watcher for hot-reload

Agent runs (e.g., claude.exe in project dir):
  │
  ├─ 8. Agent attempts to open .env
  ├─ 9. Windows kernel checks DACL → DENY Everyone → ACCESS_DENIED
  └─ 10. Agent cannot read .env

User edits phylax.toml:
  │
  ├─ 11. Watcher detects file change (< 1s)
  └─ 12. Daemon hot-reloads: recompiles GlobSets, re-applies ACEs

User runs: agentguard status
  │
  ├─ CLI → IPC → daemon: GetStatus
  ├─ Daemon queries SQLite (projects, events, blocks)
  └─ Daemon returns DaemonStatus → CLI displays

User runs: agentguard project off
  │
  ├─ CLI → IPC → daemon: DisableProtection
  ├─ Daemon removes DENY ACEs + MIC labels from [deny] files
  └─ User can now access files normally

User runs: agentguard project on
  │
  ├─ CLI → IPC → daemon: EnableProtection
  ├─ Daemon re-applies DENY ACEs + MIC labels to [deny] files
  └─ Agent is blocked again
```

## Permission Model

6 buckets, ordered by priority (lower number = higher priority):

| Priority | Bucket | Read | Write | Delete |
|----------|--------|------|-------|--------|
| 1 (max)  | deny   | ✗    | ✗     | ✗      |
| 2        | ask    | ?    | ?     | ?      |
| 3        | full   | ✓    | ✓     | ✓      |
| 4        | delete | ✓    | ✗     | ✓      |
| 5        | write  | ✓    | ✓     | ✗      |
| 6        | read   | ✓    | ✗     | ✗      |

**deny always wins**, even if a file also appears in write or full.

When a file matches no bucket, `default_mode` applies:
- `conservative`: Read=Allow, Write=Ask, Delete=Deny
- `unrestricted`: All operations = Allow

## Multi-Layer Anti-Bypass (Phase 1)

| Layer | Mechanism | Blocks |
|-------|-----------|--------|
| 1 | DENY ACE → Everyone → GENERIC_ALL | Read, write, delete |
| 2 | DENY ACE → Everyone → WRITE_DAC \| WRITE_OWNER \| DELETE | ACL modification, ownership change |
| 3 | MIC label → High Integrity (S-1-16-12288) + NO_WRITE_UP | Any write from Medium integrity processes (includes WRITE_DAC) |

Layer 3 prevents `icacls /remove:d` bypass: the agent runs at Medium integrity,
cannot write to High integrity objects even if it owns the file.

## Workspace Lints

```toml
[workspace.lints.rust]
unsafe_code = "deny"

[workspace.lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
```

Crates needing Windows FFI override with `#![allow(unsafe_code)]`:
- `agentguard-probe`
- `agentguard-enforce`
- `agentguard-daemon`
- `agentguard-notify`

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| SQLite over config file | Atomic writes, audit log queries, single .db file = complete system state |
| Named pipes over HTTP | Zero network config, same-machine only, Windows-native |
| GlobSet over regex | O(1) matching, standard glob syntax, `**` support |
| ACEs + MIC over minifilter (Phase 1) | No kernel driver, no EV cert needed, immediate value |
| Deny wins over allow | Security principle: fail-closed, never accidentally allow |
