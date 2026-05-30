# AgentGuard

AgentGuard is a Windows-first security layer for AI coding agents. It enforces what agents can read, write, or delete using explicit policy buckets and OS-level controls.

## What is in this repository

- Rust workspace for policy, store, detection, IPC, daemon, CLI, and TUI.
- C++ kernel driver folder for Phase 2 (`driver/`).
- Future modules (`modules/agentguard-scanner`, `modules/agentguard-team`).

## Permission model

Priority order:

`deny > ask > full > delete > write > read > default`

Defaults:
- `conservative`: read Allow, write Ask, delete Deny
- `unrestricted`: Allow all

`deny` always wins.

## Current architecture (Phase 1/1.5 codebase)

- Process detection and classification in `agentguard-probe`
- Policy compilation/evaluation in `agentguard-manifest` + `agentguard-policy`
- Persistence and schema ownership in `agentguard-store`
- Enforcement logic in `agentguard-enforce`
- Named pipe protocol in `agentguard-ipc`
- Orchestration in `agentguard-daemon`
- User surfaces in `agentguard-cli` and `agentguard-tui`

## Verified workspace members (2026-05-29)

From root `Cargo.toml`:

- `agentguard-core`
- `agentguard-manifest`
- `agentguard-policy`
- `agentguard-store`
- `agentguard-probe`
- `agentguard-enforce`
- `agentguard-ipc`
- `agentguard-notify`
- `agentguard-audit`
- `agentguard-daemon`
- `agentguard-cli`
- `agentguard-tui`
- `agentguard-mascot`

Repository crate not currently listed in workspace members:
- `agentguard-spawn`

## Verified test inventory (2026-05-29)

Counts below come from `cargo test -p <crate> -- --list`.

| Crate | Listed tests |
|---|---:|
| agentguard-core | 5 |
| agentguard-manifest | 48 |
| agentguard-policy | 8 |
| agentguard-store | 16 |
| agentguard-probe | 27 |
| agentguard-enforce | 11 |
| agentguard-ipc | 28 |
| agentguard-notify | 1 |
| agentguard-audit | 5 |
| agentguard-daemon | 22 |
| agentguard-cli | 38 |
| agentguard-tui | 0 |
| agentguard-mascot | 1 |

Observed execution status in this environment:
- `cargo test --workspace` is not fully green in a plain shell run.
- `agentguard-cli` e2e tests require a running daemon pipe (`\\.\pipe\agentguard`), otherwise they fail.
- Some `agentguard-enforce` tests are privilege-sensitive and can fail with `SetNamedSecurityInfoW DACL: 5`.

## Practical commands

```bash
cargo build --workspace
cargo test --workspace
cargo test -p agentguard-manifest
cargo test -p agentguard-store
cargo run -p agentguard-daemon
cargo run -p agentguard-cli -- status
cargo run -p agentguard-tui
```

## Documentation map

- Architecture overview: `docs/01-architecture.md`
- Core types: `docs/02-core-types.md`
- Manifest and policy: `docs/03-manifest-policy.md`
- Storage and audit: `docs/04-storage-audit.md`
- Detection and enforcement: `docs/05-detection-enforcement.md`
- IPC and daemon/CLI: `docs/06-ipc-daemon-cli.md`
- ADR index: `docs/adr/README.md`

## Notes for contributors

- Preserve dependency direction (`core` at the bottom, app crates at the top).
- Canonicalize filesystem paths before policy matching.
- Route all DB changes through `agentguard-store`.
- Avoid modifying `driver/` and `modules/` unless explicitly requested.
