# AgentGuard Deny Enforcement Audit (2026-05-29)

## Scope

This audit verifies effective protection of critical deny targets:

- `agentguard.toml`
- `.env`
- `.env.*`
- `.git/**`
- `**/*.key`
- `**/*.pem`
- `**/*.p12`
- `**/*.pfx`

Goal: ensure these paths are not practically accessible by AI agents under the current user-mode architecture.

---

## Root Cause Summary

Initial behavior allowed practical gaps despite deny policy:

1. Enforcement depended on restricted-token SID only in some paths.
2. `Everyone DENY` was not default-on.
3. `agentguard.toml` had special-case behavior that could weaken protection.
4. New deny files were not always protected immediately.
5. Path collection skipped deep files and filtered folders like `.git`, causing deny misses.
6. Validation tolerated critical deny omissions in TOML.

---

## Implemented Hardening

### 1) Runtime mandatory deny injection

Daemon now enforces mandatory deny patterns at runtime before compiling policy:

- `agentguard.toml`
- `.env`
- `.env.*`
- `.git/**`
- `**/*.key`
- `**/*.pem`
- `**/*.p12`
- `**/*.pfx`

Even if TOML omits these, daemon injects them and deduplicates.

### 2) Everyone DENY hardened

- `Everyone DENY` default behavior is enabled (with explicit opt-out env var).
- Applied consistently on register/reload/restore/enable.
- Kept active when agents exit if hardening mode is active.
- Applied to newly discovered deny files.

### 3) Deny path coverage fixed

Enforcement traversal now:

- Removes artificial depth limit.
- Stops skipping `.git` and other directories from deny evaluation.
- Still avoids symlink-follow traversal.

### 4) Verify command and IPC report

Added end-to-end protection audit:

- IPC request/response: `VerifyProtection` / `ProtectionReport`
- CLI command: `agentguard project verify`

Reports:

- full health count
- effective deny count (content + metadata deny)
- per-path unhealthy diagnostics

### 5) Fail-closed init and validation

- `agentguard init` now runs post-registration protection audit.
- By default, init aborts if deny coverage is unhealthy.
- Explicit insecure override: `--allow-unhealthy`.
- `project validate` now fails if mandatory deny patterns are missing from TOML.

---

## Verification Commands

Use these to verify behavior on a host:

```powershell
agentguard project validate
agentguard init
agentguard project verify
agentguard status
.\scripts\agentguard-doctor.ps1 -Workspace C:\Users\omkde\AgentGuard
.\scripts\agentguard-go.ps1 -Workspace C:\Users\omkde\AgentGuard
```

Doctor now consumes `agentguard project verify --json` and checks:

- `schema_version == 1`
- `effective_deny_paths == total_deny_paths`
- non-zero deny inventory expected for real projects

For tests in repo:

```powershell
cargo test -p agentguard-daemon -p agentguard-enforce
cargo test -p agentguard-ipc
cargo test -p agentguard-cli --bin agentguard
```

Note: `agentguard-cli` e2e tests require daemon pipe availability.

---

## Residual Risk (Architecture Limit)

Under user-mode ACL and token-based controls, absolute guarantee against every execution context is not possible.

For strict "no AI access in all contexts", kernel enforcement (Phase 2 minifilter path) is required.

Current state significantly hardens practical security in Phase 1 and adds continuous verification.
