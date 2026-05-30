# Contributing to AgentGuard

## Architecture Rules (MUST FOLLOW)

### Dependency DAG (inviolable)

```
core (0 external deps)
  ├─ manifest
  ├─ store
  ├─ policy
  ├─ probe, enforce, ipc, notify
  └─ daemon ──→ cli, tui
```

**NEVER**:
- Add a dependency from `manifest` to `enforce` or from any crate to a crate farther right in the DAG
- Add a circular dependency (e.g., `policy` ← `manifest`)
- Import from `daemon` into `core`, `manifest`, or `policy`
- Add dependencies to `agentguard-core` (it must remain zero-deps for portability)

### Realpath Security (CVE-2025-59829)

**ALWAYS canonicalize before glob match**:

```rust
// CORRECT
let canonical = std::fs::canonicalize(&path)?;
manifest.evaluate(&canonical, &op)?;

// WRONG (symlink bypass!)
manifest.evaluate(&path, &op)?;
```

`CompiledManifest::evaluate()` has a `debug_assert!` enforcing this contract.
Read [ADR-002](docs/adr/002-deny-aces-vs-minifilter-phase1.md) for the full context.

### Database Access

All database operations go through `agentguard-store`. No other crate imports `rusqlite`
directly. If you need to read or write data, add a method to `Store` in
`crates/agentguard-store/src/queries.rs`.

## Testing Requirements

### Before submitting a PR

- [ ] All tests pass: `cargo test --workspace`
- [ ] All lints pass: `cargo clippy --workspace --tests -- -D warnings`
- [ ] New functions have tests (target 80%+ coverage on new code)

### Security Gate (required before AI-agent sessions)

Run the deny-enforcement gate and ensure `GO`:

```powershell
.\scripts\agentguard-go.ps1 -Workspace C:\Users\omkde\AgentGuard
```

Manual equivalent:

```powershell
agentguard project validate
agentguard project verify --json
```

`project verify --json` must report:
- `schema_version = 1`
- `effective_deny_paths == total_deny_paths`

### Critical paths that MUST have tests

- Manifest parsing and compiled manifest evaluation
- Policy evaluation (global, project, default layers)
- Daemon orchestrator (evaluation, global rules, ask flow)
- IPC protocol (serialization, request/response roundtrips)
- SQLite store (CRUD operations, migrations)

### Running specific tests

```bash
cargo test --workspace                    # All tests
cargo test -p agentguard-manifest         # Manifest tests only
cargo test -p agentguard-daemon           # Daemon tests only
cargo test -p agentguard-policy           # Policy tests only
cargo test -p agentguard-audit            # Audit tests only
cargo test -p agentguard-store            # Store tests only
```

## Code Style

- No comments unless explaining non-obvious logic (the code documents itself)
- Use `GuardResult<T>` (alias for `Result<T, GuardError>`) for all fallible operations
- Use `recover_lock!()` macro for all `RwLock` accesses (handles poisoning)
- Prefer `debug_assert!` for security invariants (stripped in release, checked in tests)
- `unsafe` blocks must be justified and kept to a minimum (currently ~280 LOC / 10K+)

## Permission Model

6 buckets in descending priority:

| Priority | Bucket | Read | Write | Delete |
|----------|--------|------|-------|--------|
| 1 (max)  | deny   | No   | No    | No     |
| 2        | ask    | Prompt | Prompt | Prompt |
| 3        | full   | Yes  | Yes   | Yes    |
| 4        | delete | Yes  | No    | Yes    |
| 5        | write  | Yes  | Yes   | No     |
| 6        | read   | Yes  | No    | No     |

**deny ALWAYS wins**, even if the file also appears in write or full.
If a file doesn't appear in any bucket → `default_mode` applies:
- `conservative`: read=Allow, write=Ask, delete=Deny
- `unrestricted`: all Allow

4-layer evaluation precedence:
```
Global rules (system-wide)  ← highest
  ↓
Agent rules (per-image)     ← per executable
  ↓
Project rules (per-workspace) ← agentguard.toml
  ↓
Default (conservative/unrestricted)
```

## Project Structure

| Crate | Purpose | Portability |
|-------|---------|-------------|
| `agentguard-core` | Base types + errors | Cross-platform |
| `agentguard-manifest` | TOML parser + GlobSets | Cross-platform |
| `agentguard-policy` | Policy engine (global > project) | Cross-platform |
| `agentguard-store` | SQLite storage | Cross-platform |
| `agentguard-probe` | ETW + process classification | Windows-only |
| `agentguard-enforce` | DENY ACEs + Job Objects | Windows-only |
| `agentguard-ipc` | Named pipe protocol | Windows-only |
| `agentguard-notify` | Toast notifications | Windows-only |
| `agentguard-audit` | Audit event logging | Cross-platform |
| `agentguard-daemon` | Windows Service orchestrator | Windows-only |
| `agentguard-cli` | CLI tool | Cross-platform |
| `agentguard-tui` | Terminal dashboard | Cross-platform |

## Architecture Decision Records

All significant architectural decisions are documented in [docs/adr/](docs/adr/).
Read them before proposing changes to the core architecture.
To add a new ADR, use the template in [docs/adr/README.md](docs/adr/README.md) and
follow the rule: **only add, never delete**.
