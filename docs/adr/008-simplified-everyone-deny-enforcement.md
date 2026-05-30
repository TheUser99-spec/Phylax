# ADR 008: Simplified Everyone DENY Enforcement

**Status**: Accepted  
**Date**: 2026-05-29  
**Replaces**: ADR 002 (DENY ACEs + MIC + broker model)

---

## Context

Phase 1 enforcement used a three-layer model:

| Layer | Mechanism | SID | Problem |
|-------|-----------|-----|---------|
| 1. DACL | DENY ACEs | `S-1-5-12` (RESTRICTED) | Only works with brokered processes |
| 2. MIC | Mandatory Integrity Control | `S-1-16-12288` (High) | Requires admin (`SeSecurityPrivilege`) |
| 3. Everyone | DENY ACEs (opt-in) | `S-1-1-0` | Behind env var gate |

To make layer 1 work, an IFEO broker (`agentguard-spawn`) intercepted AI agent launches and injected a restricted token. This was fragile:

- `CreateProcessWithTokenW` failed with error 87/1314 on standard Windows configs
- MIC failed on 100% of files (error 1314) without admin, flooding logs with warnings
- The broker required admin to install registry hooks
- The broker could break process launch entirely (FAIL-CLOSED)

Users couldn't actually enforce `[deny]` rules because no process carried `S-1-5-12` in its token.

## Decision

**Replace the three-layer model with a single Everyone DENY ACE layer.**

- DENY ACEs are applied for `S-1-1-0` (Everyone) — always, unconditionally
- MIC is removed entirely
- The IFEO broker (`agentguard-spawn`) is removed from the workspace
- The quarantine SID (`S-1-5-12`) is removed
- `AGENTGUARD_EVERYONE_DENY` env gate is removed (always on)

### Benefits

1. **No admin required** — DENY ACEs on user-owned files work without elevation
2. **No process interference** — no registry hooks, no token manipulation, no process creation interception
3. **Zero warnings** — no MIC error 1314 flooding the console
4. **Predictable behavior** — if a file is in `[deny]`, it's blocked for everyone
5. **~450 lines removed** — simpler codebase

### Trade-offs

1. **User is also blocked** — the human user cannot access deny files directly. The daemon temporarily lifts ACEs when it needs to read `agentguard.toml`. For manual access, use:
   ```bash
   agentguard project off    # Temporarily remove all ACEs
   agentguard project on     # Re-apply all ACEs
   ```

2. **No defense-in-depth** — MIC labels are gone, so the protection is single-layer (DACL only). A kernel driver (Phase 2 minifilter) would restore depth.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  agentguard-daemon                                       │
│                                                          │
│  [Enforcer]                                              │
│    │                                                     │
│    ├─ apply_project_protections(manifest)                │
│    │   └─ for each file in [deny]:                       │
│    │       └─ apply_deny_ace(path)   ← Everyone S-1-1-0 │
│    │           ├─ GetNamedSecurityInfoW (read DACL)      │
│    │           ├─ SetEntriesInAclW   (add 2 DENY ACEs)   │
│    │           └─ SetNamedSecurityInfoW (write DACL)     │
│    │                                                     │
│    └─ release_project_protections(manifest)              │
│        └─ for each file: remove_deny_ace(path)           │
│                                                          │
│  [Self-protection]                                       │
│    └─ with_everyone_toml_read_access()                   │
│        ├─ verify_ace() → check if protected              │
│        ├─ temporarily_allow() → remove DENY ACE          │
│        ├─ read TOML                                      │
│        └─ reapply_ask() → reapply DENY ACE               │
└──────────────────────────────────────────────────────────┘
```

### ProtectionHealth (simplified)

```rust
struct ProtectionHealth {
    exists: bool,        // file present on disk
    content_deny: bool,  // GENERIC_ALL_EXCEPT_PERM_CHANGE DENY for Everyone
    metadata_deny: bool, // DELETE DENY for Everyone
}
// healthy = exists && content_deny && metadata_deny
```

### ACE details

Two DENY ACEs per file for `S-1-1-0`:

| ACE | Mask | Purpose |
|-----|------|---------|
| Content | `0x001101FF` (GENERIC_ALL_EXCEPT_PERM_CHANGE) | Blocks read, write, execute |
| Metadata | `DELETE` | Blocks deletion |

---

## Files Changed

### Deleted
| File | Reason |
|------|--------|
| `crates/agentguard-enforce/src/sid.rs` | All SID building now inline in `ace.rs` |
| `crates/agentguard-cli/src/cmd/protection.rs` | IFEO hooks, elevate, is_admin — no longer needed |

### Rewritten
| File | Changes |
|------|---------|
| `crates/agentguard-enforce/src/ace.rs` | Removed MIC (~130 lines), unified quarantine→Everyone, removed dupes. From 936→~310 lines. |
| `crates/agentguard-enforce/src/coordinator.rs` | Removed `apply_everyone_protections`, `release_everyone_protections`, `temporarily_allow_everyone`, `reapply_everyone`. All methods now use Everyone ACEs directly. |

### Simplified
| File | Changes |
|------|---------|
| `crates/agentguard-daemon/src/orchestrator.rs` | Removed `everyone_deny_enabled()` + 3 tests, removed conditional everyone calls, simplified `protect_all_projects`/`release_all_projects`/`protect_new_file`/`load_project_entry`/`register_project`/`reload_project`. |
| `crates/agentguard-daemon/src/handler.rs` | Removed `check_ifeo_broker_active()` (~65 lines), removed broker warnings, simplified IPC read. |
| `crates/agentguard-ipc/src/protocol.rs` | Removed `everyone_deny_enabled` and `broker_active` from `ProtectionReportData`. Removed `mic_high_no_write_up` from `ProtectionPathHealth`. |
| `crates/agentguard-cli/src/cmd/init.rs` | Removed `with_protection` parameter and `install_protection()` function. |
| `crates/agentguard-cli/src/main.rs` | Removed `--no-protection` flag and related tests. |
| `Cargo.toml` | Removed `agentguard-spawn` from workspace members. |

---

## How to use

### Quick start
```bash
cd my-project
cargo run -p agentguard-cli --release -- init
cargo run -p agentguard-daemon --release
```

### Blocking files
In `agentguard.toml`:
```toml
[deny]
files = [
    ".env",
    "**/*.key",
    "**/*.pem",
    ".git/**",
    "secrets/**",
]
```

### Temporarily disabling protection
```bash
agentguard project off    # Remove all DENY ACEs (you can access files)
agentguard project on     # Re-apply all DENY ACEs
```

### Verify protection status
```bash
agentguard project verify
```
Shows per-file health: `exists`, `content_deny`, `metadata_deny`, `effective_deny`.

### Dry-run file access check
```bash
agentguard project check -f .env -o read
```
Returns: Allow / Deny / Ask based on current policy.

---

## What was removed (and why)

| Removed | Reason |
|---------|--------|
| IFEO broker (`agentguard-spawn`) | Fragile, required admin, caused error 87/1314 on launch |
| MIC labels (`apply_mic_label`) | Required admin (`SeSecurityPrivilege`), failed on 100% of files, flooded logs |
| Quarantine SID (`S-1-5-12`) | No process carried it without broker |
| `AGENTGUARD_EVERYONE_DENY` env gate | Everyone DENY is now the default |
| `--no-protection` / `--with-protection` flags | Protection is always active |
| `ProtectionReportData.broker_active` | Broker concept removed |
| `ProtectionReportData.everyone_deny_enabled` | Always true now |
