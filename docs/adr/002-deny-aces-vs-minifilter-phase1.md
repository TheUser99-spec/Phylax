# ADR-002: DENY ACEs vs Minifilter for Phase 1 Enforcement

**Status**: Accepted

## Context

AgentGuard must prevent AI agent processes from reading, writing, or deleting files
that match deny rules in the project's `agentguard.toml`. Two enforcement mechanisms
were considered for Phase 1:

1. **DENY ACEs (Access Control Entries)** — Append `ACCESS_DENIED_ACE` entries to
   the file's discretionary access control list (DACL), targeting the `Everyone` SID.
   Combined with Mandatory Integrity Control (MIC) labels at High integrity with
   `NO_WRITE_UP` flag.
2. **Minifilter kernel driver** — A file system minifilter that intercepts all I/O
   requests before they reach the file system, making decisions in kernel mode.

## Decision

Phase 1 uses **DENY ACEs only** (user-mode enforcement). The minifilter kernel driver
is deferred to Phase 2.

The ACE approach applies two types of access control:
1. **DACL DENY ACE** — `GENERIC_ALL` for content + `WRITE_DAC | WRITE_OWNER | DELETE`
   for metadata protection
2. **MIC label** — High integrity with `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` to prevent
   medium-integrity processes (where AI agents run) from writing to protected files

## Consequences

- Deployable immediately without kernel driver installation or EV code signing certificate
- User-mode only means the daemon does not need admin privileges for ACE application
  (though MIC labels require elevated permissions — see known limitation)
- ACEs can be theoretically removed by an admin or a process running at High integrity,
  but standard AI agents run at Medium integrity and cannot modify ACLs
- Audit timestamps are stored in SQLite, which is user-writable (not tamper-proof)
- Phase 2 minifilter will provide kernel-level enforcement where ACEs cannot be removed
  and audit logging is tamper-proof

### Known Limitation

MIC label application requires `SeSecurityPrivilege`, which is not available to
non-elevated processes. If the daemon is not running as admin, MIC labels cannot be
applied. The `apply_deny_ace` function includes a TOCTOU-protected retry loop (3 attempts,
10ms delay) with post-application verification via `verify_ace`. If MIC application
fails, `verify_ace` returns unhealthy status and the operation fails.

This limitation is accepted for Phase 1. Phase 2's minifilter eliminates this constraint.

## Alternatives Considered

1. **Minifilter only**: Rejected for Phase 1 — requires EV certificate ($300-500/year),
   kernel driver installation (admin + reboot), and significantly more development time.
   Would delay Phase 1 release by 6+ months.
2. **ACEs without MIC**: Rejected — without MIC, medium-integrity processes could
   potentially bypass DACL DENY ACEs through certain Windows security mechanisms.
   MIC provides defense-in-depth.
3. **AppLocker / Windows Defender Application Control**: Rejected — too broad, not
   file-level granular, requires Group Policy configuration.
4. **API hooking (Detours)**: Rejected — fragile, version-dependent, anti-virus flags.
