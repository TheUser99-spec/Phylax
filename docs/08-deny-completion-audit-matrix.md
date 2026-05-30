# Deny Security Completion Audit Matrix (2026-05-29)

## Objective under audit

Protect critical deny targets from AI-agent access:

- `agentguard.toml`
- `.env`, `.env.*`
- `.git/**`
- `**/*.key`, `**/*.pem`, `**/*.p12`, `**/*.pfx`

## Requirement-by-requirement evidence

| Requirement | Current status | Evidence source | Verification command |
|---|---|---|---|
| Deny patterns must be enforced even if omitted in TOML | **Implemented** | Runtime mandatory deny injection in daemon/orchestrator and handler validations | `cargo test -p agentguard-daemon` |
| `project validate` must fail when critical deny patterns are missing | **Implemented** | Handler strict validation errors for missing mandatory deny patterns | `agentguard project validate` |
| Deny traversal must include deep paths and `.git/**` | **Implemented** | Enforcer path collection updated + tests for deep files and `.git` | `cargo test -p agentguard-enforce` |
| New deny files should be protected promptly | **Implemented** | Daemon `protect_new_file` path hardening and Everyone flow | `cargo test -p agentguard-daemon` |
| Post-init should fail-closed on unhealthy deny protections | **Implemented** | CLI `init` protection audit with default abort | `agentguard init` |
| Manual audit command should report effective deny coverage | **Implemented** | `project verify` + JSON report with effective counts | `agentguard project verify --json` |
| Machine-readable audit contract must be stable | **Implemented** | `schema_version` in report JSON | `agentguard project verify --json` |
| Operational go/no-go gate before AI sessions | **Implemented** | `agentguard-doctor.ps1` + `agentguard-go.ps1` | `.\scripts\agentguard-go.ps1 -Workspace C:\Users\omkde\AgentGuard` |
| Dry-run check should not be misleading for unregistered projects | **Implemented** | Handler loads manifest directly and applies mandatory deny in dry-run path | `cargo test -p agentguard-daemon` |
| Absolute guarantee against all execution contexts | **Not fully achievable in Phase 1** | User-mode architecture limitation documented, kernel plan ADR added | `docs/adr/007-phase2-minifilter-enforcement-plan.md` |

## Current acceptance criteria for Phase 1

Treat the environment as **secure-to-run agents** only when all are true:

1. `agentguard project validate` returns success.
2. `agentguard project verify --json` shows:
   - `schema_version == 1`
   - `effective_deny_paths == total_deny_paths`
3. `.\scripts\agentguard-go.ps1 -Workspace C:\Users\omkde\AgentGuard` returns `GO`.

## Residual risk statement

Even with all Phase 1 controls passing, absolute universal non-access across every possible context (including privileged/kernel-edge bypass classes) requires Phase 2 minifilter enforcement.

