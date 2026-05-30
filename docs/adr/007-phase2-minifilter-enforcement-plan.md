# 007 - Phase 2 Minifilter Enforcement Plan

## Context

Phase 1 hardening significantly improves deny enforcement in user-mode:

- mandatory deny patterns injected at runtime
- strict validation and fail-closed init
- continuous protection audits
- stronger Everyone DENY defaults

However, user-mode ACL and token-based controls cannot provide an absolute guarantee against all execution contexts. The product goal "no AI access to deny paths" requires kernel-level interception.

## Decision

Implement Phase 2 kernel minifilter enforcement as the authoritative deny gate for file access operations.

The minifilter becomes the source of truth for allow/deny decisions in the file path hot path, with daemon as policy oracle and audit orchestrator.

## Target behavior

When an AI process attempts denied access:

1. Minifilter intercepts I/O request before filesystem open/write/delete is completed.
2. Driver resolves normalized path and operation.
3. Driver requests decision from daemon over trusted kernel<->user channel.
4. Daemon evaluates policy layers and returns allow/deny/ask.
5. Driver enforces:
   - allow: pass through
   - deny: `STATUS_ACCESS_DENIED`
   - ask: block/pause pending daemon response (timeout => deny)

Result: no bypass through unrestricted tokens, stale ACEs, or process-classification timing windows.

## Scope (minimum)

### Driver interception points

- `IRP_MJ_CREATE` (open/read intent)
- `IRP_MJ_WRITE`
- `IRP_MJ_SET_INFORMATION` for delete/rename paths

### Process identity propagation

- kernel process callbacks propagate agent classification / provenance
- stable PID+start-time correlation to avoid PID reuse confusion
- driver sends `pid` to daemon with every query; daemon resolves to `AgentLabel` + `image_name` via tracker

### Per-agent policy overrides

Phase 2 enables per-agent rules from Phase 1 infrastructure to actually enforce:

- `agent_manifests: HashMap<String, CompiledManifest>` already compiled in daemon memory
- Driver sends `pid` → daemon looks up agent label + image name → evaluates per-agent rules **first**
- Priority: per-agent > global > project > default
- Examples:
  - `cursor.exe deny **/*.env` → cursor can never read .env files (regardless of project rules)
  - `opencode.exe read src/**` → opencode gets read-only access to src/, even if project allows write

Without minifilter, per-agent overrides are stored but inert (Phase 1 ACLs can't distinguish processes).

### Policy query channel

- `FltCreateCommunicationPort` / `FltSendMessage` based protocol
- explicit request structure:
  - process id
  - normalized absolute path
  - operation
  - correlation id
- explicit response structure:
  - decision
  - optional ask token
  - timeout semantics

### Fail-closed rules

- daemon unavailable => deny for mandatory deny scope
- protocol timeout => deny
- malformed request/response => deny

## Migration strategy

1. Keep current Phase 1 user-mode enforcement active as defense-in-depth.
2. Add feature-gated minifilter mode in daemon.
3. Shadow mode first (driver logs decisions but does not block) to compare against user-mode decisions.
4. Enforce mode when decision parity reaches acceptable threshold.
5. Retain CLI verification commands (`project verify`, doctor/go gate) for diagnostics.

## Verification checklist

### Functional

- denied read to `.env` returns `ACCESS_DENIED`
- denied read to `agentguard.toml` returns `ACCESS_DENIED`
- denied read under `.git/**` returns `ACCESS_DENIED`
- denied secret extension access (`*.pem`, `*.p12`, `*.pfx`, `*.key`) returns `ACCESS_DENIED`
- per-agent deny overrides project allow (cursor.exe deny beats project write)
- per-agent read overrides project write (opencode.exe read-only on src/ regardless)
- per-agent rules do NOT affect non-agent processes (git.exe ignore agent rules)
- ask prompts differentiate by agent (cursor.exe vs opencode.exe)

### Bypass resistance

- unrestricted process token cannot bypass
- admin-launched agent cannot bypass via ACL changes
- timing race between process detection and first file open does not bypass

### Reliability

- daemon restart behavior documented and tested
- ask flow timeout fail-closed
- no deadlocks under concurrent file operations

## Alternatives considered

1. **More user-mode hardening only**
   - rejected: cannot guarantee absolute enforcement across all contexts.
2. **ETW-only monitor + reactive blocking**
   - rejected: reactive model loses race against fast I/O.
3. **Driver-only static policy without daemon**
   - rejected: poor policy agility and ask-flow ergonomics.

## Consequences

Positive:

- strongest enforcement guarantees for deny paths
- consistent behavior independent of user token/shell context
- reduced attack surface for user-mode bypasses

Negative:

- driver development and signing complexity
- higher testing burden and release discipline
- operational complexity in kernel/user communications

