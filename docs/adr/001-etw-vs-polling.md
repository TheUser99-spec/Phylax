# ADR-001: ETW vs Polling for AI Agent Detection

**Status**: Accepted

## Context

AgentGuard Phase 1 needs real-time detection of AI agent processes (e.g., cursor.exe,
claude.exe) to trigger file system protections (DENY ACEs) before the agent can access
sensitive files.

Two approaches were evaluated:
1. **ETW (Event Tracing for Windows)** — kernel-level process creation events via
   `Microsoft-Windows-Kernel-Process` provider. Zero latency, push-based.
2. **Polling** — enumerate the process list every N milliseconds. Pull-based,
   with a detection window between polls.

## Decision

Use a **hybrid: ETW + 750ms polling** with automatic fallback to polling-only on
systems where ETW is unavailable (old Windows versions, restricted environments,
non-admin execution contexts).

- ETW provides the primary signal via `ferrisetw` crate (v0.1)
- Polling runs at 750ms as a safety net, catching processes that ETW may miss
- If ETW fails to initialize, polling runs at 500ms as the sole mechanism

## Consequences

- Near real-time detection via ETW (process creation → classification → ACE application
  within milliseconds)
- 750ms worst-case detection window when a process slips past ETW
- Graceful degradation on restricted systems
- `ferrisetw` v0.1 is less mature than other dependencies, but it is isolated in
  `agentguard-probe` and can be swapped without affecting other crates
- The ETW session name `AgentGuard-ProcessMonitor` may conflict with other ETW consumers
  (documented limitation)

## Alternatives Considered

1. **ETW-only**: Rejected — no fallback for systems without ETW support. Would exclude
   older Windows 10 builds and certain CI environments.
2. **Polling-only**: Rejected — 750ms gap between polls gives agents a window to
   read/write files before detection. For a tool that positions itself as a security
   product, this latency is unacceptable as the primary detection mechanism.
3. **Minifilter (kernel driver)**: Deferred to Phase 2. Would provide true real-time
   interception but requires kernel driver signing (EV certificate) and significantly
   more complex deployment. Phase 1 ships user-mode only to maximize install base.
4. **Windows Filtering Platform (WFP)**: Rejected — designed for network filtering,
   not suitable for file system interception.
