# ADR-004: Windows Named Pipes for IPC

**Status**: Accepted

## Context

AgentGuard consists of three processes that must communicate:
1. **Daemon** (Windows Service) — the orchestrator that runs continuously
2. **CLI** (`agentguard.exe`) — short-lived commands: init, status, project, global, agent, daemon
3. **TUI** (`agentguard-tui.exe`) — long-lived terminal dashboard with real-time event streaming

The IPC mechanism must support:
- **Request/response**: CLI sends command, daemon responds with result
- **Streaming**: TUI subscribes to real-time events (audit, agent detected, ask prompts)
- **Security**: Only the local machine, only the current user's processes
- **Performance**: Low latency for CLI commands, high throughput for event streaming

## Decision

Use **Windows Named Pipes** (`\\.\pipe\agentguard`) as the sole IPC mechanism for
Phase 1, with SDDL security descriptor `D:P(A;;0x12019F;;;AU)` restricting access
to Authenticated Users with Read/Write only (not Full Control, not Everyone).

The protocol uses a 4-byte little-endian length prefix followed by a JSON payload,
supporting 20 request types and 6 streaming event types. Async multiplexing is
provided by `tokio`.

## Consequences

- **Windows-native**: No external dependencies, no network configuration, no port
  conflicts. Works on all supported Windows versions (10+).
- **SDDL security**: Only processes running as Authenticated Users on the same machine
  can connect. Anonymous and Guest accounts are excluded. No `Everyone` or `FullControl`
  grants.
- **Duplex streaming**: A single pipe connection supports bidirectional communication,
  enabling the TUI to send commands while receiving event streams.
- **Windows-only**: This is acceptable for Phase 1 (AgentGuard targets Windows first).
  A cross-platform IPC mechanism (Unix domain sockets) would be needed for future
  platform support.
- **Pipe namespace**: `\\.\pipe\agentguard` is a well-known name. If another application
  uses the same name, the daemon fails to start. This is documented.

### Protocol Details

- **Request**: 4-byte LE u32 length + UTF-8 JSON payload
- **Response**: 4-byte LE u32 length + UTF-8 JSON payload (same format)
- **Streaming**: After `SubscribeEvents` request, the pipe stays open and the daemon
  pushes events as they occur without explicit client requests
- **Connection model**: Multiple concurrent connections supported (CLI + TUI
  simultaneously). Each connection is handled in its own tokio task.

## Alternatives Considered

1. **TCP/IP (localhost)**: Rejected — adds network stack overhead for same-machine
   communication, requires port selection and conflict resolution, opens a firewall
   prompt on first run (bad UX).
2. **Unix domain sockets**: Rejected for Phase 1 — Windows support for Unix sockets
   is only available on Windows 10 build 17063+ (2018). Named pipes are supported on
   all Windows versions.
3. **Shared memory**: Rejected — complex synchronization (need mutex/semaphore),
   harder to implement streaming semantics, no built-in request/response framing.
4. **Windows RPC**: Rejected — overengineered for same-machine communication, requires
   IDL compilation, harder to debug.
5. **HTTP (localhost REST API)**: Rejected — polling for events (no push), higher
   latency, requires HTTP library dependency on both sides.
