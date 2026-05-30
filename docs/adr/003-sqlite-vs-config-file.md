# ADR-003: SQLite for Audit & Rules Storage

**Status**: Accepted

## Context

AgentGuard needs persistent storage for:
- Global rules (system-wide deny/ask/full/delete/write/read patterns)
- Per-agent rules (cursor.exe vs claude.exe specific patterns)
- Audit events (every file access decision: allow, deny, ask)
- Agent session tracking (when agents start/stop, which workspace they're in)
- Ask decisions (user responses to [ask] prompts with optional "remember" persistence)
- Project registration (which workspaces are protected)
- Settings (key-value daemon configuration)

Two storage approaches were evaluated:
1. **SQLite** — embedded relational database with SQL query capabilities
2. **Config files (TOML/JSON/YAML)** — flat files in the filesystem

## Decision

Use **SQLite** via the `rusqlite` crate as the sole persistent storage mechanism,
exposed through `agentguard-store`. No other crate in the workspace imports `rusqlite`
directly.

The database uses WAL journal mode for concurrent read/write performance, with
`busy_timeout = 1000ms` to handle contention gracefully.

## Consequences

- **ACID compliance**: Rule changes (global, agent, project) are atomic. If the daemon
  crashes mid-write, the database is never corrupted.
- **Query capabilities**: Audit reports (events by agent, by file, by decision, by
  time range) are simple SQL queries. Without SQL, generating reports would require
  scanning flat files.
- **Single-file deployment**: The entire system state is one `.db` file at
  `%APPDATA%\AgentGuard\agentguard.db`. Backup, migration, and inspection are trivial.
- **Cross-platform**: `rusqlite` bundles SQLite, works identically on Windows, macOS,
  and Linux.
- **Migration system**: Schema changes are versioned (3 migrations in Phase 1),
  applied automatically on startup. No manual migration steps for users.
- **Fallback paths**: If `%APPDATA%` is unavailable, falls back to `%LOCALAPPDATA%`
  → `%USERPROFILE%` → current directory.

## Alternatives Considered

1. **TOML config files**: Rejected — no transactional guarantees. If the CLI writes
   a rule while the daemon reads it (race condition), the file could be corrupted or
   partially written. No query language for audit reports.
2. **JSON files**: Same problems as TOML, plus no schema enforcement.
3. **Windows Registry**: Rejected — Windows-only (AgentGuard may support other platforms
   in the future), no query language, harder to inspect/debug.
4. **LMDB / RocksDB**: Rejected — overengineered for this use case. AgentGuard's write
   volume is low (hundreds of audit events per session, not millions). SQLite handles
   this comfortably.
5. **PostgreSQL / external database**: Rejected — zero-config deployment is a hard
   requirement for Phase 1. An external DB server would be a barrier to adoption.
