# 02 — Core Types & Errors (`agentguard-core`)

Zero external dependencies. All types are `Serialize`/`Deserialize` via serde.

## Bucket — Permission Buckets

```rust
pub enum Bucket {
    Deny   = 1,  // Nothing allowed
    Ask    = 2,  // Prompt user
    Full   = 3,  // Read + write + delete
    Delete = 4,  // Read + delete (no write)
    Write  = 5,  // Read + write (no delete)
    Read   = 6,  // Read only
}
```

Lower number = higher priority. `Bucket::Deny.beats(&Bucket::Write)` returns `true`.

## FileOp — File Operations

```rust
pub enum FileOp {
    Read,
    Write,
    Delete,
}
```

## PolicyDecision — Evaluation Result

```rust
pub enum PolicyDecision {
    Allow,
    Deny,
    Ask {
        path: PathBuf,   // The file being accessed
        op:   FileOp,    // The attempted operation
    },
}
```

## DefaultMode — When No Bucket Matches

```rust
pub enum DefaultMode {
    Conservative,  // Read=Allow, Write=Ask, Delete=Deny
    Unrestricted,  // All=Allow
}
```

## AgentLabel — Classification Result

```rust
pub enum AgentLabel {
    Definite,   // S1 (env vars) or S2 (image name) matched
    Probable,   // S4 (non-interactive session)
    Inherited,  // S5 (child of a classified agent)
    Human,      // No signals matched
}
```

`label.is_agent()` returns `true` for Definite, Probable, and Inherited.

## PolicySource — Where a Decision Came From

```rust
pub enum PolicySource {
    Global,   // From global_rules table
    Project,  // From phylax.toml
    Default,  // From default_mode
}
```

## AgentEvent — Process Activity Event

```rust
pub struct AgentEvent {
    pub pid:       u32,
    pub label:     AgentLabel,
    pub image:     String,
    pub path:      PathBuf,
    pub op:        FileOp,
    pub workspace: Option<PathBuf>,
    pub timestamp: DateTime<Utc>,
}
```

## AuditEvent — Persisted Decision Record

```rust
pub struct AuditEvent {
    pub id:          Option<i64>,
    pub agent_pid:   u32,
    pub agent_label: AgentLabel,
    pub file_path:   PathBuf,
    pub operation:   FileOp,
    pub decision:    PolicyDecision,
    pub source:      PolicySource,
    pub timestamp:   DateTime<Utc>,
}
```

## AgentSession — Agent Process Lifecycle

```rust
pub struct AgentSession {
    pub id:         Option<i64>,
    pub pid:        u32,
    pub image_name: String,
    pub label:      AgentLabel,
    pub workspace:  Option<PathBuf>,
    pub started_at: DateTime<Utc>,
    pub ended_at:   Option<DateTime<Utc>>,
}
```

## GlobalRule — System-Wide Rule

```rust
pub struct GlobalRule {
    pub id:      Option<i64>,
    pub bucket:  Bucket,
    pub pattern: String,     // Glob pattern, e.g. C:\Users\*\.ssh\**
    pub created: DateTime<Utc>,
}
```

## WatchedProject — Registered Project

```rust
pub struct WatchedProject {
    pub id:            Option<i64>,
    pub root:          PathBuf,
    pub name:          String,
    pub registered_at: DateTime<Utc>,
    pub active:        bool,
}
```

## AskResponse — User Response to Ask Prompt

```rust
pub enum AskResponse {
    AllowOnce,     // Allow just this one access
    AllowSession,  // Allow for the rest of this agent session
    Deny,          // Deny this access
}
```

## GuardError — Error Enum

All errors are typed and implement `thiserror::Error`.

| Variant | Category | Description |
|---------|----------|-------------|
| `Database(String)` | Store | Generic DB error |
| `Migration { version, reason }` | Store | Migration failure |
| `ManifestParse(String)` | Manifest | TOML parse error |
| `InvalidGlob { pattern, reason }` | Manifest | Glob compilation error |
| `ManifestNotFound { path }` | Manifest | phylax.toml not found |
| `PolicyError(String)` | Policy | Evaluation error |
| `IpcConnect(String)` | IPC | Connection failed |
| `IpcSerialize(String)` | IPC | Serialization failed |
| `IpcTimeout { ms }` | IPC | Operation timed out |
| `IpcError(String)` | IPC | Generic IPC error |
| `DaemonNotRunning` | IPC | Daemon process not running |
| `EtwSession(String)` | Probe | ETW session error |
| `Classification(String)` | Probe | Classification logic error |
| `AceApply { path, reason }` | Enforce | ACE application failed |
| `AceRemove { path, reason }` | Enforce | ACE removal failed |
| `EnforcementFailed { path, reason }` | Enforce | Enforcement operation failed |
| `Notification(String)` | Notify | Notification delivery error |
| `Daemon(String)` | Daemon | Generic daemon error |
| `Io(std::io::Error)` | Generic | I/O error (from std) |
| `Internal(String)` | Generic | Internal/unexpected error |

## GuardResult

```rust
pub type GuardResult<T> = Result<T, GuardError>;
```

## default_decision()

```rust
pub fn default_decision(op: FileOp, path: PathBuf) -> PolicyDecision
```

Hardcoded conservative defaults. Used as fallback by the policy engine.
