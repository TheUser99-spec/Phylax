# 06 — IPC, Daemon & CLI

## IPC (`agentguard-ipc`)

### Transport

Named pipe on Windows (`\\.\pipe\agentguard`), Unix domain socket on Linux/macOS
(`/tmp/agentguard.sock`). The pipe name can be overridden via env var
`AGENTGUARD_IPC_PIPE` for testing.

### Codec

Length-prefixed JSON: 4 bytes (little-endian u32) + JSON payload. Maximum
message size: 4 MB.

```rust
// Encode
let bytes = protocol::encode(&request)?;
// -> [4 bytes LE length][JSON bytes]

// Decode
let request: IpcRequest = protocol::recv(&mut reader).await?;

// Send + recv via async reader/writer
protocol::send(&mut writer, &msg).await?;
let response: IpcResponse = protocol::recv(&mut reader).await?;
```

### Requests (CLI → Daemon)

| Request | Fields | Description |
|---------|--------|-------------|
| `RegisterProject` | `path` | Register a workspace |
| `UnregisterProject` | `path` | Remove workspace from watch |
| `ValidateProject` | `path` | Validate phylax.toml |
| `CheckFileAccess` | `path, op` | Dry-run policy evaluation |
| `GetStatus` | — | Get daemon status + stats |
| `Shutdown` | — | Stop the daemon |
| `ReloadPolicy` | `path` | Force reload of phylax.toml |
| `AskResponse` | `request_id, allowed, remember` | User response to ask prompt |
| `AddGlobalRule` | `bucket, pattern` | Add system-wide rule |
| `RemoveGlobalRule` | `id` | Remove system-wide rule |
| `ListGlobalRules` | — | List all system-wide rules |
| `EnableProtection` | `path` | Re-apply ACEs to workspace |
| `DisableProtection` | `path` | Remove ACEs from workspace |

### Responses (Daemon → CLI)

| Response | Fields | Description |
|----------|--------|-------------|
| `Ok` | — | Success |
| `Error` | `message` | Error description |
| `Status` | `DaemonStatus` | Daemon state + stats |
| `ProjectValidation` | `ValidationResult` | TOML validation result |
| `FileCheck` | `FileCheckResult` | Dry-run decision |
| `GlobalRulesList` | `GlobalRulesListData` | List of global rules |

### Client

```rust
let client = IpcClient::new();
// Or with custom pipe for testing:
let client = IpcClient::with_pipe("\\\\.\\pipe\\test");

client.register_project(path).await?;
client.get_status().await?;
client.check_file(path, "read".into()).await?;
client.shutdown().await?;
client.enable_protection(path).await?;
client.disable_protection(path).await?;
```

Timeout: 5 seconds per request. If the daemon is not running, returns `DaemonNotRunning`.

### Server

```rust
let handler: RequestHandler = Arc::new(|req| { /* handle */ });
let server = IpcServer::new(handler);
// Or with custom pipe:
let server = IpcServer::with_pipe(handler, pipe_name);

let (tx, rx) = mpsc::channel(1);
server.run(rx).await?;  // Blocks until shutdown signal
```

The server spawns a tokio task per connection. Each connection handles multiple
requests in a loop until the client disconnects or an error occurs.

## Daemon (`agentguard-daemon`)

### Entry Point (`main.rs`)

```rust
#[tokio::main]
async fn main() {
    let state = DaemonState::new(&db_path, shutdown_tx)?;
    let state = Arc::new(state);

    tokio::select! {
        result = server.run(shutdown_rx) => { ... }
        result = watcher::run_watcher(state, watcher_rx) => { ... }
        _ = tokio::signal::ctrl_c() => { ... }
    }
}
```

Runs IPC server, file watcher, and Ctrl+C handler concurrently via `tokio::select!`.
Whichever finishes first triggers graceful shutdown of the others.

### DaemonState (`orchestrator.rs`)

Thread-safe shared state. Cloneable (uses `Arc` internally).

```rust
pub struct DaemonState {
    pub store:          Arc<Store>,
    pub tracker:        Arc<AgentSessionTracker>,
    auditor:            Arc<Auditor>,
    projects:           Arc<RwLock<HashMap<PathBuf, ProjectEntry>>>,
    global_manifest:    Arc<RwLock<Option<CompiledManifest>>>,
    shutdown_tx:        Arc<mpsc::Sender<()>>,
}
```

#### Project Management

```rust
// Register: parse toml, compile manifest, store in DB, apply ACEs
state.register_project(workspace)?;

// Unregister: release ACEs, remove from DB
state.unregister_project(&workspace)?;

// Hot-reload: re-parse toml, re-compile, update DB
state.reload_project(&workspace)?;

// Toggle protections on/off
state.enable_protection(&workspace)?;
state.disable_protection(&workspace)?;
```

#### Access Evaluation

```rust
// Real evaluation (requires agent PID):
let decision = state.evaluate_access(pid, &path, &FileOp::Read);

// Dry-run evaluation (no PID needed):
let decision = state.evaluate_access_dry_run(&path, &FileOp::Read);
```

Evaluation order:
1. **Global rules**: if non-Allow, return immediately with `PolicySource::Global`
2. **Project rules**: find matching workspace, evaluate with cached manifest
3. **Default**: if path is in a project, use its `default_mode`; otherwise Allow

#### Global Rules

```rust
state.add_global_rule(Bucket::Deny, "*.env")?;
state.remove_global_rule(id)?;
// Automatically rebuilds global_manifest from DB after each change
```

### Handler (`handler.rs`)

Bridges IPC requests to `DaemonState`. All handlers wrap results in `IpcResponse`:

```rust
pub fn handle(state: Arc<DaemonState>, req: IpcRequest) -> IpcResponse {
    match handle_inner(state, req) {
        Ok(resp) => resp,
        Err(e) => IpcResponse::Error { message: e.to_string() },
    }
}
```

16 handlers: `RegisterProject`, `UnregisterProject`, `GetStatus`, `ValidateProject`,
`CheckFileAccess`, `Shutdown`, `ReloadPolicy`, `AskResponse`, `AddGlobalRule`,
`RemoveGlobalRule`, `ListGlobalRules`, `EnableProtection`, `DisableProtection`.

### Watcher (`watcher.rs`)

**Windows**: `ReadDirectoryChangesW` on each registered workspace directory.
When `phylax.toml` is modified, triggers `DaemonState::reload_project()`.

**Unix/dev**: File modification time polling every 500ms.

The watcher takes a snapshot of registered projects at startup. Currently does
not watch newly registered projects without a daemon restart.

## CLI (`agentguard-cli`)

14 commands, async via `#[tokio::main]`.

### Project Commands

```powershell
phylax init [--no-create]              # Create phylax.toml, register workspace
phylax status                          # Show daemon state, projects, agents, stats
phylax project validate [-p <path>]    # Validate phylax.toml
phylax project check -f <file> -o <op> # Dry-run policy check (op: read/write/delete)
phylax project show                    # Display current project policy
phylax project unregister [-p <path>]  # Remove workspace from watch
phylax project off [-p <path>]         # Temporarily disable protections
phylax project on [-p <path>]          # Re-enable protections
```

### Global Commands

```powershell
phylax global add <bucket> <pattern>   # Add system-wide rule
phylax global remove <id>              # Remove rule by ID
phylax global list                     # List all system-wide rules
```

### Daemon Commands

```powershell
phylax daemon start                    # Spawn daemon binary
phylax daemon stop                     # Send shutdown via IPC
phylax daemon restart                  # Stop + wait + start
```

### Audit Commands

```powershell
phylax audit list [--limit <N>]        # Show recent audit events
```

## TUI (`agentguard-tui`)

⏳ **Deferred to post-Phase 1.** The TUI crate exists with a functional ratatui
dashboard implementation (4 tabs: Status, Agents, Projects, Events) but is not
currently the focus of Phase 1 development. It will be finalized after the core
daemon, CLI, and enforcement pipeline are production-ready.

