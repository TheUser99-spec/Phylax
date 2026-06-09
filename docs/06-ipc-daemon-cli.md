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
| `CheckFileAccess` | `path, op, agent_image?` | Dry-run policy evaluation (supports per-agent) |
| `GetStatus` | — | Get daemon status + stats |
| `Shutdown` | — | Stop the daemon |
| `ReloadPolicy` | `path` | Force reload of phylax.toml |
| `AskResponse` | `request_id, allowed, remember` | User response to ask prompt |
| `AddGlobalRule` | `bucket, pattern` | Add system-wide rule |
| `RemoveGlobalRule` | `id` | Remove system-wide rule |
| `ListGlobalRules` | — | List all system-wide rules |
| `EnableProtection` | `path` | Re-apply ACEs to workspace |
| `DisableProtection` | `path` | Remove ACEs from workspace |
| `AddAgentRule` | `agent_image, bucket, pattern` | Add per-agent rule |
| `RemoveAgentRule` | `id` | Remove per-agent rule |
| `ListAgentRules` | — | List all per-agent rules |
| `ListAgents` | — | List classified agents |
| `GetStats` | — | Fetch daemon statistics |
| `GetPolicy` | `path` | Fetch policy for workspace |
| `VerifyProtection` | `path` | Verify ACEs applied to a file |
| `GetComplianceStatus` | `standard` | Check compliance against a standard |
| `GetComplianceReport` | `standard, format` | Generate full compliance report |
| `ExportAuditLog` | `format, filter?, limit?` | Export audit logs (csv, json, ocsf, cef, txt) |
| `GetAuditEvents` | `cursor?, limit, filter?` | Paginated audit event retrieval |
| `VerifyAuditIntegrity` | — | Verify audit log hash-chain integrity |
| `DiscoverMcpServers` | — | Scan for MCP server configs |
| `GetMcpRules` | — | List MCP governance rules |
| `AddMcpRule` | `server_name, action` | Add MCP server governance rule |
| `RemoveMcpRule` | `id` | Remove MCP governance rule |
| `CheckDexStatus` | — | Evaluate data exfiltration risk |

### Responses (Daemon → CLI)

| Response | Fields | Description |
|----------|--------|-------------|
| `Ok` | — | Success |
| `Error` | `message` | Error description |
| `Status` | `DaemonStatus` | Daemon state + stats |
| `ProjectValidation` | `ValidationResult` | TOML validation result |
| `FileCheck` | `FileCheckResult` | Dry-run decision |
| `GlobalRulesList` | `GlobalRulesListData` | List of global rules |
| `AgentRulesList` | `AgentRulesListData` | List of per-agent rules |
| `AgentList` | `AgentListData` | List of classified agents |
| `Stats` | `StatsData` | Daemon performance statistics |
| `Policy` | `PolicyData` | Workspace policy data |
| `ProtectionReport` | `ProtectionReportData` | File protection status |
| `ComplianceStatus` | `ComplianceStatusData` | Compliance standing per standard |
| `ComplianceReport` | `ComplianceReportData` | Full compliance report |
| `AuditEvents` | `AuditEventsData` | Paginated audit events |
| `AuditIntegrity` | `IntegrityReportData` | Hash-chain verification result |
| `McpDiscovery` | `McpDiscoveryData` | MCP server discovery results |
| `McpRulesList` | `McpRulesListData` | MCP governance rules |
| `DexStatus` | `DexStatusData` | Data exfiltration risk assessment |

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

30+ handlers: covers all request types above — project CRUD, file access checks, global/agent rules,
protection toggles, status/stats, audit export/events/integrity, compliance reports,
MCP server discovery/governance, and DEX data exfiltration checks.

### Watcher (`watcher.rs`)

**Windows**: `ReadDirectoryChangesW` on each registered workspace directory.
When `phylax.toml` is modified, triggers `DaemonState::reload_project()`.

**Unix/dev**: File modification time polling every 500ms.

The watcher takes a snapshot of registered projects at startup. Currently does
not watch newly registered projects without a daemon restart.

## CLI (`agentguard-cli`)

25+ commands, async via `#[tokio::main]`.

### Project Commands

```powershell
phylax init [--no-create]              # Create phylax.toml, register workspace
phylax status                          # Show daemon state, projects, agents, stats
phylax project validate [-p <path>]    # Validate phylax.toml
phylax project check -f <file> -o <op> # Dry-run policy check (op: read/write/delete)
phylax project check -f <f> -o <op> -a <agent> # Per-agent dry-run check
phylax project show                    # Display current project policy
phylax project unregister [-p <path>]  # Remove workspace from watch
phylax project off [-p <path>]         # Temporarily disable protections
phylax project on [-p <path>]          # Re-enable protections
phylax project verify                  # Audit protection coverage
```

### Global Rules

```powershell
phylax global add <bucket> <pattern>   # Add system-wide rule
phylax global remove <id>              # Remove rule by ID
phylax global list                     # List all system-wide rules
```

### Agent Rules

```powershell
phylax agent add <image> <bucket> <pattern>  # Add per-agent rule
phylax agent remove <id>                     # Remove per-agent rule
phylax agent list                            # List all per-agent rules
```

### Daemon Commands

```powershell
phylax daemon start                    # Spawn daemon binary
phylax daemon stop                     # Send shutdown via IPC
phylax daemon restart                  # Stop + wait + start
phylax run                             # Start daemon + TUI dashboard
phylax serve [--port <p>]             # Start daemon + web dashboard (default :1977)
phylax start [--port <p>]             # Alias for `phylax serve`
```

### Compliance Commands

```powershell
phylax compliance list                          # List available standards
phylax compliance status [--standard <s>]       # Daemon compliance check
phylax compliance evaluate [--standard <s>]     # Offline compliance evaluation
phylax compliance generate [--standard <s>]     # Generate compliance report (json/md)
phylax compliance check-gaps [--standard <s>]   # Find compliance gaps
```

### MCP Governance Commands

```powershell
phylax mcp discover                    # Discover MCP servers on this system
phylax mcp list                        # List MCP governance rules
phylax mcp add <name> <action>         # Add MCP server rule (deny/ask/read)
phylax mcp remove <id>                 # Remove MCP rule
```

### DEX Command

```powershell
phylax dex                             # Check data exfiltration risk
```

### Audit Commands

```powershell
phylax audit list [--limit <N>]        # Show recent audit events
phylax audit tail                      # Watch audit events in real time
phylax audit export [--format <f>] [--output <o>]  # Export (csv/txt/json/ocsf/cef)
phylax audit verify-integrity          # Verify hash-chain integrity
```

### Scanner Command

```powershell
phylax scan [<path>]                   # Scan for malicious AI model files
```

### Other Commands

```powershell
phylax update [--check]                # Auto-update from GitHub
phylax ui                              # Open TUI (daemon must be running)
```

## TUI (`agentguard-tui`)

Terminal dashboard with 6 tabs (Status, Agents, Projects, Events, Stats, Rules) built on
ratatui + crossterm, running at 60fps. Launched via `phylax run` or `phylax ui`.

## Web Dashboard

A web-based dashboard is available at `http://127.0.0.1:1977` launched via `phylax serve`
or `phylax start`.

