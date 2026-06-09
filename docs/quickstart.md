# phylax — Quickstart Guide

## What phylax Does

phylax is an OS-level security layer for Windows that controls what AI coding agents (Claude Code, Cursor, OpenCode, Copilot, Windsurf, Aider, and others) can read, write, or delete on your machine.

It is **not** a wrapper, proxy, or IDE extension. It applies real Windows ACLs (DENY ACEs + Mandatory Integrity Control) so the OS kernel itself returns ACCESS_DENIED to the agent before it ever touches a protected file.

## Key Facts

| Fact | Detail |
|------|--------|
| **100% local** | No accounts, no cloud, no telemetry |
| **Works offline** | No internet needed |
| **Audit logs** | Stored in local SQLite at `%APPDATA%\AgentGuard\phylax.db` |
| **Multi-agent** | Detects Claude, Cursor, OpenCode, Copilot, Windsurf, Aider, and more |
| **OS-level** | Real Windows ACLs — not an app-level block |

---

## Installation

```powershell
irm https://raw.githubusercontent.com/TheUser99-spec/AgentGuard/main/install.ps1 | iex
```

After installation, you have the `agentguard` command available in your terminal.

---

## Quick Start

```powershell
phylax init       # Creates phylax.toml + starts daemon + registers project
phylax run        # Opens the live dashboard (daemon + TUI)
```

At this point, phylax is running and protecting your project. Any AI agent that tries to access a denied file will be blocked by Windows ACLs.

---

## Commands Reference

### Daemon Lifecycle

| Command | Description |
|---------|-------------|
| `phylax daemon start` | Start daemon in background (no console window, survives terminal close) |
| `phylax stop` | Stop daemon and release all Windows file locks |
| `phylax run` | Start daemon + open TUI dashboard together (60fps) |
| `phylax serve` | Start daemon + open web dashboard at http://127.0.0.1:1977 |
| `phylax start` | Alias for `phylax serve` |
| `phylax ui` | Open TUI only (daemon must already be running) |

### Project Management

| Command | Description |
|---------|-------------|
| `phylax init` | Create `phylax.toml`, start daemon, register current project |
| `phylax status` | Show live status: projects, agents, events, blocks |
| `phylax project validate` | Validate your `phylax.toml` syntax |
| `phylax project check -f <file> -o <op>` | Dry-run: check what would happen if an agent tried `<op>` on `<file>` |
| `phylax project check -f <f> -o <op> -a <agent>` | Per-agent dry-run check (e.g. `-a opencode`) |
| `phylax project verify` | Audit effective protection coverage |
| `phylax project on` | Turn protection ON for the current project |
| `phylax project off` | Turn protection OFF for the current project |

### Global Rules

| Command | Description |
|---------|-------------|
| `phylax global add deny "*.env"` | Add a global deny rule for all projects |
| `phylax global list` | List all global rules |
| `phylax global remove <id>` | Remove a global rule |

### Per-Agent Rules

| Command | Description |
|---------|-------------|
| `phylax agent add opencode deny "*.pem"` | Add a deny rule for a specific agent |
| `phylax agent list` | List all per-agent rules |
| `phylax agent remove <id>` | Remove a per-agent rule |

### Compliance

| Command | Description |
|---------|-------------|
| `phylax compliance list` | List available compliance standards |
| `phylax compliance status` | Check live compliance status (requires daemon) |
| `phylax compliance evaluate` | Offline compliance evaluation |
| `phylax compliance generate` | Generate compliance report (json/md) |

### MCP Governance

| Command | Description |
|---------|-------------|
| `phylax mcp discover` | Discover MCP servers on this system |
| `phylax mcp list` | List MCP governance rules |
| `phylax mcp add <name> <action>` | Add MCP rule (deny/ask/read) |

### DEX (Data Exfiltration)

| Command | Description |
|---------|-------------|
| `phylax dex` | Check data exfiltration risk (network egress, USB devices) |

### AI Model Scanner

| Command | Description |
|---------|-------------|
| `phylax scan [<path>]` | Scan directory for malicious AI model files (pickle, safetensors, gguf) |

### Audit & Monitoring

| Command | Description |
|---------|-------------|
| `phylax audit list` | View audit history (blocked attempts, allowed operations) |
| `phylax audit tail` | Follow audit events in real time |
| `phylax audit export --format json` | Export audit logs (csv/txt/json/ocsf/cef) |
| `phylax audit verify-integrity` | Verify cryptographic integrity of the audit log hash chain |

### Updates

| Command | Description |
|---------|-------------|
| `phylax update` | Auto-update phylax from GitHub |

---

## How the Daemon Works

### Normal Operation

When the daemon is running:
1. It watches for AI agent processes on your system
2. It applies DENY ACEs and MIC labels to files matching your `[deny]` rules
3. Any attempt by an AI agent to read/write/delete a denied file returns `ACCESS_DENIED` from Windows
4. All events are logged to SQLite

### Daemon Survivability

- The daemon runs **invisibly** (no console window)
- It **survives terminal close** — it keeps running even after you close PowerShell
- To check if it's running: `phylax status`

### Stopping the Daemon

```
phylax stop
```

Stopping the daemon:
- Releases all Windows file locks
- Removes DENY ACEs from protected files
- Files become accessible again

**This is important:** While the daemon is stopped, denied files are NOT protected. To edit protected files like `.env` or `phylax.toml`:

```powershell
phylax stop
# Edit your files...
phylax daemon start
```

You can also press `Q` in the TUI dashboard to stop the daemon.

---

## Permission Model

phylax uses 6 permission buckets ordered by priority:

```
deny > ask > full > delete > write > read
```

| Priority | Bucket | Read | Write | Delete | Meaning |
|----------|--------|------|-------|--------|---------|
| 1 | deny | No | No | No | Complete block |
| 2 | ask | Prompt | Prompt | Prompt | User must approve |
| 3 | full | Yes | Yes | Yes | Unrestricted |
| 4 | delete | Yes | No | Yes | Read + Delete only |
| 5 | write | Yes | Yes | No | Read + Write only |
| 6 | read | Yes | No | No | Read-only |

**Deny always wins.** If a file matches both `[deny]` and `[write]`, deny takes precedence.

### Conservative Default

When no rule matches a file:
- Read -> Allowed
- Write -> Ask (prompts user)
- Delete -> Denied

---

## Three-Layer Anti-Bypass Protection

phylax applies **three layers** of Windows security to each denied file:

| Layer | Mechanism | What It Blocks |
|-------|-----------|----------------|
| 1 | DENY ACE -> Everyone -> GENERIC_ALL | Read, write, delete |
| 2 | DENY ACE -> Everyone -> WRITE_DAC, WRITE_OWNER, DELETE | ACL modification, ownership change |
| 3 | MIC label -> High Integrity + NO_WRITE_UP | Privilege bypass (icacls /remove:d) |

Layer 3 prevents `icacls /remove:d` bypass because the agent runs at Medium integrity and cannot write to High integrity objects.

---

## Phase 1 Limitations (Current)

phylax is currently in **Phase 1** (user-mode enforcement). These are the known limitations:

### Files Are Only Protected While Daemon Runs

- When `phylax stop` is executed, all DENY ACEs are removed
- Files become fully accessible
- A malicious agent could wait for the daemon to stop, or the user might forget to restart it

### ACE-Based Enforcement

- Protections are applied via Windows ACLs, not real-time interception
- There is a small window between agent detection and ACE application (~750ms polling interval)
- An agent could theoretically start, read a file, and exit between polls

### Audit Logs Are User-Writable

- SQLite database at `%APPDATA%\AgentGuard\phylax.db` is in user space
- A determined agent with filesystem access could modify or delete audit logs

### Everyone ACEs

- DENY ACEs apply to Everyone (including the human user)
- You must stop the daemon to work on protected files yourself
- Use `phylax project off` / `phylax project on` to temporarily disable protection

---

## Phase 2 Roadmap (Kernel Minifilter)

Phase 2 adds a C++ kernel minifilter driver (`driver/phylax.sys`) that will:

| Feature | Phase 1 | Phase 2 |
|---------|---------|---------|
| Enforcement method | Windows ACLs (DENY ACEs) | Real-time I/O interception at kernel level |
| Can daemon stop remove protection? | Yes | No — kernel driver persists independently |
| Per-operation interception | No (ACL-based) | Yes — IRP paused and inspected |
| Ask flow | Not enforced real-time | IRP paused, waits for user response |
| Per-agent overrides | Stored, not evaluated | PID passed to daemon for evaluation |
| Tamper-proof audit | No | Yes — kernel-level logging |
| Bypass via daemon kill | Possible | Blocked — protection survives daemon restart |

Phase 2 is currently under development in `driver/`. It requires a signed kernel driver (EV certificate).

---

## Agent Detection

phylax detects AI agents using 5 signals in priority order:

| Signal | Method | Result |
|--------|--------|--------|
| S1 | Known environment variables (CLAUDE_CODE, CURSOR_SESSION, OPENAI_API_KEY, etc.) | Definite |
| S2 | Image name match (claude.exe, cursor.exe, opencode.exe, etc.) | Definite |
| S3 | node.exe with agent keywords in command line | Definite |
| S4 | Session 0 + no window station (non-interactive process) | Probable |
| S5 | Parent already classified as agent | Inherited |

### Supported Agents

phylax recognizes these AI coding tools automatically:
- Claude Code
- Cursor
- OpenCode
- GitHub Copilot CLI
- Windsurf
- Aider
- Goose
- Cline
- Gemini CLI

---

## phylax.toml Reference

```toml
[project]
name = "my-project"
default = "conservative"    # or "unrestricted"

[deny]                       # Highest priority — complete block
files = [".env", ".env.*", "secrets/**", "*.pem", "*.key", "phylax.toml"]

[ask]                        # User must approve each operation
files = ["Cargo.lock", "package-lock.json", "migrations/**"]

[write]                      # Agent can read and write, not delete
files = ["src/**", "tests/**", "docs/**"]

[read]                       # Agent can only read
files = ["README.md", "docs/**"]
```

### Default Modes

| Mode | Read | Write | Delete |
|------|------|-------|--------|
| `conservative` | Allow | Ask | Deny |
| `unrestricted` | Allow | Allow | Allow |

### Mandatory Deny Patterns

These patterns are **always denied** by the daemon, even if missing from your `phylax.toml`:
- `phylax.toml` — prevents policy tampering
- `.env`, `.env.*` — always protect secrets
- `.git/**` — protect git internals
- `**/*.key`, `**/*.pem`, `**/*.p12`, `**/*.pfx` — always protect key material

---

## Architecture Diagram

```
AI Agent Process (e.g. claude.exe)
        |
        | tries to open/read/write/delete a file
        v
Windows Kernel (checks DACL)
        |
        | DENY ACE found -> ACCESS_DENIED
        | MIC label blocks Medium integrity write
        v
Agent receives ERROR_ACCESS_DENIED
        |
        v
phylax Daemon logs audit event -> SQLite
```

## Crate Structure

```
crates/
  agentguard-core/         Base types (no deps)
  agentguard-manifest/     TOML parser + GlobSet
  agentguard-policy/       Decision engine
  agentguard-store/        SQLite access
  agentguard-probe/        Process detection
  agentguard-enforce/      ACL enforcement
  agentguard-ipc/          Named pipe protocol
  agentguard-notify/       User prompts
  agentguard-audit/        Event logging
  agentguard-daemon/       Main orchestrator
  agentguard-cli/          CLI (clap)
  agentguard-tui/          Dashboard (ratatui, 60fps)
  agentguard-mascot/        Optional terminal mascot UI

driver/
  phylax.sys           Phase 2 kernel minifilter (C++)
```
