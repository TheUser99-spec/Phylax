<div align="center">

![Stars](https://img.shields.io/github/stars/TheUser99-spec/AgentGuard?style=for-the-badge&color=f2c94c)
![Version](https://img.shields.io/github/v/release/TheUser99-spec/AgentGuard?style=for-the-badge&color=6cdda3)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)

</div>

<br>

> **Your AI coding agent just tried to write to `~/.ssh/id_rsa`. AgentGuard stopped it.**

AgentGuard is a Windows security layer that sits between your filesystem and any AI coding agent — Claude Code, Cursor, OpenCode, Copilot, Windsurf, you name it. It watches every file operation in real time and enforces exactly what each agent can read, write, or delete.

<br>

<p align="center">
  <i>🎬 Demo GIF coming soon — placeholder for the real thing</i>
  <br>
  <sub><i>In the meantime: <code>agentguard run</code> and watch the dashboard light up.</i></sub>
</p>

<br>

---

## 📦 Install

```powershell
irm https://raw.githubusercontent.com/TheUser99-spec/AgentGuard/main/install.ps1 | iex
```

Then restart your terminal and type:

```powershell
agentguard init       # creates agentguard.toml, starts daemon, registers your project
agentguard run        # opens the dashboard
```

That's it. Your workspace is protected.

---

## 🧠 Why this exists

I built AgentGuard because AI coding agents are incredible — and terrifying.

Cursor rewrote my entire auth module in one prompt. Claude deleted a migration file I forgot to commit. OpenCode tried to read my `.env` file to "understand the project better." None of them asked. None of them should.

AI agents don't have intentions. They have instructions. And right now, those instructions don't include "check if this file is sensitive before touching it."

AgentGuard is the missing safety net. It doesn't slow agents down — it just draws a line they can't cross.

---

## 🛡️ What it does

| Situation | Without AgentGuard | With AgentGuard |
|---|---|---|
| Agent reads `.env` | Happens silently | **Blocked** — you never even see it |
| Agent edits `src/` | Normal behavior | **Allowed** — that's the job |
| Agent wants to delete `Cargo.lock` | Huh, it's gone | **Paused** — asks you first |
| Malicious package tries to read SSH keys | Huge problem | **Denied** — at the OS level |

---

## ⚔️ Threat Model

AgentGuard treats AI coding agents as **powerful but untrusted processes** — similar to how a browser treats JavaScript from the internet.

| Threat | Mitigation |
|---|---|
| Agent reads secrets (`.env`, `.pem`, `.key`) | `[deny]` bucket — blocked at ACL level before the agent ever opens the file |
| Agent deletes critical project files | `[delete]` bucket or `[deny]` — OS-level DACL prevents handle acquisition |
| Agent spawns child processes to bypass rules | Classifier detects `Inherited` processes — same policy applies |
| Agent modifies `agentguard.toml` itself | Mandatory deny — always injected, user can't accidentally remove it |
| Agent turns off protection | Requires Administrator — not available to user-mode agents |

AgentGuard operates at **ring 3 (user mode)** using Windows discretionary access control lists (DACLs). A future kernel minifilter (ring 0) will make bypass functionally impossible.

---

## 🎮 How it works

```
Agent writes file ──→ Probe detects process ──→ Classifier labels it
                                                      │
                                                      ▼
                                            Policy engine checks rules
                                                      │
                                          ┌───────────┼───────────┐
                                          ▼           ▼           ▼
                                        DENY        ASK         ALLOW
                                     (blocked)   (prompts you) (goes through)
                                          │           │           │
                                          └───────────┴───────────┘
                                                      │
                                                      ▼
                                                Audit log (SQLite)
```

Four layers, sub-millisecond decisions:

1. **Probe** — Windows ToolHelp32 polling, detects every process in real time
2. **Classifier** — 4 signals (env vars, image name, command line, session 0 heuristics) determine if a process is an AI agent
3. **Policy engine** — evaluates `agentguard.toml` rules using compiled glob sets, resolves `deny > ask > full > delete > write > read`
4. **Enforcer** — applies Windows ACEs directly to protected files and folders

---

## 🚀 Commands

| Command | What it does |
|---|---|
| `agentguard init` | Creates `agentguard.toml`, starts daemon, registers project |
| `agentguard run` | Starts daemon + opens TUI dashboard in one command |
| `agentguard ui` | Opens the TUI (daemon must be running) |
| `agentguard status` | Live status: projects, agents, events, blocks today |
| `agentguard daemon start` | Starts the background daemon |
| `agentguard daemon stop` | Gracefully stops the daemon |
| `agentguard daemon restart` | Stop + start |
| `agentguard project validate` | Validates your `agentguard.toml` |
| `agentguard project check -f <file> -o <op>` | Dry-run: what would happen if agent touched this file? |
| `agentguard project verify` | Audits effective protection coverage |
| `agentguard global add deny "*.env"` | Add a global deny rule |
| `agentguard global list` | List all global rules |
| `agentguard agent add cursor.exe deny "secrets/**"` | Per-agent rule |
| `agentguard audit list` | Show recent audit events |
| `agentguard update` | Auto-update to latest GitHub release |

---

## 📝 agentguard.toml

```toml
[project]
name = "my-agentguard-project"
default = "conservative"

[deny]
files = [
    ".env",
    ".env.*",
    "secrets/**",
    "*.pem",
    "*.key",
]

[ask]
files = [
    "Cargo.lock",
    "package-lock.json",
    "migrations/**",
]

[write]
files = [
    "src/**",
    "tests/**",
]

[read]
files = [
    "README.md",
    "docs/**",
]
```

### Bucket priority

```
deny → ask → full → delete → write → read
  ↑                                          Highest priority wins.
  └─ deny always wins.                      deny can't be overridden.
```

When no rule matches, `default` kicks in:
- `conservative`: read = Allow, write = Ask, delete = Deny
- `unrestricted`: all = Allow

---

## 🗺️ Roadmap

- [x] Process detection & AI agent classification (11 known agents, 25 env signals)
- [x] `agentguard.toml` parser with glob-based policy engine
- [x] Windows ACL/ACE enforcement (DACL-based deny buckets)
- [x] SQLite audit log with full event history
- [x] Named-pipe IPC protocol (20 request types)
- [x] Real-time event streaming to TUI
- [x] Terminal dashboard (ratatui, 60fps)
- [x] Unified CLI with `init`, `run`, `ui`, `update`
- [x] One-command PowerShell installer
- [x] Auto-update from GitHub Releases
- [x] Global rules (apply to every project)
- [x] Per-agent rules (cursor.exe vs claude.exe)
- [x] Ask flow — agent requests, you approve (IPC round-trip)
- [ ] Kernel minifilter driver (ring 0 enforcement, no user-mode bypass possible)
- [ ] Windows Service integration (`agentguard service install`)
- [ ] Team policies via `agentguard-team.toml`
- [ ] Cross-platform (macOS/Linux)

---

## 🏗️ Build from source

```bash
# Requires Rust 1.80+
git clone https://github.com/TheUser99-spec/AgentGuard.git
cd AgentGuard
cargo build --workspace --release

# Output:
#   target/release/agentguard.exe         (CLI + TUI)
#   target/release/agentguard-daemon.exe  (background daemon)
```

---

## 📚 Documentation

| Doc | Topic |
|---|---|
| [Architecture](docs/01-architecture.md) | System design and component interaction |
| [Core types](docs/02-core-types.md) | Permission model, buckets, decisions |
| [Manifest & policy](docs/03-manifest-policy.md) | `agentguard.toml` format and policy evaluation |
| [Storage & audit](docs/04-storage-audit.md) | SQLite schema and audit pipeline |
| [Detection & enforcement](docs/05-detection-enforcement.md) | Process classification and ACE application |
| [IPC & daemon/CLI](docs/06-ipc-daemon-cli.md) | Named pipe protocol and daemon lifecycle |
| [ADR index](docs/adr/README.md) | Architecture Decision Records |

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Dependency direction is strictly enforced: `core ← manifest ← policy ← (enforce, audit, probe, notify, ipc) ← daemon ← cli/tui`.

---

<br>

<div align="center">

**If AgentGuard saved your `.env` today, you know what to do →**

<br>

[![Stars](https://img.shields.io/github/stars/TheUser99-spec/AgentGuard?style=social)](https://github.com/TheUser99-spec/AgentGuard)

<sub>Built with Rust 🦀 — Windows-first, agent-proof.</sub>

</div>
