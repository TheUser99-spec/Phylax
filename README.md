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
  <i>🎬 Demo GIF coming soon</i>
  <br>
  <sub><i><code>agentguard run</code> and watch the dashboard light up.</i></sub>
</p>

<br>

---

## 📦 Install

```powershell
irm https://raw.githubusercontent.com/TheUser99-spec/AgentGuard/main/install.ps1 | iex
```

```powershell
agentguard init       # creates agentguard.toml, starts daemon, registers your project
agentguard run        # opens the dashboard
```

---

## 🔄 Daemon lifecycle

The daemon runs **invisible** (no console window) and **survives terminal close**.

| Command | What it does |
|---|---|
| `agentguard daemon start` | Start daemon (invisible, background) |
| `agentguard stop` | Stop daemon (releases Windows file locks) |
| `agentguard run` | Daemon + TUI together |
| `agentguard ui` | TUI only (daemon already running) |

**Important:** While the daemon is running, protected files are locked by Windows ACLs. To edit `agentguard.toml`, `.env`, or any `[deny]` file, stop the daemon first:

```powershell
agentguard stop
# edit your files...
agentguard daemon start
```

Pressing `Q` in the TUI also stops the daemon automatically.

---

## ⚔️ Threat Model

| Threat | Mitigation |
|---|---|
| Agent reads secrets (`.env`, `.pem`, `.key`) | `[deny]` bucket — blocked at ACL level |
| Agent deletes critical files | OS-level DACL prevents handle acquisition |
| Agent spawns child processes | `Inherited` label — same policy applies |
| Agent modifies `agentguard.toml` | Mandatory deny — always injected |

---

## 🚀 Commands

| Command | What it does |
|---|---|
| `agentguard init` | Creates `agentguard.toml`, starts daemon, registers project |
| `agentguard run` | Starts daemon + opens TUI dashboard |
| `agentguard stop` | Stops the daemon (releases file locks) |
| `agentguard status` | Live status: projects, agents, events, blocks |
| `agentguard project validate` | Validates your `agentguard.toml` |
| `agentguard project check -f <file> -o <op>` | Dry-run file access check |
| `agentguard project verify` | Audits effective protection coverage |
| `agentguard global add deny "*.env"` | Add a global deny rule |
| `agentguard audit list` | View audit history |
| `agentguard update` | Auto-update from GitHub |

---

## 📝 agentguard.toml

```toml
[project]
name = "my-agentguard-project"
default = "conservative"

[deny]
files = [".env", ".env.*", "secrets/**", "*.pem", "*.key"]

[ask]
files = ["Cargo.lock", "migrations/**"]

[write]
files = ["src/**", "tests/**"]

[read]
files = ["README.md", "docs/**"]
```

Bucket priority: `deny → ask → full → delete → write → read`. Deny always wins.

---

## 🗺️ Roadmap

- [x] Process detection & AI agent classification
- [x] `agentguard.toml` parser with glob-based policy engine
- [x] Windows ACL/ACE enforcement
- [x] SQLite audit log
- [x] IPC protocol (20 request types)
- [x] Terminal dashboard (ratatui, 60fps)
- [x] Unified CLI: `init`, `run`, `ui`, `stop`, `update`
- [x] Invisible daemon (no console, survives terminal close)
- [ ] Kernel minifilter driver (ring 0)
- [ ] Windows Service integration
- [ ] Cross-platform (macOS/Linux)

---

## 🏗️ Build from source

```bash
git clone https://github.com/TheUser99-spec/AgentGuard.git
cd AgentGuard
cargo build --workspace --release
```

---

## 📚 Docs

| Doc | Topic |
|---|---|
| [Architecture](docs/01-architecture.md) | System design |
| [Core types](docs/02-core-types.md) | Permission model |
| [Manifest & policy](docs/03-manifest-policy.md) | `agentguard.toml` |
| [Storage & audit](docs/04-storage-audit.md) | SQLite schema |
| [Detection & enforcement](docs/05-detection-enforcement.md) | Process classification |
| [IPC & daemon/CLI](docs/06-ipc-daemon-cli.md) | Protocol + lifecycle |
| [ADR index](docs/adr/README.md) | Architecture decisions |

---

<br>

<div align="center">

**If AgentGuard saved your `.env` today, you know what to do →**

[![Stars](https://img.shields.io/github/stars/TheUser99-spec/AgentGuard?style=social)](https://github.com/TheUser99-spec/AgentGuard)

<sub>Built with Rust — Windows-first, agent-proof.</sub>

</div>
