<div align="center">

![Stars](https://img.shields.io/github/stars/TheUser99-spec/AgentGuard?style=for-the-badge&color=f2c94c)
![Version](https://img.shields.io/github/v/release/TheUser99-spec/AgentGuard?style=for-the-badge&color=6cdda3)
![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=for-the-badge)

</div>

<br>

> **AI coding tools can make mistakes. Phylax stops them before they touch your private files.**

---

## What is Phylax

Phylax is a Windows security layer that sits between your filesystem and any AI coding agent. It applies real Windows ACLs so the OS kernel itself returns `ACCESS_DENIED` before the agent ever touches a protected file.

It works with Claude Code, Cursor, OpenCode, Copilot, Windsurf, Aider, and others.

---

## Why it exists

AI agents have unrestricted filesystem access. They can read your secrets, delete your migrations, or wipe your config files — without asking, without warning. Real incidents happen every day.

Phylax draws a boundary. The agent can edit your source code. It can never touch your `.env`, your SSH keys, or your policy files.

---

## Demo

<p align="center">
  <i>🎬 Demo GIF coming soon</i>
  <br>
  <sub><code>agentguard run</code> and watch the dashboard light up.</sub>
</p>

---

## Install

```powershell
irm https://raw.githubusercontent.com/TheUser99-spec/AgentGuard/main/install.ps1 | iex
```

---

## Basic usage

```powershell
agentguard init       # Creates agentguard.toml, starts daemon, registers your project
agentguard run        # Opens the live dashboard
```

That's it. Your project is protected.

---

## Advanced

### Daemon lifecycle

The daemon runs invisible in the background — no console window, survives terminal close.

| Command | What it does |
|---|---|
| `agentguard daemon start` | Start daemon (invisible) |
| `agentguard stop` | Stop daemon and release file locks |
| `agentguard run` | Daemon + dashboard together |
| `agentguard ui` | Dashboard only |
| `agentguard status` | Live status: projects, agents, events, blocks |
| `agentguard update` | Auto-update from GitHub |

While the daemon runs, denied files are locked by Windows ACLs. To edit protected files:

```powershell
agentguard stop
# edit your files...
agentguard daemon start
```

Press `Q` in the dashboard to stop the daemon.

### Permission model

Six buckets ordered by priority. **Deny always wins.**

| Priority | Bucket | Meaning |
|---|---|---|
| 1 | `[deny]` | Complete block |
| 2 | `[ask]` | User must approve |
| 3 | `[full]` | Unrestricted |
| 4 | `[delete]` | Read + Delete |
| 5 | `[write]` | Read + Write |
| 6 | `[read]` | Read only |

When no rule matches: read allowed, write asks, delete denied.

### agentguard.toml

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

### All commands

| Command | What it does |
|---|---|
| `agentguard init` | Create agentguard.toml, start daemon, register project |
| `agentguard run` | Start daemon + open dashboard |
| `agentguard stop` | Stop daemon (releases file locks) |
| `agentguard status` | Live status: projects, agents, events, blocks |
| `agentguard project validate` | Validate agentguard.toml |
| `agentguard project check -f <f> -o <op>` | Dry-run file access check |
| `agentguard project verify` | Audit protection coverage |
| `agentguard global add deny "*.env"` | Add global deny rule |
| `agentguard audit list` | View audit history |
| `agentguard update` | Auto-update from GitHub |

### Anti-bypass

Phylax applies three layers of Windows security to each denied file so even if one layer is bypassed, the others hold.

| Layer | Mechanism | Blocks |
|---|---|---|
| 1 | DENY ACE → Everyone → GENERIC_ALL | Read, write, delete |
| 2 | DENY ACE → Everyone → WRITE_DAC, WRITE_OWNER, DELETE | ACL modification, ownership change |
| 3 | MIC label → High Integrity + NO_WRITE_UP | `icacls /remove:d` bypass |

### 100% local

No account, no cloud, no telemetry.

- No login required
- Works fully offline
- Audit logs in local SQLite (`%APPDATA%\Phylax\agentguard.db`)
- No API keys, no registration, no phone number

Your files, your rules, your machine.

### Build from source

```bash
git clone https://github.com/TheUser99-spec/AgentGuard.git
cd Phylax
cargo build --workspace --release
```

### More docs

| Doc | Topic |
|---|---|
| [Quickstart](docs/quickstart.md) | Complete guide |
| [Architecture](docs/01-architecture.md) | System design |
| [Core types](docs/02-core-types.md) | Permission model |
| [Manifest & policy](docs/03-manifest-policy.md) | agentguard.toml |
| [Storage & audit](docs/04-storage-audit.md) | SQLite schema |
| [Detection](docs/05-detection-enforcement.md) | Process classification |
| [IPC & daemon/CLI](docs/06-ipc-daemon-cli.md) | Protocol + lifecycle |
| [ADR index](docs/adr/README.md) | Architecture decisions |

---

## Roadmap

- [x] Process detection & AI agent classification
- [x] agentguard.toml parser with glob-based policy engine
- [x] Windows ACL/ACE enforcement
- [x] Three-layer anti-bypass (DENY ACEs + MIC labels)
- [x] SQLite audit log
- [x] IPC protocol (20 request types)
- [x] Terminal dashboard (ratatui, 60fps)
- [x] Unified CLI
- [x] Invisible daemon
- [ ] Kernel minifilter driver (Phase 2)
- [ ] Agent-only blocking (no need to stop daemon)
- [ ] Cross-platform (macOS/Linux)

---

## License

Phylax is open-source under the **Apache 2.0 License**. See [LICENSE](LICENSE).

Comes with **no warranty**. See [DISCLAIMER.md](DISCLAIMER.md).

---

<br>

<div align="center">

**If Phylax saved your `.env` today, you know what to do →**

[![Stars](https://img.shields.io/github/stars/TheUser99-spec/AgentGuard?style=social)](https://github.com/TheUser99-spec/AgentGuard)

<sub>Built with Rust — Windows-first, agent-proof.</sub>

</div>
