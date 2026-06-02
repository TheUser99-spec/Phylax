<div align="center">

![Stars](https://img.shields.io/github/stars/TheUser99-spec/Phylax?style=for-the-badge&color=f2c94c)
![Version](https://img.shields.io/github/v/release/TheUser99-spec/Phylax?style=for-the-badge&color=6cdda3)
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
  <img src="assets/demo.gif" alt="Phylax Demo" width="720">
</p>

---

## Install

```powershell
irm https://raw.githubusercontent.com/TheUser99-spec/Phylax/main/install.ps1 | iex
```

---

## Basic usage

```powershell
phylax init       # Creates phylax.toml, starts daemon, registers your project
phylax run        # Opens the live dashboard
```

That's it. Your project is protected.

---

## Advanced

### Daemon lifecycle

The daemon runs invisible in the background — no console window, survives terminal close.

| Command | What it does |
|---|---|
| `phylax daemon start` | Start daemon (invisible) |
| `phylax stop` | Stop daemon and release file locks |
| `phylax run` | Daemon + dashboard together |
| `phylax ui` | Dashboard only |
| `phylax status` | Live status: projects, agents, events, blocks |
| `phylax update` | Auto-update from GitHub |

While the daemon runs, denied files are locked by Windows ACLs. To edit protected files:

```powershell
phylax stop
# edit your files...
phylax daemon start
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

### phylax.toml

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
| `phylax init` | Create phylax.toml, start daemon, register project |
| `phylax run` | Start daemon + open dashboard |
| `phylax stop` | Stop daemon (releases file locks) |
| `phylax status` | Live status: projects, agents, events, blocks |
| `phylax project validate` | Validate phylax.toml |
| `phylax project check -f <f> -o <op>` | Dry-run file access check |
| `phylax project verify` | Audit protection coverage |
| `phylax global add deny "*.env"` | Add global deny rule |
| `phylax audit list` | View audit history |
| `phylax update` | Auto-update from GitHub |

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
- Audit logs in local SQLite (`%APPDATA%\Phylax\phylax.db`)
- No API keys, no registration, no phone number

Your files, your rules, your machine.

### Build from source

```bash
git clone https://github.com/TheUser99-spec/Phylax.git
cd Phylax
cargo build --workspace --release
```

### More docs

| Doc | Topic |
|---|---|
| [Quickstart](docs/quickstart.md) | Complete guide |
| [Architecture](docs/01-architecture.md) | System design |
| [Core types](docs/02-core-types.md) | Permission model |
| [Manifest & policy](docs/03-manifest-policy.md) | phylax.toml |
| [Storage & audit](docs/04-storage-audit.md) | SQLite schema |
| [Detection](docs/05-detection-enforcement.md) | Process classification |
| [IPC & daemon/CLI](docs/06-ipc-daemon-cli.md) | Protocol + lifecycle |
| [ADR index](docs/adr/README.md) | Architecture decisions |

---

## Roadmap

- [x] Process detection & AI agent classification
- [x] phylax.toml parser with glob-based policy engine
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

[![Stars](https://img.shields.io/github/stars/TheUser99-spec/Phylax?style=social)](https://github.com/TheUser99-spec/Phylax)

<sub>Built with Rust — Windows-first, agent-proof.</sub>

</div>
