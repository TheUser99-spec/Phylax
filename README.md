<div align="center">

![Stars](https://img.shields.io/github/stars/TheUser99-spec/Phylax?style=for-the-badge&color=f2c94c)
![Version](https://img.shields.io/github/v/release/TheUser99-spec/Phylax?style=for-the-badge&color=6cdda3)
![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?style=for-the-badge&logo=windows)
<br>
[![X](https://img.shields.io/badge/X-@Phylaxdev-000000?style=for-the-badge&logo=x)](https://x.com/Phylaxdev)

[English](README.md) &nbsp;|&nbsp; [Español](README.es.md)

</div>

<br>

## ⭐ Phylax | OS-level protection for AI coding agents

**A Windows security layer that applies real ACLs so the kernel blocks AI agents from touching protected files.**

- Blocks reads to `.env`, keys, secrets via DENY ACEs
- Blocks deletes to `migrations/`, config, infra via MIC labels
- Works with Claude Code, Cursor, Windsurf, Aider, OpenCode, Copilot
- Web dashboard at `http://127.0.0.1:1977` + Terminal TUI (ratatui, 60fps)
- Compliance reports: EU AI Act, NIST, ISO 42001, SOC 2
- MCP server governance + DEX data exfiltration detection
- Phase 1: user-mode ACL enforcement. Phase 2: kernel minifilter driver (in development)
- Open source (Apache 2.0). 100% local. Seeking technical review.

> **Technical feedback & security review appreciated.**<br>
> Found a limitation? Open an issue. Want to audit the code? `cargo build --workspace`.

<p align="center">
  <img src="assets/demo.gif" alt="Phylax Demo" width="720">
</p>

---

## What is Phylax

**Phylax is a safety boundary for AI coding agents.** It ensures agents can edit your source code — but never touch your secrets, configs, or system files.

Under the hood, it applies real Windows ACLs so the OS kernel itself returns `ACCESS_DENIED` before the agent ever touches a protected file. Claude Code, Cursor, OpenCode, Copilot, Windsurf, Aider — it doesn't matter which agent. If the kernel says no, the agent gets nothing.

---

## Why it exists

AI agents have unrestricted filesystem access. They can read secrets, delete migrations, or wipe config files — without asking. 

**Real examples from the wild:**

```
Claude tried to delete migrations/ → BLOCKED
Cursor tried to read .env          → BLOCKED
OpenCode tried to modify secrets/  → BLOCKED
```

Thousands of open issues across Claude Code, Cursor, Copilot, and others document agents silently destroying data. Not because they're malicious — because they don't understand context, value, or consequence.

Phylax draws a boundary. The agent can edit your source code. It can never touch your `.env`, your SSH keys, or your policy files.

---

## Install

> **Inspect the installer first:** [`install.ps1`](https://raw.githubusercontent.com/TheUser99-spec/Phylax/main/install.ps1)

```powershell
irm https://raw.githubusercontent.com/TheUser99-spec/Phylax/main/install.ps1 | iex
phylax init
phylax run
```

<details>
<summary>Manual install (build from source)</summary>

```bash
git clone https://github.com/TheUser99-spec/Phylax.git
cd Phylax
cargo build --workspace --release
```
</details>

---

## Who is this for?

- **Vibe coders** using Claude, Cursor, Windsurf, or any AI coding tool
- **Developers** working with agents that hallucinate file operations
- **Anyone** with `.env`, API keys, configs, or infrastructure files
- **Teams** who want agent productivity without agent risk
- **People who've already lost data** to an AI agent and never want it to happen again

---

## Why Phylax is different

| Not this | This |
|---|---|
| Not a linter | **Kernel-level enforcement** |
| Not a sandbox | **Real Windows ACLs + MIC labels** |
| Not a plugin | **Works with all agents, no integration needed** |
| Not a prompt rule | **The OS blocks the I/O — the agent can't override it** |
| No cloud dependency | **100% local, zero telemetry** |

---

## How it works

1. **Detect** — Phylax identifies AI agent processes by name, environment variables, and command-line inspection
2. **Classify** — Every file I/O is checked against your `phylax.toml` rules
3. **Enforce** — Matched files get DENY ACEs + Mandatory Integrity Control labels. The Windows kernel blocks access at ring 3
4. **Audit** — Every blocked attempt is logged in local SQLite

---

## 🛡️ Anti-bypass (3 layers of protection)

Even if an agent tries to modify ACLs or take ownership, Phylax blocks it at the OS level.

| Layer | Mechanism | Blocks |
|---|---|---|
| 1 | DENY ACE → Everyone → GENERIC_ALL | Read, write, delete |
| 2 | DENY ACE → Everyone → WRITE_DAC, WRITE_OWNER, DELETE | ACL modification, ownership change |
| 3 | MIC label → High Integrity + NO_WRITE_UP | `icacls /remove:d` and privilege bypass |

Layer 3 is the kill shot: even if an agent runs `icacls /remove:d` to strip the DENY ACE, it fails because the agent runs at Medium integrity while the file is labeled High integrity with NO_WRITE_UP. The kernel rejects the write regardless of ownership.

---

## Permission model

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

[Full permission model docs →](https://phylax.pages.dev/docs#permission-model)

---

## phylax.toml

```toml
[project]
name = "my-project"
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

---

## Commands

| Command | What it does |
|---|---|
| `phylax start` | Start daemon + open web dashboard |
| `phylax init` | Create phylax.toml, start daemon, register project |
| `phylax run` | Start daemon + open terminal TUI (60fps) |
| `phylax stop` | Stop daemon (releases file locks) |
| `phylax status` | Live status: projects, agents, events, blocks |
| `phylax project validate` | Validate phylax.toml syntax |
| `phylax project check -f <f> -o <op>` | Dry-run file access check |
| `phylax project check -f <f> -o <op> -a <agent>` | Per-agent dry-run check |
| `phylax project verify` | Audit protection coverage |
| `phylax global add deny "*.env"` | Add global deny rule |
| `phylax agent add opencode deny "*.pem"` | Add per-agent rule |
| `phylax compliance status` | EU AI Act / NIST / ISO 42001 / SOC 2 |
| `phylax mcp discover` | Discover MCP servers on this system |
| `phylax dex` | Data exfiltration risk check |
| `phylax scan` | Scan for malicious AI model files |
| `phylax audit list` | View audit history |
| `phylax audit export` | Export audit logs (csv, json, ocsf, cef) |
| `phylax audit verify-integrity` | Verify audit log hash chain |
| `phylax update` | Auto-update from GitHub |

---

## Build from source

```bash
git clone https://github.com/TheUser99-spec/Phylax.git
cd Phylax
cargo build --workspace --release
```

---

## Roadmap

- [x] Process detection & AI agent classification
- [x] phylax.toml parser with glob-based policy engine
- [x] Windows ACL/ACE enforcement
- [x] Three-layer anti-bypass (DENY ACEs + MIC labels)
- [x] SQLite audit log
- [x] IPC protocol (30+ request types)
- [x] Terminal dashboard (ratatui, 60fps) + Web dashboard
- [x] Unified CLI with compliance, MCP, DEX, scanner commands
- [x] Invisible daemon
- [x] EU AI Act / NIST / ISO 42001 / SOC 2 compliance reports
- [x] MCP server discovery and governance
- [x] Data exfiltration detection (DEX)
- [x] AI model file scanner (pickle, safetensors, gguf)
- [x] Audit log hash-chain integrity verification
- [x] Landing page + FAQ + tutorial + bilingual docs
- [ ] Kernel minifilter driver (Phase 2)
- [ ] Agent-only blocking (no need to stop daemon)
- [ ] Cross-platform (macOS/Linux)

---

## Docs

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
| [Landing page](https://phylax.pages.dev) | Full product site |
| [Tutorial](https://phylax.pages.dev/tutorial) | 5-minute setup guide |
| [Tutorial Kit](TUTORIAL-KIT.md) | Video scripts for content creators |
| [Press Kit](PRESS-KIT.md) | Brand assets, logos, colors |
| [Curriculum](CURRICULUM.md) | Full course structure (35 lessons) |

---

## Community

- ⭐ [GitHub](https://github.com/TheUser99-spec/Phylax) — stars, issues, contributions
- 🐦 [X / Twitter](https://x.com/Phylaxdev) — updates, announcements
- 📖 [Documentation](https://phylax.pages.dev/docs) — full reference
- 🎓 [Tutorial](https://phylax.pages.dev/tutorial) — get started in 5 minutes
- 🎬 [Tutorial Kit](TUTORIAL-KIT.md) — make a video about Phylax

---

## License

Phylax is open-source under the **Apache 2.0 License**. See [LICENSE](LICENSE).

Comes with **no warranty**. See [DISCLAIMER.md](DISCLAIMER.md).

---

<br>

<div align="center">

**If Phylax saved your `.env` today, you know what to do →**

[![Stars](https://img.shields.io/github/stars/TheUser99-spec/Phylax?style=social)](https://github.com/TheUser99-spec/Phylax)
&nbsp;
[![X](https://img.shields.io/badge/X-@Phylaxdev-000000?style=social&logo=x)](https://x.com/Phylaxdev)

<sub>Built with Rust — Windows-first, agent-proof.</sub>

</div>
