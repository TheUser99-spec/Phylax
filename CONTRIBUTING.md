# 🤝 Contributing to Phylax

Thanks for your interest in contributing! Phylax is an open-source project and we welcome contributions from everyone.

---

## Code of Conduct

Be respectful. Be constructive. We're building security software — quality and correctness matter more than speed.

---

## How to Contribute

### 🐛 Reporting Bugs

1. Check [existing issues](https://github.com/TheUser99-spec/Phylax/issues) to avoid duplicates
2. Use the bug report template
3. Include:
   - Windows version (`winver`)
   - Phylax version (`phylax --version`)
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs from `%APPDATA%\Phylax\phylax.db`

### 💡 Feature Requests

1. Check [existing issues](https://github.com/TheUser99-spec/Phylax/issues) and [the roadmap](https://phylax.pages.dev/development-path)
2. Explain the problem you're trying to solve
3. Describe your proposed solution
4. Consider Phase timing (Phase 1 = user-mode ACLs, Phase 2 = kernel driver)

### 🔧 Pull Requests

1. **Fork the repo** and create a branch from `main`
2. **Keep PRs focused** — one feature/fix per PR
3. **Follow the dependency direction:**
   ```
   core ← manifest ← policy ← (enforce, audit, probe, notify, ipc) ← daemon ← cli, tui
   ```
4. **Do not modify** without approval:
   - Root `Cargo.toml`
   - `crates/agentguard-core/src/types.rs`
   - `crates/agentguard-store/src/migrations.rs`
   - `driver/**`
   - `modules/**`
   - `docs/adr/**` (append new ADRs, don't delete historical ones)
5. **Write tests** for new functionality
6. **Run tests before submitting:**
   ```bash
   cargo test --workspace
   cargo test -p <your-crate>
   ```
7. **Use conventional commits:** `feat(scope): description`, `fix(scope): description`

---

## Development Setup

### Prerequisites

- **Rust** (stable, latest)
- **Windows 10 or 11** (primary platform)
- **Visual Studio Build Tools** (for C++ driver in Phase 2)

### Build

```bash
git clone https://github.com/TheUser99-spec/Phylax.git
cd Phylax
cargo build --workspace
```

### Run tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p agentguard-manifest
cargo test -p agentguard-store
cargo test -p agentguard-policy
```

### Run the daemon

```bash
cargo run -p agentguard-daemon
```

### Run the TUI dashboard

```bash
cargo run -p agentguard-tui
```

---

## Project Structure

```
crates/
  agentguard-core/       <- Base types and shared errors (no external deps)
  agentguard-manifest/   <- phylax.toml parser + compiled GlobSets
  agentguard-policy/     <- Decision engine (deny > ask > full > delete > write > read)
  agentguard-store/      <- SQLite access and schema ownership
  agentguard-probe/      <- Process polling + subject classification
  agentguard-enforce/    <- ACL/ACE enforcement and coordination
  agentguard-ipc/        <- Named-pipe protocol and client/server
  agentguard-notify/     <- User prompts/notifications for [ask]
  agentguard-audit/      <- Audit logging integration
  agentguard-daemon/     <- Main orchestrator/service logic
  agentguard-cli/        <- CLI entrypoint and commands
  agentguard-tui/        <- Ratatui dashboard
  agentguard-mascot/     <- Optional terminal mascot UI
  agentguard-compliance/ <- EU AI Act, NIST, ISO 42001, SOC 2 compliance
  agentguard-cloud/      <- Cloud deployment helpers
  agentguard-scanner/    <- AI model file scanner (pickle, safetensors, gguf)
  agentguard-web/        <- Web dashboard (Axum) at http://127.0.0.1:1977
  agentguard-mcp/        <- MCP server governance
  agentguard-dex/        <- Data exfiltration detection

driver/                  <- C++ minifilter (Phase 2, modify with caution)
modules/                 <- Phase 3/4 placeholders
docs/                    <- Architecture docs and ADRs
landing/                 <- Astro landing page (phylax.pages.dev)
```

---

## Coding Conventions

- **Rust:** Follow standard Rust conventions (`rustfmt`, `clippy`)
- **C++ (driver):** Windows kernel coding style
- **Astro:** Follow existing component patterns in `landing/src/`
- **Path canonicalization** is mandatory before glob matching:
  ```rust
  let canonical = std::fs::canonicalize(&path)?;
  let relative = canonical.strip_prefix(&workspace_root)?;
  compiled_manifest.evaluate(relative, &op);
  ```
- **Store is the only DB boundary** — no other crate imports `rusqlite` directly
- **Test before claiming behavior**

---

## Permission Model

Priority order: `deny` > `ask` > `full` > `delete` > `write` > `read`

`deny` always wins. Default when no rule matches:
- `conservative`: read Allow, write Ask, delete Deny
- `unrestricted`: Allow all

---

## Getting Help

- **Docs:** https://phylax.pages.dev/docs
- **FAQ:** https://phylax.pages.dev/faq
- **Issues:** https://github.com/TheUser99-spec/Phylax/issues
- **X/Twitter:** https://x.com/Phylaxdev

---

## Recognition

All contributors will be listed in the project. Significant contributions may be highlighted in release notes and on the website.
