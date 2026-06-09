# AI Agent Security Gap Analysis (2025-2026)

## Research for Phylax OS-Level Security Layer
**Date:** June 2026  
**Scope:** Identify gaps uniquely addressable by OS-level filesystem enforcement

---

## 1. New Agent Frameworks — Security Gaps

### 1.1 Browser Use (97.5k stars, Python, v0.12.9)
- **Primary risk:** Uses real Chrome browser profiles with saved logins (`real_browser.py`). Agent has full access to all saved passwords, session cookies, autofill data.
- **Persistent filesystem:** Cloud version offers "persistent filesystem and memory" — agent writes/reads arbitrary files.
- **Tool execution:** Custom tools (`@tools.action`) run arbitrary Python with no sandboxing.
- **Phylax gap to address:** Agent writes to `~/.browser-use/`, browser profile directories, downloads folder — all invisible to app-level security. No OS-enforced read/write boundaries on browser profile data.

### 1.2 Cline (62.9k stars, TypeScript, v3.88.0)
- **Terminal execution:** Runs bash commands directly in user's terminal — full shell access.
- **Multi-agent Kanban:** Each card gets its own git worktree with auto-commit. Agents in parallel writing files.
- **Scheduled agents:** Cron-based agents that "persist across restarts" — persistent state on disk.
- **Messaging connectors:** Connects to Slack, Telegram, Discord, WhatsApp — agent has access to chat histories, can send messages as user.
- **Plugin system:** SDK allows registering custom tools that "execute: async (input) => { ... }" — arbitrary code.
- **Phylax gap to address:** No file-level ACLs on which directories agents can modify. Agent with `cline` access can read `.env`, private keys, SSH configs, and exfiltrate via messaging connectors.

### 1.3 Aider (45.8k stars, Python, v0.86.0)
- **Full codebase access:** Generates a repo map of entire codebase — reads all files.
- **Git integration:** Auto-commits with generated messages. Can force-push if not constrained.
- **Lint/test execution:** Agent runs user's test suites and linters — arbitrary command execution.
- **Voice-to-code:** Audio piped to LLM — potential for exfiltration via side channel.
- **Phylax gap to address:** Agent reads `.env`, `.git/config` (remote URLs with tokens), `~/.ssh/`. No OS-level deny on sensitive files regardless of agent framework.

### 1.4 CrewAI (52.9k stars, Python, v1.14.6)
- **Multi-agent delegation:** Agents can delegate to other agents autonomously — transitive trust.
- **Tool integration:** Agents use tools (`SerperDevTool`, custom tools) that hold API keys in memory.
- **Telemetry:** Anonymous telemetry collects "tools names available", "roles of agents", "language model used". Opt-in "share_crew" collects task descriptions, outputs.
- **Output files:** Tasks write `output_file='report.md'` — arbitrary filesystem writes.
- **Phylax gap to address:** Agent output files can overwrite project configs. No enforcement on where CrewAI agents can write.

### 1.5 LangGraph (34k stars, Python, v1.2.4)
- **Durable execution:** "Persist through failures" — state checkpoints written to disk (SQLite/Postgres). State contains all agent conversation, tool outputs, file contents.
- **Long-term memory:** "Persistent memory across sessions" — all historical interactions stored.
- **Human-in-the-loop:** Humans inspect/modify agent state — but no audit of what was inspected.
- **Deep Agents:** "Leverage file systems for complex tasks" — file system as working memory. Agent writes/reads arbitrary files.
- **Phylax gap to address:** Checkpoint/state databases are a goldmine for exfiltration. OS-level read protection on agent state stores. File system memory is unconstrained — no directory boundaries.

### 1.6 AutoGen → Microsoft Agent Framework (58.7k stars, maintenance mode)
- **MCP Server integration:** Explicit warning — "Only connect to trusted MCP servers as they may execute commands in your local environment."
- **Code execution:** Magentic-One agent performs "code execution, web browsing, and file handling."
- **Cross-language:** .NET + Python agents — broader attack surface.
- **AutoGen Studio:** Explicitly "not meant to be production-ready" — no built-in auth/security.
- **Phylax gap to address:** MCP-configured tools get process-level trust. No OS enforcement that a tool's MCP server can only access declared directories.

### 1.7 Manus AI (General-Purpose Agent)
- **Browser automation:** Full browser control for web tasks — session cookie exposure.
- **Code execution:** Runs Python/JS in sandboxes (typically Docker) — but Docker escape is well-documented.
- **Multi-step autonomy:** Long-running tasks with persistent state — window for data exfiltration.
- **Phylax gap to address:** Docker sandbox escape means agent can access host filesystem. OS-level enforcement remains the last line of defense.

### 1.8 OpenAI Agents SDK / Swarm
- **Handoff patterns:** Agents transfer context between each other — context can accumulate secrets.
- **Tool use without validation:** Agent chooses which functions to call — no runtime validation that tool arguments don't contain path traversal.
- **Phylax gap to address:** No OS-level check when agent writes output. File operations bypass all application logic.

### 1.9 Google ADK (Agent Development Kit)
- **Tight GCP integration:** Agents have service account credentials with broad IAM roles.
- **A2A native:** Inter-agent communication over HTTP — network-level attack surface.
- **Phylax gap to address:** Service account credential files (`~/.config/gcloud/`) readable by any agent process.

### 1.10 Anthropic Agent SDK / Claude Code
- **Bash tool:** Claude Code executes arbitrary shell commands with user approval — but approval fatigue leads to auto-approve.
- **File editing:** Direct file system access with write capability.
- **MCP integration:** Connects to MCP servers — inherits MCP security gaps.
- **Phylax gap to address:** Even with approval, no OS-level constraint on *which* files the agent can touch. Approve-once = permanent access.

---

## 2. Agent Memory/Persistence — Security Gaps

### 2.1 State Storage Mechanisms
| Framework | Persistence Method | Files Written |
|---|---|---|
| LangGraph | SQLite/Postgres checkpointer | `*.db`, `*.sqlite` in project dir |
| CrewAI | Memory (short-term + long-term) | In-process + optional DB |
| Cline | `.cline/` directory, git worktrees | Task history, agent memory |
| Browser Use | `browser_use/` data dir | Cookies, localStorage, screenshots |
| Aider | `.aider*` files in project | Chat history, repo map cache |
| AutoGen | AgentChat state | In-process (no default persistence) |

### 2.2 Key Risks
- **Vector DB memory (Chroma, Pinecone, Weaviate):** Agents store embeddings of code/chat/document contents. If agent is compromised, entire knowledge base exfiltratable.
- **Session persistence files:** Contain full conversation history, tool outputs, file diffs. A rogue agent can read other agents' sessions.
- **Browser state:** Browser Use's "persistent filesystem" stores authenticated sessions. Single file copy = session hijacking.
- **Phylax gap to address:** OS-level read/write boundaries between agent sessions. Agent A's memory/state files should not be readable by Agent B's process.

---

## 3. Agent-to-Agent Communication — Security Gaps

### 3.1 MCP (Model Context Protocol)
- **Architecture:** Client-server over stdio or HTTP+SSE. Server exposes tools, resources, prompts.
- **Critical gap (2026):** MCP server can execute arbitrary code. No capability-based security model in the protocol itself — trust is binary (trust/don't trust).
- **Tool declaration spoofing:** Server declares what tools it provides; client has no way to verify server won't execute additional operations.
- **Resource access:** `resources/list` exposes file contents — no read-boundary enforcement.
- **Phylax gap to address:** MCP servers run as OS processes. Phylax can enforce that MCP server process can only read declared resource directories, regardless of what the protocol allows.

### 3.2 A2A (Agent-to-Agent, Google/Linux Foundation, v1.0.1)
- **24.2k stars.** Agent Cards declare capabilities, skills, auth schemes.
- **Security model:** "Preserve Opacity" — agents don't share internal state, memory, or tools. But Agent Cards can declare auth credentials.
- **Streaming (SSE) + push notifications:** long-lived connections — exploit surface for connection hijacking.
- **Discovery:** Agent Cards with credential info — if Card is spoofed, agent sends credentials to malicious endpoint.
- **Phylax gap to address:** A2A is application-layer. Phylax can enforce that A2A client process can only connect to pre-approved network endpoints (by PID → socket filtering in Phase 2 minifilter).

### 3.3 Cross-Agent Attack Surfaces
- **Multi-agent orchestration (CrewAI, AutoGen, LangGraph):** Orchestrator agent delegates to sub-agents with full trust. If any sub-agent is compromised or prompt-injected, all downstream agents inherit the compromise.
- **Cline teams:** Coordinator breaks work into subtasks → specialist agents. Each specialist gets "their own tools and context" — but no filesystem isolation between team members.
- **Phylax gap to address:** OS-level isolation between agent processes in a multi-agent team. Agent A writes to `/workspace/agent-a/`, Agent B to `/workspace/agent-b/` — enforced at FS level, not application level.

---

## 4. Agent Identity/Auth — Security Gaps

### 4.1 API Key Management
- **All frameworks:** API keys stored in `.env` files, environment variables, or framework-specific config. Any agent with shell access can `cat .env`.
- **Browser Use:** Real Chrome profiles contain cookies/sessions for dozens of services — effectively a master key.
- **Cline:** Connects to 10+ LLM providers — all API keys in one config.
- **Phylax gap to address:** Deny read on `.env`, `credentials.json`, `~/.aws/credentials`, `~/.config/gcloud/` for agent processes. These files are known paths that OS-level ACLs can protect.

### 4.2 OAuth for Agents
- **No standard for agent OAuth:** RFC 8628 (device flow) is closest, but agents don't follow it consistently.
- **Service account abuse:** Google ADK agents use GCP service accounts. Agent can enumerate all accessible GCP resources.
- **Phylax gap to address:** Service account key files (`*.json`, `*.pem`) are regular files. OS-level deny-read prevents agent from ever loading them.

### 4.3 Credential Exfiltration Vectors
- **Git:** `git config --global --list` reveals tokens in remote URLs.
- **Shell history:** `~/.bash_history`, `~/.zsh_history` contain previously typed secrets.
- **Clipboard:** Browser agents access system clipboard.
- **Environment:** `env` / `Get-ChildItem Env:` dumps all env vars including secrets.
- **Phylax gap to address:** All exfiltration happens through OS read syscalls. Kernel minifilter can block reads on credential paths before they reach userspace.

---

## 5. Agent Sandboxing — What's Missing

### 5.1 Current Approaches

| Approach | Fails Against |
|---|---|
| **Docker containers** | Container escape CVEs, privileged mode, host filesystem mounts, Docker socket access |
| **gVisor** | Syscall emulation gaps, performance overhead causes users to disable it |
| **Firecracker microVMs** | Best isolation but heavy — not practical for dev laptop agents |
| **WebAssembly sandbox** | Limited to WASM-compatible languages; can't run native Python/Node agents |
| **Python `exec()` / `eval()` isolation** | Trivially bypassed; `import os; os.system("rm -rf /")` |
| **E2B / CodeInterpreter sandboxes** | Cloud-only; local agents have no equivalent |

### 5.2 Why Sandboxing Fails Against Determined Agents
- **LLM is creative:** Agent can generate escape payloads by trial-and-error, reading Docker/K8s CVE databases.
- **Tool chaining:** `browser → download script → execute → escalate` — single sandbox can't see the chain.
- **Persistence:** Agent writes to startup scripts, cron, systemd, LaunchAgents — survives sandbox restart.
- **Phylax unique position:** OS-level enforcement (ACLs on files, kernel minifilter) operates *below* any sandbox. Even if agent escapes Docker, it still can't read files that Phylax denies.

---

## 6. Regulatory Developments (Late 2025-2026)

### 6.1 EU AI Act — Agentic AI Provisions
- **High-risk classification:** Agents that make decisions affecting legal rights, employment, or access to services are "high-risk."
- **Transparency:** Users must know they're interacting with an AI agent.
- **Human oversight:** Mandatory human-in-the-loop for high-risk decisions.
- **Data governance:** Training data and agent state subject to GDPR. Agent memory containing PII must be deletable.
- **Phylax relevance:** Audit logging at OS level proves compliance — all file accesses by agents are recorded.

### 6.2 US Executive Orders
- **AI Safety and Security (Oct 2025 - updated 2026):** Requires developers of "dual-use" AI models to report safety tests. Agent frameworks fall under scrutiny.
- **NIST AI RMF:** Agents classified as AI systems. Risk management framework applies.
- **Phylax relevance:** OS-level enforcement is a compensating control in NIST RMF. "Preventive" controls are weighted higher than "detective" controls.

### 6.3 Industry-Specific Regulations
- **Financial services:** FINRA/SEC scrutinize AI trading agents. OS-level audit trail required.
- **Healthcare:** HIPAA applies to agents handling PHI. File-level access controls mandatory.
- **Government:** FedRAMP for cloud agents. Local agents processing classified info need mandatory access controls (MAC).
- **Phylax relevance:** Phylax provides the file-level audit trail and mandatory access controls these regulations demand.

---

## 7. Agent Observability — What's Invisible

### 7.1 What Current Tools Track
- **LangSmith:** Traces execution paths, state transitions, runtime metrics.
- **CrewAI AMP:** Real-time metrics, logs, traces.
- **OpenTelemetry for agents:** LLM calls, tool invocations, token usage, latency.

### 7.2 What's Invisible to App-Level Observability
- **File read operations:** Agent reads a file but doesn't report what it read. LangSmith can't see that agent read `~/.ssh/id_rsa`.
- **Network connections:** Agent opens socket but observability tool only sees tool call. Can't see agent exfiltrating data to C2 server.
- **Child process spawns:** Agent spawns a shell, shell spawns a crypto miner. Tool trace ends at "ran bash command."
- **DLL injection / process hollowing:** Agent loads malicious DLL. Observability never sees it.
- **Registry modifications:** Agent adds persistence via `HKCU\Run`. Invisible to application-level tracing.
- **Named pipe communication:** Agent uses IPC that observability tool doesn't instrument.

### 7.3 Phylax Unique Visibility
- **OS-level:** Every `CreateFile`, `ReadFile`, `WriteFile`, `DeleteFile` — complete file operation audit.
- **Process tree:** Tracks full parent-child chain from agent launcher → agent → subprocess → payload.
- **Network:** Socket creation by PID — which agent opened which connection.
- **Registry:** Agent persistence mechanisms visible.
- **This is the fundamental gap: Observability tools see what the agent *says* it's doing. Phylax sees what the agent *actually* does at the OS level.**

---

## 8. Summary: Phylax's Unique Value Proposition

### Gaps Only OS-Level Can Address

| Layer | What Can See | What It Misses |
|---|---|---|
| Application (LangSmith, OTel) | LLM calls, tool invocations, state | File reads, network exfil, child processes, registry |
| Container (Docker, gVisor) | Resource limits, syscall filtering | Container escape, host FS mounted paths |
| Agent Framework (rules) | Prompt-based guardrails | Jailbroken agent ignores all guardrails |
| **OS-Level (Phylax)** | **Every I/O operation** | **Nothing at the OS layer** |

### Top 10 Phylax-Addressable Gaps

1. **Agent reads secrets files** → Phylax denies Read on `~/.ssh/`, `.env`, credential paths
2. **Agent writes to system config** → Phylax denies Write on `/etc/`, `~/.bashrc`, startup paths
3. **Agent exfiltrates via network** → Phase 2 minifilter blocks socket creation for agent PID
4. **Agent modifies other agents' state** → Phylax enforces per-agent directory boundaries
5. **Agent persists via registry/startup** → Phylax denies registry Write for agent process
6. **Agent escapes sandbox** → Phylax ACLs apply regardless of container context
7. **Agent deletes audit logs** → Phylax protects its own audit trail with deny-delete ACL
8. **Multi-agent transitive trust** → Phylax assigns per-agent labels, enforces per-label rules
9. **Browser agent steals cookies** → Phylax denies Read on browser profile directories
10. **No observability of actual I/O** → Phylax audit logs every file operation with PID/subject

### Strategic Position
Phylax is positioned as the **last line of defense** — the OS-level enforcement layer that operates below frameworks, below sandboxes, below approval mechanisms. When an agent determines to read, write, or delete a file, Phylax is the final arbiter at the `NtCreateFile` / `NtReadFile` call level. No framework, SDK, or observability tool operates at this depth.

---

*Generated for Phylax security roadmap. Focus areas: credential path protection, per-agent directory isolation, audit completeness, kernel minifilter readiness.*
