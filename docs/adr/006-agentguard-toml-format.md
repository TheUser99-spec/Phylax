# ADR-006: agentguard.toml Format & Backward Compatibility

**Status**: Accepted

## Context

Every AgentGuard-protected project contains an `agentguard.toml` file that defines
which files AI agents can read, write, or delete. This file is:
- Created by `agentguard init` (7-layer auto-detection)
- Edited manually by developers
- Parsed by `agentguard-manifest` and compiled into GlobSets
- Version-controlled alongside project source code

The format must be:
- Human-readable and writable (developers edit it by hand)
- Machine-parsable with clear error messages
- Backward-compatible (upgrading AgentGuard must never break existing projects)
- Versioned (future format changes must be detectable)

## Decision

Use **TOML** as the configuration format with the following schema:

```toml
[project]
name = "MyProject"
version = "0.1.0"
default = "conservative"  # or "unrestricted"

[deny]
files = ["**/*.key", ".env", ".git/**"]

[ask]
files = ["Cargo.lock", "package-lock.json"]

[full]
files = ["src/**"]

[delete]
files = ["target/**", "node_modules/**"]

[write]
files = ["**/*.rs", "**/*.ts"]

[read]
files = ["docs/**", "README.md"]
```

### Why TOML over alternatives

- **TOML**: Officially supported by Cargo (Rust's build system), familiar to Rust
  developers, strict typing, good error messages.
- **YAML**: Overly complex (anchors, aliases, multi-line string quirks), indentation
  errors are silent, no schema validation.
- **JSON**: No comments, verbose syntax (double quotes everywhere), poor readability
  for humans editing by hand.
- **INI**: No nested sections, no arrays of strings natively, too limited.

### Backward Compatibility Strategy

1. **Schema versioning**: The `[project]` section always carries a `version` field.
   Future AgentGuard versions read this field to detect old-format manifests and
   apply migrations.
2. **Additive changes only**: New buckets or fields are added with defaults that
   preserve existing behavior. Example: if a `[network]` bucket is added in v2.0,
   projects without it default to "no restrictions" (equivalent to current behavior).
3. **Deprecation with warnings**: If a field is renamed or removed, old manifests
   continue to work with a deprecation warning printed to stderr. Support is removed
   after 2 major versions.
4. **Never silently break**: `agentguard project validate` returns validation errors
   for invalid manifests, never silently ignores unknown or malformed fields.
5. **Migration tool**: A future `agentguard migrate` command will automatically update
   `agentguard.toml` from old formats to the current version.

## Consequences

- Developers are already familiar with TOML from `Cargo.toml`, `pyproject.toml`,
  `taplo.toml` — zero learning curve.
- The `toml` crate provides strict parsing with line/column error reporting.
  Malformed manifests produce actionable error messages.
- Adding a new bucket (e.g., `[execute]` for process execution control) is a
  single new section addition — no format redesign needed.
- TOML's lack of programmatic features (no conditionals, no includes, no variables)
  is intentional — the file describes policy, not logic. Complex policy is expressed
  through the 6-bucket priority system, not through scripting.

## Alternatives Considered

1. **YAML**: Rejected — too many footguns (Norway problem, `yes`/`no` as booleans,
   indentation-sensitive). YAML parsers are larger and slower than TOML parsers.
2. **JSON**: Rejected — no comments means developers must document policy choices
   elsewhere, breaking the self-documenting nature of `agentguard.toml`.
3. **JSONC (JSON with Comments)**: Rejected — no standard Rust parser, VS Code-specific,
   not a universal format.
4. **KDL (Cuddly Document Language)**: Rejected — too niche, no mature Rust ecosystem,
   developers would need to learn a new syntax.
5. **Custom DSL**: Rejected — reinventing the wheel, need parser, lexer, error
   reporting, syntax highlighting for IDEs. TOML has all of this already.
