# 03 — Manifest & Policy Engine (`agentguard-manifest` + `agentguard-policy`)

## phylax.toml Specification

### Full Example

```toml
# phylax.toml — project root

[project]
name    = "my-app"
default = "conservative"   # conservative | unrestricted

[deny]
files = [
    ".env", ".env.*",
    "*.pem", "*.key", "*.p12",
    ".git/**",
    "secrets/**",
]

[ask]
files = [
    "Cargo.lock",
    "package-lock.json",
    "*.config.js",
    "*.config.ts",
]

[full]
files = [
    "temp/**",
]

[delete]
files = [
    "target/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "*.log",
    "tmp/**",
]

[write]
files = [
    "src/**",
    "tests/**",
    "Cargo.toml",
    "package.json",
]

[read]
files = [
    "docs/**/*.md",
    "README.md",
    ".cursor/rules/**",
]
```

### Bucket Behavior

| Bucket | File matched? | Read | Write | Delete |
|--------|--------------|------|-------|--------|
| deny   | Yes          | Deny | Deny  | Deny   |
| ask    | Yes          | Ask  | Ask   | Ask    |
| full   | Yes          | Allow| Allow | Allow  |
| delete | Yes          | Allow| Default* | Allow |
| write  | Yes          | Allow| Allow | Deny   |
| read   | Yes          | Allow| Deny  | Deny   |
| (none) | No           | Default* | Default* | Default* |

\* Default depends on `default_mode`: conservative or unrestricted.

### Glob Syntax

Standard Unix glob syntax with `**` support. On Windows, both `/` and `\` are
recognized as path separators.

- `*.env` — matches `.env` in the workspace root
- `src/**/*.rs` — matches all `.rs` files under `src/`
- `secrets/**` — matches everything under `secrets/`
- `.git/**` — matches everything under `.git/`

### Discovery

`find_manifest(start_path)` walks up the directory tree looking for `phylax.toml`.
Returns the first one found, or `ManifestNotFound` error.

## CompiledManifest

`ProjectManifest` is parsed from TOML, then compiled into `CompiledManifest` which
stores pre-compiled `GlobSet`s for each bucket. This enables O(1) matching at runtime.

```rust
pub struct CompiledManifest {
    pub workspace_root: PathBuf,
    pub default_mode:   DefaultMode,
    // 6 GlobSets (one per bucket), all private
}
```

### compile()

```rust
let manifest = ProjectManifest::parse_str(toml_content)?;
let compiled = CompiledManifest::compile(&manifest, workspace_root)?;
```

### evaluate()

```rust
let (decision, source) = compiled.evaluate(abs_path, &FileOp::Read);
```

Returns `(PolicyDecision, PolicySource)`.

**IMPORTANT**: `abs_path` MUST be canonicalized (`std::fs::canonicalize`) before
calling `evaluate()`. This prevents symlink bypass (CVE-2025-59829).

### bucket_for_path()

```rust
pub fn bucket_for_path(&self, abs_path: &Path) -> Option<Bucket>
```

Returns the winning bucket for a path, or `None` if no bucket matches.

### apply_default()

```rust
pub fn apply_default(&self, abs_path: &Path, op: &FileOp) -> PolicyDecision
```

Returns the decision based on `default_mode` when no explicit bucket matches.

### winning_bucket() (private)

Checks buckets in priority order: deny → ask → full → delete → write → read.
Stops at the first match. Returns `None` if no match.

## CompiledPolicy

Wraps global + project manifests to enforce global > project > default layering.

```rust
pub struct CompiledPolicy {
    global:  Option<CompiledManifest>,
    project: Option<CompiledManifest>,
}
```

### evaluate_file_op()

```rust
pub fn evaluate_file_op(&self, abs_path: &Path, op: &FileOp)
    -> (PolicyDecision, PolicySource)
```

Evaluation order:
1. **Global rules**: if non-Allow, return with `PolicySource::Global`
2. **Project rules**: if non-Allow, return with `PolicySource::Project`
3. **Default**: return with `PolicySource::Default`

## Global Rules

Global rules live in the `global_rules` SQLite table, not in a TOML file.
They apply to ALL projects and are managed via the CLI:

```powershell
agentguard global add deny "C:\Users\*\.ssh\**"
agentguard global add ask "*.lock"
agentguard global list
agentguard global remove 1
```

Patterns without path separators (`\` or `/`) are auto-expanded to `**/pattern`
so they match anywhere in the filesystem.

For evaluation, global rules are compiled into a `CompiledManifest` with an
empty workspace root. Since `strip_prefix("")` always succeeds, the full
absolute path is used for glob matching.
