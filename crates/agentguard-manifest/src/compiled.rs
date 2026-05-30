use agentguard_core::{
    Bucket, DefaultMode, FileOp, GuardError, GuardResult, PolicyDecision, PolicySource,
};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::{Path, PathBuf};

use crate::parser::ProjectManifest;

/// Manifest compilado: los globs ya estan convertidos a GlobSets
/// para matching O(1). Listo para usar en el hot path.
#[derive(Debug, Clone)]
pub struct CompiledManifest {
    pub workspace_root: PathBuf,
    pub default_mode: DefaultMode,
    deny_count: usize,
    ask_count: usize,
    write_count: usize,
    delete_count: usize,
    read_count: usize,
    deny: GlobSet,
    ask: GlobSet,
    full: GlobSet,
    delete: GlobSet,
    write: GlobSet,
    read: GlobSet,
}

impl CompiledManifest {
    /// Compila un ProjectManifest a GlobSets.
    /// `workspace_root` es la carpeta donde esta el agentguard.toml.
    pub fn compile(manifest: &ProjectManifest, workspace_root: PathBuf) -> GuardResult<Self> {
        Ok(Self {
            workspace_root,
            default_mode: manifest.project.default.clone(),
            deny_count: manifest.deny.files.len(),
            ask_count: manifest.ask.files.len(),
            write_count: manifest.write.files.len(),
            delete_count: manifest.delete.files.len(),
            read_count: manifest.read.files.len(),
            deny: build_globset(&manifest.deny.files, "deny")?,
            ask: build_globset(&manifest.ask.files, "ask")?,
            full: build_globset(&manifest.full.files, "full")?,
            delete: build_globset(&manifest.delete.files, "delete")?,
            write: build_globset(&manifest.write.files, "write")?,
            read: build_globset(&manifest.read.files, "read")?,
        })
    }

    /// Evalua si una operacion sobre un path esta permitida.
    ///
    /// **CONTRATO DE SEGURIDAD:** `abs_path` debe ser un path absoluto y
    /// canonicalizado (`std::fs::canonicalize`) antes de llamar a este metodo.
    /// De lo contrario, un symlink puede hacer bypass de las reglas
    /// (ver AGENTS.md — CVE-2025-59829).
    ///
    /// Para Global/Agent manifests (workspace_root vacio), los patrones
    /// se evaluan contra el path absoluto completo (via prefix `**/`).
    pub fn evaluate(&self, abs_path: &Path, op: &FileOp) -> (PolicyDecision, PolicySource) {
        debug_assert!(
            abs_path.is_absolute() || abs_path.has_root(),
            "SECURITY: path must be absolute/canonicalized before evaluate(): {}",
            abs_path.display()
        );
        let bucket = self.bucket_for_path(abs_path);

        let decision = match bucket {
            Some(Bucket::Deny) => PolicyDecision::Deny,
            Some(Bucket::Ask) => PolicyDecision::Ask {
                path: abs_path.to_path_buf(),
                op: *op,
            },

            Some(Bucket::Full) => PolicyDecision::Allow,

            Some(Bucket::Delete) => match op {
                FileOp::Read | FileOp::Delete => PolicyDecision::Allow,
                FileOp::Write => self.apply_default(abs_path, op),
            },

            Some(Bucket::Write) => match op {
                FileOp::Read | FileOp::Write => PolicyDecision::Allow,
                FileOp::Delete => PolicyDecision::Deny,
            },

            Some(Bucket::Read) => match op {
                FileOp::Read => PolicyDecision::Allow,
                _ => PolicyDecision::Deny,
            },

            None => self.apply_default(abs_path, op),
        };

        let source = if bucket.is_some() {
            PolicySource::Project
        } else {
            PolicySource::Default
        };

        (decision, source)
    }

    pub fn bucket_for_path(&self, abs_path: &Path) -> Option<Bucket> {
        let rel = abs_path.strip_prefix(&self.workspace_root).ok()?;
        self.winning_bucket(rel)
    }

    fn winning_bucket(&self, rel: &Path) -> Option<Bucket> {
        if self.deny.is_match(rel) {
            return Some(Bucket::Deny);
        }
        if self.ask.is_match(rel) {
            return Some(Bucket::Ask);
        }
        if self.full.is_match(rel) {
            return Some(Bucket::Full);
        }
        if self.delete.is_match(rel) {
            return Some(Bucket::Delete);
        }
        if self.write.is_match(rel) {
            return Some(Bucket::Write);
        }
        if self.read.is_match(rel) {
            return Some(Bucket::Read);
        }
        None
    }

    pub fn apply_default(&self, abs_path: &Path, op: &FileOp) -> PolicyDecision {
        match self.default_mode {
            DefaultMode::Unrestricted => PolicyDecision::Allow,
            DefaultMode::Conservative => match op {
                FileOp::Read => PolicyDecision::Allow,
                FileOp::Write => PolicyDecision::Ask {
                    path: abs_path.to_path_buf(),
                    op: *op,
                },
                FileOp::Delete => PolicyDecision::Deny,
            },
        }
    }

    pub fn bucket_counts(&self) -> (usize, usize, usize, usize, usize) {
        (
            self.deny_count,
            self.ask_count,
            self.write_count,
            self.delete_count,
            self.read_count,
        )
    }
}

fn build_globset(patterns: &[String], _bucket_name: &str) -> GuardResult<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern).map_err(|e| GuardError::InvalidGlob {
            pattern: pattern.clone(),
            reason: e.to_string(),
        })?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| GuardError::ManifestParse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ProjectManifest;

    fn compile(toml: &str) -> CompiledManifest {
        let manifest = ProjectManifest::parse_str(toml).unwrap();
        CompiledManifest::compile(&manifest, PathBuf::from("/workspace")).unwrap()
    }

    #[test]
    fn deny_blocks_all_ops() {
        let cm = compile(
            r#"[deny]
files = [".env"]"#,
        );
        let path = Path::new("/workspace/.env");

        assert_eq!(cm.evaluate(path, &FileOp::Read).0, PolicyDecision::Deny);
        assert_eq!(cm.evaluate(path, &FileOp::Write).0, PolicyDecision::Deny);
        assert_eq!(cm.evaluate(path, &FileOp::Delete).0, PolicyDecision::Deny);
    }

    #[test]
    fn deny_beats_write() {
        let cm = compile(
            r#"
[deny]
files = [".env"]
[write]
files = [".env"]
"#,
        );
        let (decision, _) = cm.evaluate(Path::new("/workspace/.env"), &FileOp::Write);
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn write_bucket_blocks_delete() {
        let cm = compile(
            r#"[write]
files = ["src/**"]"#,
        );
        let path = Path::new("/workspace/src/main.rs");

        assert_eq!(cm.evaluate(path, &FileOp::Read).0, PolicyDecision::Allow);
        assert_eq!(cm.evaluate(path, &FileOp::Write).0, PolicyDecision::Allow);
        assert_eq!(cm.evaluate(path, &FileOp::Delete).0, PolicyDecision::Deny);
    }

    #[test]
    fn conservative_default_ask_on_write() {
        let cm = compile(
            r#"[project]
default = "conservative""#,
        );
        let path = Path::new("/workspace/anything.txt");

        let (r, _) = cm.evaluate(path, &FileOp::Read);
        let (w, _) = cm.evaluate(path, &FileOp::Write);
        let (d, _) = cm.evaluate(path, &FileOp::Delete);

        assert_eq!(r, PolicyDecision::Allow);
        assert_eq!(
            w,
            PolicyDecision::Ask {
                path: path.to_path_buf(),
                op: FileOp::Write
            }
        );
        assert_eq!(d, PolicyDecision::Deny);
    }

    #[test]
    fn path_outside_workspace_allows() {
        let cm = compile(
            r#"[deny]
files = ["**"]"#,
        );
        let (decision, source) = cm.evaluate(Path::new("/other/secret.key"), &FileOp::Read);
        assert_eq!(decision, PolicyDecision::Allow);
        assert_eq!(source, PolicySource::Default);
    }

    /// CVE-2025-59829 regression: symlink bypass blocked via canonicalize.
    ///
    /// Create a workspace where `outside/` is denied. Create a symlink
    /// `safe/link → outside/`. Attempt to access `safe/link/secret.txt`.
    /// After canonicalize resolves the symlink, the path maps to
    /// `outside/secret.txt` which MUST be denied.
    #[cfg(unix)]
    #[test]
    fn symlink_bypass_blocked_via_canonicalize() {
        use std::os::unix::fs as unix_fs;

        let tmp = tempfile::tempdir().unwrap();
        let workspace_raw = tmp.path();
        let workspace = std::fs::canonicalize(workspace_raw).unwrap();

        let outside = workspace.join("outside");
        let safe = workspace.join("safe");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(&safe).unwrap();

        let secret = outside.join("secret.txt");
        std::fs::write(&secret, b"API_KEY=secret").unwrap();

        let link = safe.join("link");
        unix_fs::symlink(&outside, &link).unwrap();

        let manifest = ProjectManifest::parse_str(
            r#"
[deny]
files = ["outside/**"]
"#,
        )
        .unwrap();
        let compiled = CompiledManifest::compile(&manifest, workspace.clone()).unwrap();

        let symlink_target = link.join("secret.txt");
        let canonical = std::fs::canonicalize(&symlink_target).unwrap();

        let (decision, _source) = compiled.evaluate(&canonical, &FileOp::Read);
        assert_eq!(
            decision,
            PolicyDecision::Deny,
            "CVE-2025-59829: symlink bypass — canonicalized path {:?} should be Deny",
            canonical
        );
    }

    /// Cross-platform test: canonicalize + evaluate respects deny rules on real files.
    /// Verifies that the canonicalize-before-evaluate contract works end-to-end,
    /// which is the mitigation for CVE-2025-59829.
    #[test]
    fn canonicalized_path_respects_deny() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace_raw = tmp.path();
        let workspace = std::fs::canonicalize(workspace_raw).unwrap();

        let outside = workspace.join("outside");
        std::fs::create_dir(&outside).unwrap();

        let secret = outside.join("secret.txt");
        std::fs::write(&secret, b"API_KEY=secret").unwrap();

        let manifest = ProjectManifest::parse_str(
            r#"
[deny]
files = ["outside/**"]
"#,
        )
        .unwrap();
        let compiled = CompiledManifest::compile(&manifest, workspace.clone()).unwrap();

        let canonical = std::fs::canonicalize(&secret).unwrap();
        let (decision, _source) = compiled.evaluate(&canonical, &FileOp::Read);
        assert_eq!(decision, PolicyDecision::Deny);

        let (decision, _source) = compiled.evaluate(&canonical, &FileOp::Write);
        assert_eq!(decision, PolicyDecision::Deny);

        let (decision, _source) = compiled.evaluate(&canonical, &FileOp::Delete);
        assert_eq!(decision, PolicyDecision::Deny);
    }
}
