use agentguard_core::{Bucket, GuardResult};
use agentguard_manifest::CompiledManifest;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "target", "__pycache__", ".venv", "vendor",
];

#[derive(Clone)]
pub struct Enforcer {
    workspace_root: PathBuf,
    cached_deny_paths: HashSet<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PathProtectionHealth {
    pub path: PathBuf,
    pub health: crate::ace::ProtectionHealth,
}

impl Enforcer {
    pub fn new(workspace_root: PathBuf) -> Self {
        let root = std::fs::canonicalize(&workspace_root).unwrap_or(workspace_root);
        let root = strip_verbatim_prefix(root);
        Self {
            workspace_root: root,
            cached_deny_paths: HashSet::new(),
        }
    }

    pub fn apply_project_protections(&mut self, manifest: &CompiledManifest) -> GuardResult<()> {
        let deny_paths = self.collect_paths_for_bucket(manifest, Bucket::Deny);
        let write_paths = self.collect_paths_for_bucket(manifest, Bucket::Write);
        let delete_paths = self.collect_paths_for_bucket(manifest, Bucket::Delete);
        let read_paths = self.collect_paths_for_bucket(manifest, Bucket::Read);

        for path in deny_paths.iter().chain(read_paths.iter()) {
            crate::ace::apply_deny_ace(path)?;
        }
        for path in write_paths.iter().chain(read_paths.iter()) {
            crate::ace::apply_delete_deny_ace(path)?;
        }
        for path in delete_paths.iter() {
            crate::ace::apply_write_deny_ace(path)?;
        }

        let mut all = deny_paths;
        all.extend(write_paths); all.extend(delete_paths); all.extend(read_paths);
        self.cached_deny_paths = all;
        Ok(())
    }

    pub fn release_project_protections(&self) -> GuardResult<()> {
        for path in &self.cached_deny_paths {
            if let Err(e) = crate::ace::remove_deny_ace(path) {
                eprintln!(
                    "[daemon] WARN: failed to remove ACE from {}: {e}",
                    path.display()
                );
            }
        }
        Ok(())
    }

    pub fn temporarily_allow(&self, path: &Path) -> GuardResult<()> {
        crate::ace::remove_deny_ace(path)
    }

    pub fn reapply_ask(&self, path: &Path) -> GuardResult<()> {
        crate::ace::apply_deny_ace(path)
    }

    pub fn add_to_deny_cache(&mut self, path: PathBuf) {
        self.cached_deny_paths.insert(path);
    }

    pub fn remove_from_deny_cache(&mut self, path: &Path) {
        self.cached_deny_paths.remove(path);
    }

    pub fn cached_deny_paths(&self) -> &HashSet<PathBuf> {
        &self.cached_deny_paths
    }

    pub fn audit_project_protections(
        &self,
        manifest: &CompiledManifest,
    ) -> GuardResult<Vec<PathProtectionHealth>> {
        let mut deny_paths: Vec<PathBuf> = self
            .collect_paths_for_bucket(manifest, Bucket::Deny)
            .into_iter()
            .collect();
        deny_paths.sort();

        let mut out = Vec::with_capacity(deny_paths.len());
        for path in deny_paths {
            let health = crate::ace::verify_ace(&path)?;
            out.push(PathProtectionHealth { path, health });
        }
        Ok(out)
    }

    fn collect_paths_for_bucket(
        &self,
        manifest: &CompiledManifest,
        target: Bucket,
    ) -> HashSet<PathBuf> {
        let mut result = HashSet::new();

        let walker = walkdir::WalkDir::new(&self.workspace_root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !SKIP_DIRS.iter().any(|skip| name.as_ref() == *skip)
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file());

        for entry in walker {
            let path = entry.path();
            if manifest.bucket_for_path(path) == Some(target) {
                result.insert(path.to_path_buf());
            }
        }

        result
    }
}

fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix("\\\\?\\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use agentguard_core::Bucket;
    use agentguard_manifest::{CompiledManifest, ProjectManifest};
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn make_manifest(workspace: &Path, _spec: &str) -> CompiledManifest {
        let toml = r#"
[project]
name = "test"
default = "unrestricted"

[deny]
files = ["*.env", "secrets/**"]

[ask]
files = ["*.lock"]

[write]
files = ["src/**"]

[read]
files = ["docs/**"]
"#;
        let manifest = ProjectManifest::parse_str(toml).unwrap();
        manifest.compile(workspace.to_path_buf()).unwrap()
    }

    fn create_files(dir: &TempDir) -> Vec<PathBuf> {
        let paths = vec![
            dir.path().join(".env"),
            dir.path().join("secrets").join("key.pem"),
            dir.path().join("Cargo.lock"),
            dir.path().join("src").join("main.rs"),
            dir.path().join("docs").join("readme.md"),
            dir.path().join("public").join("index.html"),
        ];

        for p in &paths {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(p, "test content").unwrap();
        }

        paths
    }

    #[test]
    fn collect_deny_paths_finds_dotenv() {
        let tmp = TempDir::new().unwrap();
        create_files(&tmp);
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let root = strip_verbatim_prefix(root);
        let manifest = make_manifest(&root, "");
        let enforcer = Enforcer::new(root.clone());

        let paths = enforcer.collect_paths_for_bucket(&manifest, Bucket::Deny);

        let expected = root.join(".env");
        assert!(paths.contains(&expected));
    }

    #[test]
    fn collect_deny_paths_includes_agentguard_toml_when_denied() {
        let tmp = TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let root = strip_verbatim_prefix(root);

        let toml_path = root.join("agentguard.toml");
        std::fs::write(&toml_path, "deny me").unwrap();

        let manifest = ProjectManifest::parse_str(
            r#"
[project]
name = "test"
default = "unrestricted"

[deny]
files = ["agentguard.toml"]
"#,
        )
        .unwrap()
        .compile(root.clone())
        .unwrap();
        let enforcer = Enforcer::new(root.clone());

        let paths = enforcer.collect_paths_for_bucket(&manifest, Bucket::Deny);
        assert!(paths.contains(&toml_path));
    }

    #[test]
    fn collect_paths_include_deep_files() {
        let tmp = TempDir::new().unwrap();
        let deep = tmp.path().join("a/b/c/d/e/f/g/h/i/j/k/file.txt");
        std::fs::create_dir_all(deep.parent().unwrap()).unwrap();
        std::fs::write(&deep, "SECRET").unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let root = strip_verbatim_prefix(root);
        let manifest = ProjectManifest::parse_str(
            r#"
[project]
name = "test"
default = "unrestricted"

[deny]
files = ["**/*.txt"]
"#,
        )
        .unwrap()
        .compile(root.clone())
        .unwrap();
        let enforcer = Enforcer::new(root.clone());

        let paths = enforcer.collect_paths_for_bucket(&manifest, Bucket::Deny);

        assert!(paths.contains(&deep));
    }

    #[test]
    fn collect_paths_include_git_when_denied() {
        let tmp = TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let root = strip_verbatim_prefix(root);

        let git_config = root.join(".secrets").join("config");
        std::fs::create_dir_all(git_config.parent().unwrap()).unwrap();
        std::fs::write(&git_config, "[core]").unwrap();

        let manifest = ProjectManifest::parse_str(
            r#"
[project]
name = "test"
default = "unrestricted"

[deny]
files = [".secrets/**"]
"#,
        )
        .unwrap()
        .compile(root.clone())
        .unwrap();
        let enforcer = Enforcer::new(root.clone());

        let paths = enforcer.collect_paths_for_bucket(&manifest, Bucket::Deny);
        assert!(paths.contains(&git_config));
    }

    #[test]
    fn empty_workspace_no_panic() {
        let tmp = TempDir::new().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let root = strip_verbatim_prefix(root);
        let manifest = make_manifest(&root, "");
        let enforcer = Enforcer::new(root.clone());

        let paths = enforcer.collect_paths_for_bucket(&manifest, Bucket::Deny);

        assert!(paths.is_empty());
    }

    #[test]
    fn deny_cache_is_populated_after_apply() {
        let tmp = TempDir::new().unwrap();
        create_files(&tmp);
        let root = std::fs::canonicalize(tmp.path()).unwrap();
        let root = strip_verbatim_prefix(root);
        let manifest = make_manifest(&root, "");
        let mut enforcer = Enforcer::new(root.clone());

        assert!(enforcer.cached_deny_paths().is_empty());
        enforcer.apply_project_protections(&manifest).unwrap();

        let expected = root.join(".env");
        assert!(enforcer.cached_deny_paths().contains(&expected));
        assert!(enforcer.cached_deny_paths().len() >= 2);
    }
}
