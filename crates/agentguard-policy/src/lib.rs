//! CompiledPolicy — integra reglas globales (DB) + reglas de proyecto (agentguard.toml).
//!
//! La capa global SIEMPRE gana sobre la de proyecto.

use std::path::Path;

use agentguard_core::{Bucket, FileOp, GuardResult, PolicyDecision, PolicySource};
use agentguard_manifest::{CompiledManifest, ProjectManifest};

pub struct CompiledPolicy {
    global: Option<CompiledManifest>,
    project: Option<CompiledManifest>,
}

impl CompiledPolicy {
    pub fn from_project(
        manifest: &ProjectManifest,
        workspace_root: std::path::PathBuf,
    ) -> GuardResult<Self> {
        let compiled = CompiledManifest::compile(manifest, workspace_root)?;
        Ok(CompiledPolicy {
            global: None,
            project: Some(compiled),
        })
    }

    pub fn with_global_rules(mut self, rules: &[(Bucket, String)]) -> GuardResult<Self> {
        let mut manifest = ProjectManifest::default();
        for (bucket, path) in rules {
            match bucket {
                Bucket::Deny => manifest.deny.files.push(path.clone()),
                Bucket::Ask => manifest.ask.files.push(path.clone()),
                Bucket::Full => manifest.full.files.push(path.clone()),
                Bucket::Delete => manifest.delete.files.push(path.clone()),
                Bucket::Write => manifest.write.files.push(path.clone()),
                Bucket::Read => manifest.read.files.push(path.clone()),
            }
        }
        let root = self
            .project
            .as_ref()
            .map(|p| p.workspace_root.clone())
            .unwrap_or_else(|| std::path::PathBuf::from("/"));
        let compiled = CompiledManifest::compile(&manifest, root)?;
        self.global = Some(compiled);
        Ok(self)
    }

    pub fn evaluate_file_op(&self, abs_path: &Path, op: &FileOp) -> (PolicyDecision, PolicySource) {
        // Global rules always win
        if let Some(ref global) = self.global {
            let (decision, source) = global.evaluate(abs_path, op);
            if matches!(decision, PolicyDecision::Deny | PolicyDecision::Ask { .. }) {
                return (decision, PolicySource::Global);
            }
            if source == PolicySource::Project {
                return (decision, PolicySource::Global);
            }
        }

        // Project rules
        if let Some(ref project) = self.project {
            return project.evaluate(abs_path, op);
        }

        // Default
        (PolicyDecision::Allow, PolicySource::Default)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_manifest() -> ProjectManifest {
        let toml = r#"
[project]
name = "test"
default = "conservative"

[deny]
files = [".env"]

[ask]
files = ["Cargo.lock"]

[write]
files = ["src/**"]
"#;
        ProjectManifest::parse_str(toml).unwrap()
    }

    #[test]
    fn test_project_deny() {
        let policy = CompiledPolicy::from_project(
            &sample_manifest(),
            std::path::PathBuf::from("/workspace"),
        )
        .unwrap();

        let (decision, source) =
            policy.evaluate_file_op(Path::new("/workspace/.env"), &FileOp::Read);
        assert_eq!(decision, PolicyDecision::Deny);
        assert_eq!(source, PolicySource::Project);
    }

    #[test]
    fn test_project_allow_write() {
        let policy = CompiledPolicy::from_project(
            &sample_manifest(),
            std::path::PathBuf::from("/workspace"),
        )
        .unwrap();

        let (decision, _) =
            policy.evaluate_file_op(Path::new("/workspace/src/main.rs"), &FileOp::Write);
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_global_overrides_project() {
        let policy = CompiledPolicy::from_project(
            &sample_manifest(),
            std::path::PathBuf::from("/workspace"),
        )
        .unwrap()
        .with_global_rules(&[(Bucket::Deny, "src/**".to_string())])
        .unwrap();

        let (decision, source) =
            policy.evaluate_file_op(Path::new("/workspace/src/main.rs"), &FileOp::Read);
        assert_eq!(decision, PolicyDecision::Deny);
        assert_eq!(source, PolicySource::Global);
    }

    #[test]
    fn global_ask_beats_project_write() {
        let policy = CompiledPolicy::from_project(
            &sample_manifest(),
            std::path::PathBuf::from("/workspace"),
        )
        .unwrap()
        .with_global_rules(&[(Bucket::Ask, "src/**".to_string())])
        .unwrap();

        let (decision, source) =
            policy.evaluate_file_op(Path::new("/workspace/src/main.rs"), &FileOp::Write);
        assert!(matches!(decision, PolicyDecision::Ask { .. }));
        assert_eq!(source, PolicySource::Global);
    }

    #[test]
    fn project_ask_returns_ask_decision() {
        let policy = CompiledPolicy::from_project(
            &sample_manifest(),
            std::path::PathBuf::from("/workspace"),
        )
        .unwrap();

        let (decision, source) =
            policy.evaluate_file_op(Path::new("/workspace/Cargo.lock"), &FileOp::Write);
        assert!(matches!(decision, PolicyDecision::Ask { .. }));
        assert_eq!(source, PolicySource::Project);
    }

    #[test]
    fn default_unrestricted_allows_delete() {
        let toml = r#"
[project]
name = "test"
default = "unrestricted"
"#;
        let manifest = ProjectManifest::parse_str(toml).unwrap();
        let policy =
            CompiledPolicy::from_project(&manifest, std::path::PathBuf::from("/workspace"))
                .unwrap();

        let (decision, source) =
            policy.evaluate_file_op(Path::new("/workspace/anything.txt"), &FileOp::Delete);
        assert_eq!(decision, PolicyDecision::Allow);
        assert_eq!(source, PolicySource::Default);
    }

    #[test]
    fn global_full_beats_project_deny() {
        let toml = r#"
[project]
name = "test"
default = "conservative"

[deny]
files = [".env"]
"#;
        let manifest = ProjectManifest::parse_str(toml).unwrap();
        let policy =
            CompiledPolicy::from_project(&manifest, std::path::PathBuf::from("/workspace"))
                .unwrap()
                .with_global_rules(&[(Bucket::Full, ".env".to_string())])
                .unwrap();

        let (decision, source) =
            policy.evaluate_file_op(Path::new("/workspace/.env"), &FileOp::Read);
        assert_eq!(decision, PolicyDecision::Allow);
        assert_eq!(source, PolicySource::Global);
    }

    #[test]
    fn no_rules_uses_project_default() {
        let toml = r#"
[project]
name = "test"
default = "conservative"
"#;
        let manifest = ProjectManifest::parse_str(toml).unwrap();
        let policy =
            CompiledPolicy::from_project(&manifest, std::path::PathBuf::from("/workspace"))
                .unwrap();

        let (read, _) = policy.evaluate_file_op(Path::new("/workspace/file.txt"), &FileOp::Read);
        let (write, _) = policy.evaluate_file_op(Path::new("/workspace/file.txt"), &FileOp::Write);
        let (delete, _) =
            policy.evaluate_file_op(Path::new("/workspace/file.txt"), &FileOp::Delete);

        assert_eq!(read, PolicyDecision::Allow);
        assert!(matches!(write, PolicyDecision::Ask { .. }));
        assert_eq!(delete, PolicyDecision::Deny);
    }
}
