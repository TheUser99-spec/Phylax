use agentguard_core::{DefaultMode, GuardError, GuardResult};
use std::path::{Path, PathBuf};

use crate::parser::{BucketSpec, ProjectManifest};

/// Busca `agentguard.toml` desde `start` hacia arriba en el arbol de directorios.
///
/// Devuelve la ruta al fichero si se encuentra, o `ManifestNotFound` si no.
pub fn find_manifest(start: &Path) -> GuardResult<PathBuf> {
    let mut current = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };

    loop {
        let candidate = current.join("agentguard.toml");
        if candidate.exists() {
            return Ok(candidate);
        }

        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                return Err(GuardError::ManifestNotFound {
                    path: start.display().to_string(),
                })
            }
        }
    }
}

// ── Auto-Detection 7-Layer ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Rust,
    Node,
    Python,
    Go,
    Java,
    Unknown,
}

impl Language {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rust => "Rust",
            Self::Node => "Node.js",
            Self::Python => "Python",
            Self::Go => "Go",
            Self::Java => "Java",
            Self::Unknown => "unknown",
        }
    }
}

/// S1: Detecta el lenguaje del proyecto mirando ficheros de configuracion.
pub fn detect_language(root: &Path) -> Language {
    if root.join("Cargo.toml").exists() {
        return Language::Rust;
    }
    if root.join("package.json").exists() {
        return Language::Node;
    }
    if root.join("pyproject.toml").exists()
        || root.join("requirements.txt").exists()
        || root.join("setup.py").exists()
    {
        return Language::Python;
    }
    if root.join("go.mod").exists() {
        return Language::Go;
    }
    if root.join("pom.xml").exists() || root.join("build.gradle").exists() {
        return Language::Java;
    }
    Language::Unknown
}

/// S2: Detecta ficheros de secrets en el arbol del proyecto.
pub fn detect_secrets(root: &Path) -> Vec<String> {
    let mut patterns: Vec<String> = Vec::new();
    let sensitive_extensions = [".pem", ".key", ".p12", ".pfx", ".pkcs8", ".der"];
    let sensitive_names: &[&str] = &[
        ".env",
        ".netrc",
        "_netrc",
        "credentials",
        ".npmrc",
        ".pypirc",
    ];

    let walker = walkdir::WalkDir::new(root)
        .max_depth(4)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            name != "target" && name != "node_modules" && name != ".git" && name != "__pycache__"
        });

    let mut found_root = false;

    for entry in walker.filter_map(|e| match e {
        Ok(entry) => Some(entry),
        Err(err) => {
            eprintln!("[discovery] WARN: cannot access entry during secrets scan: {err}");
            None
        }
    }) {
        let abs = entry.path();
        let name = abs.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Strip workspace root
        let rel = match abs.strip_prefix(root) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let is_root = rel
            .parent()
            .map(|p| p.as_os_str().is_empty())
            .unwrap_or(true);

        // Secret files by exact name
        for sn in sensitive_names {
            if name == *sn || (sn.starts_with('.') && name.starts_with(sn)) {
                if sn == &".env" {
                    if is_root {
                        patterns.push(".env".to_string());
                        patterns.push(".env.*".to_string());
                    } else {
                        patterns.push("**/.env".to_string());
                        patterns.push("**/.env.*".to_string());
                    }
                    found_root = true;
                    break;
                } else {
                    patterns.push(format!("**/{name}"));
                    break;
                }
            }
        }

        // Secret files by extension
        for ext in &sensitive_extensions {
            if name.ends_with(ext) {
                patterns.push(format!("**/*{ext}"));
                break;
            }
        }

        // AWS / SSH directories
        if name == ".aws" || name == ".ssh" || name == "secrets" || name == "keys" {
            patterns.push(format!("**/{name}/**"));
        }
    }

    // Always include these generic patterns as safety net
    if !found_root {
        patterns.push(".env".to_string());
        patterns.push(".env.*".to_string());
    }
    patterns.push("**/*.pem".to_string());
    patterns.push("**/*.key".to_string());
    patterns.push("**/*.p12".to_string());
    patterns.push("**/*.pfx".to_string());

    patterns.sort();
    patterns.dedup();
    patterns
}

/// S3: Artefactos de build segun el lenguaje detectado.
pub fn detect_build_artifacts(lang: Language) -> Vec<String> {
    let mut patterns = vec![
        // Generic — always safe to delete
        "*.log".to_string(),
        "tmp/**".to_string(),
    ];

    match lang {
        Language::Rust => {
            patterns.push("target/**".to_string());
        }
        Language::Node => {
            patterns.push("node_modules/**".to_string());
            patterns.push("dist/**".to_string());
            patterns.push("build/**".to_string());
            patterns.push(".next/**".to_string());
        }
        Language::Python => {
            patterns.push("__pycache__/**".to_string());
            patterns.push("*.pyc".to_string());
            patterns.push(".tox/**".to_string());
            patterns.push("dist/**".to_string());
            patterns.push("build/**".to_string());
            patterns.push("*.egg-info/**".to_string());
        }
        Language::Go => {
            patterns.push("vendor/**".to_string());
        }
        Language::Java => {
            patterns.push("target/**".to_string());
            patterns.push("build/**".to_string());
            patterns.push(".gradle/**".to_string());
            patterns.push("*.jar".to_string());
            patterns.push("*.war".to_string());
        }
        Language::Unknown => {}
    }

    patterns.sort();
    patterns.dedup();
    patterns
}

/// S4: Repositorios VCS — siempre en [deny].
pub fn detect_vcs_patterns(root: &Path) -> Vec<String> {
    let mut patterns = Vec::new();

    if root.join(".git").exists() {
        patterns.push(".git/**".to_string());
    }
    if root.join(".hg").exists() {
        patterns.push(".hg/**".to_string());
    }
    if root.join(".svn").exists() {
        patterns.push(".svn/**".to_string());
    }

    patterns
}

/// S5: Ficheros de IDE/Editor — solo lectura.
pub fn detect_editor_patterns(root: &Path) -> Vec<String> {
    let mut patterns = Vec::new();

    if root.join(".vscode").exists() {
        patterns.push(".vscode/**".to_string());
    }
    if root.join(".idea").exists() {
        patterns.push(".idea/**".to_string());
    }
    if root.join(".cursor").exists() {
        patterns.push(".cursor/**".to_string());
    }

    // Always add README + license-like files
    if root.join("README.md").exists() {
        patterns.push("README.md".to_string());
    }
    if root.join("README").exists() {
        patterns.push("README".to_string());
    }
    if root.join("LICENSE").exists()
        || root.join("LICENSE.md").exists()
        || root.join("LICENSE.txt").exists()
    {
        patterns.push("LICENSE*".to_string());
    }
    if root.join("CHANGELOG.md").exists() {
        patterns.push("CHANGELOG.md".to_string());
    }
    if root.join("CONTRIBUTING.md").exists() {
        patterns.push("CONTRIBUTING.md".to_string());
    }

    patterns
}

/// S7: Ficheros CI/CD — necesitan atencion, bucket [ask].
pub fn detect_ci_patterns(root: &Path) -> Vec<String> {
    let mut patterns = Vec::new();

    if root.join(".github").exists() {
        patterns.push(".github/**".to_string());
    }
    if root.join(".gitlab-ci.yml").exists() {
        patterns.push(".gitlab-ci.yml".to_string());
    }
    if root.join("Jenkinsfile").exists() {
        patterns.push("Jenkinsfile".to_string());
    }
    if root.join("azure-pipelines.yml").exists() {
        patterns.push("azure-pipelines.yml".to_string());
    }
    if root.join(".circleci").exists() {
        patterns.push(".circleci/**".to_string());
    }
    if root.join(".travis.yml").exists() {
        patterns.push(".travis.yml".to_string());
    }
    if root.join("Dockerfile").exists() {
        patterns.push("Dockerfile*".to_string());
    }

    // Lock files → ask (dependency changes need review)
    if root.join("Cargo.lock").exists() {
        patterns.push("Cargo.lock".to_string());
    }
    if root.join("package-lock.json").exists() {
        patterns.push("package-lock.json".to_string());
    }
    if root.join("yarn.lock").exists() {
        patterns.push("yarn.lock".to_string());
    }
    if root.join("pnpm-lock.yaml").exists() {
        patterns.push("pnpm-lock.yaml".to_string());
    }
    if root.join("go.sum").exists() {
        patterns.push("go.sum".to_string());
    }
    if root.join("Pipfile.lock").exists() {
        patterns.push("Pipfile.lock".to_string());
    }

    patterns.sort();
    patterns.dedup();
    patterns
}

/// S6: Estructura del proyecto — que se puede escribir y que solo leer.
/// Devuelve (write_patterns, read_patterns).
pub fn detect_project_structure(root: &Path, lang: Language) -> (Vec<String>, Vec<String>) {
    let mut write_patterns = Vec::new();
    let mut read_patterns = Vec::new();

    let has_src = root.join("src").exists();
    let has_tests = root.join("tests").exists()
        || root.join("test").exists()
        || root.join("spec").exists()
        || root.join("__tests__").exists();
    let has_docs = root.join("docs").exists();

    // Source code — read+write
    if has_src {
        write_patterns.push("src/**".to_string());
    }

    // Tests — read+write
    if has_tests {
        write_patterns.push("tests/**".to_string());
    }

    // Docs — read only
    if has_docs {
        read_patterns.push("docs/**".to_string());
    }

    // Language-specific config files — read+write
    match lang {
        Language::Rust => {
            if root.join("Cargo.toml").exists() {
                write_patterns.push("Cargo.toml".to_string());
            }
        }
        Language::Node => {
            if root.join("package.json").exists() {
                write_patterns.push("package.json".to_string());
            }
            if root.join("tsconfig.json").exists() {
                write_patterns.push("tsconfig*.json".to_string());
            }
        }
        Language::Python => {
            if root.join("pyproject.toml").exists() {
                write_patterns.push("pyproject.toml".to_string());
            }
            if root.join("requirements.txt").exists() {
                write_patterns.push("requirements*.txt".to_string());
            }
        }
        Language::Go => {
            if root.join("go.mod").exists() {
                write_patterns.push("go.mod".to_string());
                write_patterns.push("go.sum".to_string());
            }
        }
        Language::Java => {
            if root.join("pom.xml").exists() {
                write_patterns.push("pom.xml".to_string());
            }
            if root.join("build.gradle").exists() {
                write_patterns.push("build.gradle".to_string());
                write_patterns.push("settings.gradle".to_string());
            }
        }
        Language::Unknown => {}
    }

    // Common project files — read only
    if root.join(".gitignore").exists() {
        read_patterns.push(".gitignore".to_string());
    }
    if root.join(".dockerignore").exists() {
        read_patterns.push(".dockerignore".to_string());
    }
    if root.join("Makefile").exists() {
        read_patterns.push("Makefile".to_string());
    }

    write_patterns.sort();
    write_patterns.dedup();
    read_patterns.sort();
    read_patterns.dedup();

    (write_patterns, read_patterns)
}

/// Orquesta las 7 capas y devuelve un ProjectManifest listo para escribir.
pub fn auto_detect(root: &Path) -> ProjectManifest {
    let root = if root.is_file() {
        root.parent().unwrap_or(root)
    } else {
        root
    };

    let lang = detect_language(root);
    let name = root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("my-project")
        .to_string();

    let mut deny = detect_secrets(root);
    deny.extend(detect_vcs_patterns(root));
    // agentguard.toml itself must be protected from AI agents reading/modifying policy.
    // The daemon skips ACE application on this file to preserve hot-reload capability.
    deny.push("agentguard.toml".to_string());
    deny.sort();
    deny.dedup();

    let delete = detect_build_artifacts(lang);

    let read = detect_editor_patterns(root);

    let ask = detect_ci_patterns(root);

    let (write, read_extra) = detect_project_structure(root, lang);
    let mut read = read;
    read.extend(read_extra);
    read.sort();
    read.dedup();

    ProjectManifest {
        project: crate::parser::ProjectMeta {
            name: Some(name),
            description: None,
            default: DefaultMode::Conservative,
        },
        deny: BucketSpec { files: deny },
        ask: BucketSpec { files: ask },
        full: BucketSpec { files: vec![] },
        delete: BucketSpec { files: delete },
        write: BucketSpec { files: write },
        read: BucketSpec { files: read },
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_rust_project(dir: &Path) {
        fs::write(dir.join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src").join("main.rs"), "fn main() {}").unwrap();
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join("README.md"), "# Test").unwrap();
        fs::write(dir.join(".env"), "SECRET=xxx").unwrap();
    }

    fn setup_node_project(dir: &Path) {
        fs::write(
            dir.join("package.json"),
            r#"{"name": "test", "version": "1.0.0"}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src").join("index.js"), "console.log(1)").unwrap();
        fs::create_dir_all(dir.join(".git")).unwrap();
        fs::write(dir.join(".gitignore"), "node_modules").unwrap();
    }

    // ── Language detection ────────────────────────────────────────────

    #[test]
    fn detects_rust() {
        let dir = tempfile::tempdir().unwrap();
        setup_rust_project(dir.path());
        assert_eq!(detect_language(dir.path()), Language::Rust);
    }

    #[test]
    fn detects_node() {
        let dir = tempfile::tempdir().unwrap();
        setup_node_project(dir.path());
        assert_eq!(detect_language(dir.path()), Language::Node);
    }

    #[test]
    fn detects_python_via_pyproject() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pyproject.toml"), "[tool]").unwrap();
        assert_eq!(detect_language(dir.path()), Language::Python);
    }

    #[test]
    fn detects_python_via_requirements() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("requirements.txt"), "flask").unwrap();
        assert_eq!(detect_language(dir.path()), Language::Python);
    }

    #[test]
    fn detects_go() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("go.mod"), "module test").unwrap();
        assert_eq!(detect_language(dir.path()), Language::Go);
    }

    #[test]
    fn detects_java_maven() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("pom.xml"), "<project/>").unwrap();
        assert_eq!(detect_language(dir.path()), Language::Java);
    }

    #[test]
    fn detects_java_gradle() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("build.gradle"), "").unwrap();
        assert_eq!(detect_language(dir.path()), Language::Java);
    }

    #[test]
    fn unknown_on_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(detect_language(dir.path()), Language::Unknown);
    }

    // ── Secrets detection ─────────────────────────────────────────────

    #[test]
    fn detects_root_env_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".env"), "SECRET=1").unwrap();
        let patterns = detect_secrets(dir.path());
        assert!(patterns.contains(&".env".to_string()));
    }

    #[test]
    fn detects_nested_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("server");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join(".env"), "SECRET=1").unwrap();
        let patterns = detect_secrets(dir.path());
        assert!(patterns.contains(&"**/.env".to_string()));
    }

    #[test]
    fn detects_pem_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("certs")).unwrap();
        fs::write(dir.path().join("certs").join("server.pem"), "key").unwrap();
        let patterns = detect_secrets(dir.path());
        assert!(patterns.contains(&"**/*.pem".to_string()));
    }

    #[test]
    fn detects_aws_dir() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".aws")).unwrap();
        fs::write(dir.path().join(".aws").join("credentials"), "key").unwrap();
        let patterns = detect_secrets(dir.path());
        let has_aws = patterns.iter().any(|p| p.contains(".aws"));
        assert!(has_aws, "Should detect .aws directory. Got: {patterns:?}");
    }

    #[test]
    fn always_includes_generic_patterns() {
        let dir = tempfile::tempdir().unwrap();
        let patterns = detect_secrets(dir.path());
        assert!(patterns.contains(&"**/*.pem".to_string()));
        assert!(patterns.contains(&"**/*.key".to_string()));
    }

    // ── Build artifacts ───────────────────────────────────────────────

    #[test]
    fn rust_artifacts_include_target() {
        let patterns = detect_build_artifacts(Language::Rust);
        assert!(patterns.contains(&"target/**".to_string()));
    }

    #[test]
    fn node_artifacts_include_node_modules() {
        let patterns = detect_build_artifacts(Language::Node);
        assert!(patterns.contains(&"node_modules/**".to_string()));
    }

    #[test]
    fn python_artifacts_include_pycache() {
        let patterns = detect_build_artifacts(Language::Python);
        assert!(patterns.contains(&"__pycache__/**".to_string()));
    }

    #[test]
    fn unknown_artifacts_are_minimal() {
        let patterns = detect_build_artifacts(Language::Unknown);
        assert!(patterns.contains(&"*.log".to_string()));
    }

    // ── VCS detection ─────────────────────────────────────────────────

    #[test]
    fn detects_git() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        let patterns = detect_vcs_patterns(dir.path());
        assert!(patterns.contains(&".git/**".to_string()));
    }

    #[test]
    fn no_vcs_on_empty() {
        let dir = tempfile::tempdir().unwrap();
        let patterns = detect_vcs_patterns(dir.path());
        assert!(patterns.is_empty());
    }

    // ── Editor detection ──────────────────────────────────────────────

    #[test]
    fn detects_vscode() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        let patterns = detect_editor_patterns(dir.path());
        assert!(patterns.contains(&".vscode/**".to_string()));
    }

    #[test]
    fn detects_readme_and_license() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("README.md"), "# hi").unwrap();
        fs::write(dir.path().join("LICENSE"), "MIT").unwrap();
        let patterns = detect_editor_patterns(dir.path());
        assert!(patterns.contains(&"README.md".to_string()));
        assert!(patterns.contains(&"LICENSE*".to_string()));
    }

    // ── CI detection ──────────────────────────────────────────────────

    #[test]
    fn detects_github_actions() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".github").join("workflows")).unwrap();
        let patterns = detect_ci_patterns(dir.path());
        assert!(patterns.contains(&".github/**".to_string()));
    }

    #[test]
    fn detects_dockerfile_and_locks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Dockerfile"), "FROM alpine").unwrap();
        fs::write(dir.path().join("Cargo.lock"), "").unwrap();
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        let patterns = detect_ci_patterns(dir.path());
        assert!(patterns.contains(&"Cargo.lock".to_string()));
        assert!(patterns.contains(&"package-lock.json".to_string()));
        assert!(patterns.iter().any(|p| p.starts_with("Dockerfile")));
    }

    // ── Project structure ─────────────────────────────────────────────

    #[test]
    fn rust_project_structure() {
        let dir = tempfile::tempdir().unwrap();
        setup_rust_project(dir.path());
        let (write, _read) = detect_project_structure(dir.path(), Language::Rust);
        assert!(write.contains(&"src/**".to_string()));
        assert!(write.contains(&"Cargo.toml".to_string()));
    }

    #[test]
    fn node_project_structure() {
        let dir = tempfile::tempdir().unwrap();
        setup_node_project(dir.path());
        let (write, _read) = detect_project_structure(dir.path(), Language::Node);
        assert!(write.contains(&"src/**".to_string()));
        assert!(write.contains(&"package.json".to_string()));
    }

    // ── Full auto-detect ──────────────────────────────────────────────

    #[test]
    fn auto_detect_rust_project() {
        let dir = tempfile::tempdir().unwrap();
        setup_rust_project(dir.path());
        fs::write(dir.path().join("Cargo.lock"), "").unwrap();
        let manifest = auto_detect(dir.path());
        assert_eq!(
            manifest.project.name.as_deref(),
            Some(dir.path().file_name().unwrap().to_str().unwrap())
        );
        assert!(!manifest.deny.files.is_empty(), "Should have deny patterns");
        assert!(
            !manifest.delete.files.is_empty(),
            "Should have delete patterns"
        );
        assert!(
            !manifest.write.files.is_empty(),
            "Should have write patterns"
        );
        // Rust: Cargo.lock should be in ask
        assert!(manifest.ask.files.contains(&"Cargo.lock".to_string()));
    }

    #[test]
    fn auto_detect_node_project() {
        let dir = tempfile::tempdir().unwrap();
        setup_node_project(dir.path());
        fs::write(dir.path().join("package-lock.json"), "{}").unwrap();
        fs::write(dir.path().join(".env"), "KEY=1").unwrap();
        let manifest = auto_detect(dir.path());
        assert_eq!(detect_language(dir.path()), Language::Node);
        assert!(!manifest.deny.files.is_empty());
        assert!(manifest
            .delete
            .files
            .contains(&"node_modules/**".to_string()));
        assert!(manifest.write.files.contains(&"package.json".to_string()));
    }

    #[test]
    fn auto_detect_empty_project_is_valid() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = auto_detect(dir.path());
        assert!(
            manifest.deny.files.contains(&"**/*.pem".to_string()),
            "Even empty projects get generic secret patterns"
        );
    }

    #[test]
    fn auto_detect_manifest_can_compile() {
        let dir = tempfile::tempdir().unwrap();
        setup_rust_project(dir.path());
        let manifest = auto_detect(dir.path());

        let got = crate::compiled::CompiledManifest::compile(&manifest, dir.path().to_path_buf());
        match &got {
            Ok(_) => {}
            Err(e) => panic!("Auto-detected manifest should compile: {e}"),
        }
        assert!(got.is_ok());
    }

    #[test]
    fn auto_detect_no_duplicate_patterns() {
        let dir = tempfile::tempdir().unwrap();
        setup_rust_project(dir.path());
        let manifest = auto_detect(dir.path());

        let mut seen = std::collections::HashSet::new();
        for p in &manifest.deny.files {
            assert!(seen.insert(p), "Duplicate deny pattern: {p}");
        }
        for p in &manifest.ask.files {
            assert!(seen.insert(p), "Duplicate ask pattern: {p}");
        }
        for p in &manifest.delete.files {
            assert!(seen.insert(p), "Duplicate delete pattern: {p}");
        }
        for p in &manifest.write.files {
            assert!(seen.insert(p), "Duplicate write pattern: {p}");
        }
        for p in &manifest.read.files {
            assert!(seen.insert(p), "Duplicate read pattern: {p}");
        }
    }

    #[test]
    fn auto_detect_different_languages_produce_different_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"x\"").unwrap();
        let rust_manifest = auto_detect(dir.path());

        let dir2 = tempfile::tempdir().unwrap();
        fs::write(dir2.path().join("package.json"), "{}").unwrap();
        let node_manifest = auto_detect(dir2.path());

        assert_ne!(
            rust_manifest.delete.files, node_manifest.delete.files,
            "Different languages should produce different build artifact patterns"
        );
    }

    // ── find_manifest (existing) ───────────────────────────────────────

    #[test]
    fn finds_manifest_in_current_dir() {
        let dir = tempfile::tempdir().unwrap();
        let toml = dir.path().join("agentguard.toml");
        fs::write(&toml, "[project]\nname = \"test\"").unwrap();

        let found = find_manifest(dir.path()).unwrap();
        assert_eq!(found, toml);
    }

    #[test]
    fn finds_manifest_in_parent() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("src/deep/nested");
        fs::create_dir_all(&sub).unwrap();

        let toml = dir.path().join("agentguard.toml");
        fs::write(&toml, "").unwrap();

        let found = find_manifest(&sub).unwrap();
        assert_eq!(found, toml);
    }

    #[test]
    fn returns_error_when_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let result = find_manifest(dir.path());
        assert!(matches!(result, Err(GuardError::ManifestNotFound { .. })));
    }
}
