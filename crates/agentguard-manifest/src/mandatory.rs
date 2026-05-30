use crate::ProjectManifest;

pub const MANDATORY_DENY_PATTERNS: &[&str] = &[
    "agentguard.toml",
    ".env",
    ".env.*",
    ".git/**",
    "**/*.key",
    "**/*.pem",
    "**/*.p12",
    "**/*.pfx",
];

pub fn enforce_mandatory_denies(manifest: &mut ProjectManifest) {
    for pat in MANDATORY_DENY_PATTERNS {
        if !manifest.deny.files.iter().any(|p| p == pat) {
            manifest.deny.files.push((*pat).to_string());
        }
    }
    manifest.deny.files.sort();
    manifest.deny.files.dedup();
}

pub fn missing_mandatory_denies(manifest: &ProjectManifest) -> Vec<&'static str> {
    MANDATORY_DENY_PATTERNS
        .iter()
        .copied()
        .filter(|pat| !manifest.deny.files.iter().any(|p| p == pat))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn enforce_mandatory_denies_adds_all_patterns() {
        let mut m = ProjectManifest::default();
        enforce_mandatory_denies(&mut m);
        for pat in MANDATORY_DENY_PATTERNS {
            assert!(
                m.deny.files.iter().any(|p| p == pat),
                "missing mandatory deny pattern: {pat}"
            );
        }
    }

    #[test]
    fn enforce_mandatory_denies_deduplicates_existing() {
        let mut m = ProjectManifest::default();
        m.deny.files.push(".env".into());
        m.deny.files.push(".env".into());
        m.deny.files.push(".git/**".into());
        enforce_mandatory_denies(&mut m);

        let env_count = m.deny.files.iter().filter(|p| p.as_str() == ".env").count();
        let git_count = m
            .deny
            .files
            .iter()
            .filter(|p| p.as_str() == ".git/**")
            .count();
        assert_eq!(env_count, 1);
        assert_eq!(git_count, 1);
    }

    #[test]
    fn missing_mandatory_denies_detects_omissions() {
        let mut m = ProjectManifest::default();
        m.deny.files.push(".env".into());
        let missing = missing_mandatory_denies(&m);
        assert!(missing.contains(&"agentguard.toml"));
        assert!(missing.contains(&".git/**"));
        assert!(!missing.contains(&".env"));
    }

    #[test]
    fn missing_mandatory_denies_is_empty_when_complete() {
        let mut m = ProjectManifest::default();
        enforce_mandatory_denies(&mut m);
        let missing = missing_mandatory_denies(&m);
        assert!(missing.is_empty());
    }
}
