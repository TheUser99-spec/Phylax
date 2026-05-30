use agentguard_core::AgentLabel;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ClassifierConfig {
    pub known_agent_images: HashSet<String>,
    pub agent_env_vars: HashSet<String>,
    pub system_processes: HashSet<String>,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        let images: HashSet<String> = [
            "claude.exe",
            "claude-code.exe",
            "cursor.exe",
            "opencode.exe",
            "aider.exe",
            "aider",
            "goose.exe",
            "goose",
            "cline",
            "gemini.exe",
            // node.exe is NOT matched by image name alone (requires S3 cmdline check).
            // It's included here so that it can be used with add_known_image().
            "node.exe",
            "windsurf.exe",
            "codeium.exe",
            "cody.exe",
            "tabnine.exe",
            "augment.exe",
            "continue.exe",
            "q.exe",
            "q-developer.exe",
            "replit.exe",
            "trae.exe",
            "devin.exe",
            "opendevin.exe",
            "phind.exe",
            "pearai.exe",
            "blackbox.exe",
        ]
        .iter()
        .map(|s| s.to_lowercase())
        .collect();

        let env_vars: HashSet<String> = [
            "CLAUDE_CODE",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CURSOR_SESSION",
            "CURSOR_CHANNEL",
            "OPENAI_API_KEY",
            "CODEX_SESSION",
            "GEMINI_API_KEY",
            "CLINE_MODE",
            "GOOSE_SESSION",
            "AGENT_ENVIRONMENT",
            "AI_AGENT_MODE",
            "AGENT_SESSION_ID",
            "WINDSURF_SESSION",
            "CONTINUE_SESSION",
            "Q_DEVELOPER",
            "AMAZON_Q_SESSION",
            "CODY_ENDPOINT",
            "AUGMENT_TOKEN",
            "TABNINE_TOKEN",
            "SOURCECRAFT_SESSION",
            "ZED_AI",
            "REPLIT_SESSION",
            "TRAE_SESSION",
            "DEVIN_SESSION",
            "PHIND_SESSION",
            "BLACKBOX_SESSION",
            "PEARAI_SESSION",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let system: HashSet<String> = [
            "audiodg.exe",
            "svchost.exe",
            "lsass.exe",
            "csrss.exe",
            "winlogon.exe",
            "services.exe",
            "smss.exe",
            "spoolsv.exe",
            "wininit.exe",
            "fontdrvhost.exe",
            "dwm.exe",
            "sihost.exe",
            "taskhostw.exe",
            "ctfmon.exe",
            "msiexec.exe",
            "wlms.exe",
            "runtimebroker.exe",
            "searchindexer.exe",
            "securityhealthservice.exe",
            "shellexperiencehost.exe",
            "startmenuexperiencehost.exe",
            "textinputhost.exe",
            "systemsettings.exe",
            "applicationframehost.exe",
            "wudfhost.exe",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        Self {
            known_agent_images: images,
            agent_env_vars: env_vars,
            system_processes: system,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub image_name: String,
    pub cmdline: String,
    pub env_vars: Vec<String>,
    pub session_id: u32,
    pub has_window: bool,
    pub parent_pid: Option<u32>,
}

pub struct SubjectClassifier {
    config: ClassifierConfig,
}

impl SubjectClassifier {
    pub fn new(config: ClassifierConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ClassifierConfig::default())
    }

    pub fn classify(&self, info: &ProcessInfo) -> AgentLabel {
        for key in &info.env_vars {
            if self.config.agent_env_vars.contains(key.as_str()) {
                return AgentLabel::Definite;
            }
        }

        let image = info.image_name.to_lowercase();
        if image != "node.exe" && self.config.known_agent_images.contains(&image) {
            return AgentLabel::Definite;
        }

        if image == "node.exe" && self.cmdline_looks_like_agent(&info.cmdline) {
            return AgentLabel::Definite;
        }

        if info.session_id == 0 && !info.has_window {
            if self.config.system_processes.contains(&image) {
                return AgentLabel::Human;
            }
            return AgentLabel::Probable;
        }

        AgentLabel::Human
    }

    fn cmdline_looks_like_agent(&self, cmdline: &str) -> bool {
        let lower = cmdline.to_lowercase();
        let agent_keywords = [
            "claude",
            "cursor",
            "cline",
            "aider",
            "goose",
            "copilot",
            "opencode",
            "gemini-cli",
            "windsurf",
            "codeium",
            "cody",
            "tabnine",
            "augment",
            "continue",
            "q-developer",
            "sourcegraph",
            "replit",
            "trae",
            "devin",
            "opendevin",
            "phind",
            "pearai",
            "blackbox",
        ];
        agent_keywords.iter().any(|kw| lower.contains(kw))
    }

    pub fn add_known_image(&mut self, image: String) {
        self.config.known_agent_images.insert(image.to_lowercase());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn info(image: &str, env_vars: &[&str]) -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            image_name: image.to_string(),
            cmdline: String::new(),
            env_vars: env_vars.iter().map(|s| s.to_string()).collect(),
            session_id: 1,
            has_window: true,
            parent_pid: None,
        }
    }

    #[test]
    fn claude_env_var_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("node.exe", &["CLAUDE_CODE"]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn cursor_exe_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("cursor.exe", &[]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn node_with_claude_cmdline_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let mut p = info("node.exe", &[]);
        p.cmdline = r"node.exe C:\Users\x\AppData\Roaming\claude\dist\index.js".to_string();
        let label = c.classify(&p);
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn session0_no_window_is_probable() {
        let c = SubjectClassifier::with_defaults();
        let mut p = info("unknown-service.exe", &[]);
        p.session_id = 0;
        p.has_window = false;
        let label = c.classify(&p);
        assert_eq!(label, AgentLabel::Probable);
    }

    #[test]
    fn normal_process_is_human() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("notepad.exe", &[]));
        assert_eq!(label, AgentLabel::Human);
    }

    #[test]
    fn anthropic_api_key_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("python.exe", &["ANTHROPIC_API_KEY"]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn windsurf_exe_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("windsurf.exe", &[]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn codeium_exe_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("codeium.exe", &[]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn tabnine_exe_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("tabnine.exe", &[]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn augment_token_env_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("python.exe", &["AUGMENT_TOKEN"]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn windsurf_session_env_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("node.exe", &["WINDSURF_SESSION"]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn node_with_windsurf_cmdline_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let mut p = info("node.exe", &[]);
        p.cmdline = r"node.exe /path/to/windsurf/dist/server.js".to_string();
        let label = c.classify(&p);
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn opencode_exe_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("opencode.exe", &[]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn replit_exe_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("replit.exe", &[]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn amazon_q_env_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("q.exe", &["AMAZON_Q_SESSION"]));
        assert_eq!(label, AgentLabel::Definite);
    }

    #[test]
    fn gh_exe_is_not_agent() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("gh.exe", &[]));
        assert_eq!(label, AgentLabel::Human);
    }

    #[test]
    fn devin_exe_is_definite() {
        let c = SubjectClassifier::with_defaults();
        let label = c.classify(&info("devin.exe", &[]));
        assert_eq!(label, AgentLabel::Definite);
    }
}
