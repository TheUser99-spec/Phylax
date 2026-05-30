use agentguard_core::{AgentLabel, GuardError, GuardResult, PolicyDecision};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub fn pipe_name() -> String {
    if let Ok(name) = std::env::var("AGENTGUARD_IPC_PIPE") {
        return name;
    }
    #[cfg(windows)]
    {
        r"\\.\pipe\agentguard".to_string()
    }
    #[cfg(not(windows))]
    {
        "/tmp/agentguard.sock".to_string()
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcRequest {
    RegisterProject {
        path: PathBuf,
    },
    UnregisterProject {
        path: PathBuf,
    },
    ValidateProject {
        path: PathBuf,
    },
    CheckFileAccess {
        path: PathBuf,
        op: String,
    },
    GetStatus,
    Shutdown,
    ReloadPolicy {
        path: PathBuf,
    },
    AskResponse {
        request_id: u64,
        allowed: bool,
        remember: bool,
    },
    AddGlobalRule {
        bucket: String,
        pattern: String,
    },
    RemoveGlobalRule {
        id: i64,
    },
    ListGlobalRules,
    EnableProtection {
        path: PathBuf,
    },
    DisableProtection {
        path: PathBuf,
    },
    SubscribeEvents,
    GetStats,
    GetPolicy {
        path: PathBuf,
    },
    AddAgentRule {
        agent_image: String,
        bucket: String,
        pattern: String,
    },
    RemoveAgentRule {
        id: i64,
    },
    ListAgentRules {
        agent_image: Option<String>,
    },
    VerifyProtection {
        path: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok,
    Error { message: String },
    Status(DaemonStatus),
    ProjectValidation(ValidationResult),
    FileCheck(FileCheckResult),
    GlobalRulesList(GlobalRulesListData),
    Event(StreamingEvent),
    Stats(DashboardStats),
    Policy(PolicyData),
    AgentRulesList(AgentRulesListData),
    ProtectionReport(ProtectionReportData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRulesListData {
    pub rules: Vec<GlobalRuleInfo>,
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub version: String,
    pub projects: Vec<ProjectInfo>,
    pub active_agents: Vec<ActiveAgent>,
    pub events_today: u64,
    pub blocks_today: u64,
    pub recent_events: Vec<AuditEventView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEventView {
    pub id: i64,
    pub agent_pid: u32,
    pub agent_label: String,
    pub file_path: String,
    pub operation: String,
    pub decision: String,
    pub source: String,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub path: PathBuf,
    pub toml_hash: String,
    pub added_at: i64,
    pub deny_count: usize,
    pub ask_count: usize,
    pub write_count: usize,
    pub delete_count: usize,
    pub read_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveAgent {
    pub pid: u32,
    pub image_name: String,
    pub label: AgentLabel,
    pub workspace: Option<PathBuf>,
    pub started_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub summary: PolicySummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySummary {
    pub deny_patterns: usize,
    pub ask_patterns: usize,
    pub write_patterns: usize,
    pub delete_patterns: usize,
    pub read_patterns: usize,
    pub full_patterns: usize,
    pub default_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRuleInfo {
    pub id: i64,
    pub bucket: String,
    pub pattern: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCheckResult {
    pub path: PathBuf,
    pub op: String,
    pub decision: PolicyDecision,
    pub source: String,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Dashboard stats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStats {
    pub total_events: u64,
    pub blocks: u64,
    pub allows: u64,
    pub asks: u64,
    pub top_agents: Vec<AgentStat>,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStat {
    pub agent_label: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyData {
    pub project_name: String,
    pub default_mode: String,
    pub deny: Vec<String>,
    pub ask: Vec<String>,
    pub full: Vec<String>,
    pub delete: Vec<String>,
    pub write: Vec<String>,
    pub read: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRuleInfo {
    pub id: i64,
    pub agent_image: String,
    pub bucket: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRulesListData {
    pub rules: Vec<AgentRuleInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionPathHealth {
    pub path: PathBuf,
    pub exists: bool,
    pub content_deny: bool,
    pub metadata_deny: bool,
    pub effective_deny: bool,
    pub healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionReportData {
    pub schema_version: u32,
    pub workspace: PathBuf,
    pub total_deny_paths: usize,
    pub healthy_paths: usize,
    pub effective_deny_paths: usize,
    pub unhealthy_paths: Vec<ProtectionPathHealth>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Streaming events (push from daemon to subscribed clients)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum StreamingEvent {
    AuditEvent(AuditEventView),
    AgentDetected(ActiveAgent),
    AgentExited {
        pid: u32,
    },
    StatusUpdate {
        events_today: u64,
        blocks_today: u64,
        active_agents_count: usize,
        projects_count: usize,
    },
    SystemMessage {
        message: String,
        #[serde(rename = "level")]
        level: String,
        #[serde(default)]
        timestamp: i64,
    },
    AskPrompt {
        request_id: u64,
        agent_label: String,
        file_path: String,
        operation: String,
    },
}

// ---------------------------------------------------------------------------
// Codec — length-prefixed JSON
// ---------------------------------------------------------------------------

pub fn encode<T: Serialize>(msg: &T) -> GuardResult<Vec<u8>> {
    let json = serde_json::to_vec(msg).map_err(|e| GuardError::IpcError(e.to_string()))?;
    let len = json.len() as u32;
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(&json);
    Ok(buf)
}

pub async fn read_exact_bytes(
    reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
    n: usize,
) -> GuardResult<Vec<u8>> {
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| GuardError::IpcError(e.to_string()))?;
    Ok(buf)
}

pub async fn recv<T: for<'de> Deserialize<'de>>(
    reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
) -> GuardResult<T> {
    let len_bytes = read_exact_bytes(reader, 4).await?;
    let len_arr: [u8; 4] = len_bytes
        .try_into()
        .map_err(|_| GuardError::IpcError("invalid length prefix".into()))?;
    let len = u32::from_le_bytes(len_arr) as usize;

    if len > 4 * 1024 * 1024 {
        return Err(GuardError::IpcError("IPC message too large".into()));
    }

    let body = read_exact_bytes(reader, len).await?;
    serde_json::from_slice(&body).map_err(|e| GuardError::IpcError(format!("invalid JSON: {e}")))
}

pub async fn send<T: Serialize>(
    writer: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    msg: &T,
) -> GuardResult<()> {
    let bytes = encode(msg)?;
    writer
        .write_all(&bytes)
        .await
        .map_err(|e| GuardError::IpcError(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use agentguard_core::{AgentLabel, PolicyDecision};
    use std::path::PathBuf;
    use tokio::io::{duplex, AsyncWriteExt};

    fn test_request() -> IpcRequest {
        IpcRequest::RegisterProject {
            path: PathBuf::from("/test/project"),
        }
    }

    fn test_status() -> DaemonStatus {
        DaemonStatus {
            running: true,
            version: "0.1.0".into(),
            recent_events: vec![],
            projects: vec![ProjectInfo {
                path: PathBuf::from("/test"),
                toml_hash: "abc123".into(),
                added_at: 1700000000,
                deny_count: 5,
                ask_count: 2,
                write_count: 10,
                delete_count: 3,
                read_count: 20,
            }],
            active_agents: vec![ActiveAgent {
                pid: 1234,
                image_name: "claude.exe".into(),
                label: AgentLabel::Definite,
                workspace: Some(PathBuf::from("/test")),
                started_at: 1700000000,
            }],
            events_today: 42,
            blocks_today: 7,
        }
    }

    // ─── encode / recv roundtrips ────────────────────────────────────────

    #[test]
    fn encode_then_recv_request() {
        let req = test_request();
        let bytes = encode(&req).unwrap();
        let decoded: IpcRequest = serde_json::from_slice(&bytes[4..]).unwrap();
        assert_eq!(decoded.discriminant(), req.discriminant());
    }

    #[test]
    fn encode_produces_length_prefix() {
        let req = test_request();
        let bytes = encode(&req).unwrap();
        let prefix = u32::from_le_bytes(bytes[..4].try_into().unwrap());
        assert_eq!(prefix as usize, bytes.len() - 4);
    }

    #[tokio::test]
    async fn send_recv_roundtrip_request() {
        let (mut client, mut server) = duplex(4096);
        let req = test_request();

        send(&mut client, &req).await.unwrap();
        let decoded: IpcRequest = recv(&mut server).await.unwrap();

        match decoded {
            IpcRequest::RegisterProject { path } => {
                assert_eq!(path, PathBuf::from("/test/project"));
            }
            _ => panic!("expected RegisterProject"),
        }
    }

    #[tokio::test]
    async fn send_recv_roundtrip_response() {
        let (mut client, mut server) = duplex(4096);
        let resp = IpcResponse::Ok;

        send(&mut server, &resp).await.unwrap();
        let decoded: IpcResponse = recv(&mut client).await.unwrap();

        assert!(matches!(decoded, IpcResponse::Ok));
    }

    // ─── all request variants ────────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_all_request_types() {
        let requests = vec![
            IpcRequest::RegisterProject {
                path: PathBuf::from("/a"),
            },
            IpcRequest::UnregisterProject {
                path: PathBuf::from("/b"),
            },
            IpcRequest::ValidateProject {
                path: PathBuf::from("/c"),
            },
            IpcRequest::CheckFileAccess {
                path: PathBuf::from("/d"),
                op: "write".into(),
            },
            IpcRequest::GetStatus,
            IpcRequest::Shutdown,
            IpcRequest::ReloadPolicy {
                path: PathBuf::from("/e"),
            },
            IpcRequest::AskResponse {
                request_id: 99,
                allowed: true,
                remember: false,
            },
            IpcRequest::AddGlobalRule {
                bucket: "deny".into(),
                pattern: "*.env".into(),
            },
            IpcRequest::RemoveGlobalRule { id: 1 },
            IpcRequest::ListGlobalRules,
            IpcRequest::EnableProtection {
                path: PathBuf::from("/p"),
            },
            IpcRequest::DisableProtection {
                path: PathBuf::from("/p"),
            },
            IpcRequest::SubscribeEvents,
            IpcRequest::GetStats,
            IpcRequest::GetPolicy {
                path: PathBuf::from("/test"),
            },
            IpcRequest::AddAgentRule {
                agent_image: "cursor.exe".into(),
                bucket: "deny".into(),
                pattern: "*.env".into(),
            },
            IpcRequest::RemoveAgentRule { id: 1 },
            IpcRequest::ListAgentRules {
                agent_image: Some("cursor.exe".into()),
            },
            IpcRequest::VerifyProtection {
                path: PathBuf::from("/test"),
            },
        ];

        for req in requests {
            let (mut a, mut b) = duplex(4096);
            send(&mut a, &req).await.unwrap();
            let decoded: IpcRequest = recv(&mut b).await.unwrap();
            // verify it deserialized without error via discriminant match
            let _ = decoded;
        }
    }

    // ─── all response variants ───────────────────────────────────────────

    #[tokio::test]
    async fn roundtrip_all_response_types() {
        let responses = vec![
            IpcResponse::Ok,
            IpcResponse::Error {
                message: "something broke".into(),
            },
            IpcResponse::Status(test_status()),
            IpcResponse::ProjectValidation(ValidationResult {
                valid: true,
                errors: vec![],
                warnings: vec!["unused pattern".into()],
                summary: PolicySummary {
                    deny_patterns: 2,
                    ask_patterns: 1,
                    write_patterns: 5,
                    delete_patterns: 0,
                    read_patterns: 10,
                    full_patterns: 0,
                    default_mode: "conservative".into(),
                },
            }),
            IpcResponse::FileCheck(FileCheckResult {
                path: PathBuf::from("/test/.env"),
                op: "read".into(),
                decision: PolicyDecision::Deny,
                source: "project".into(),
                reason: "deny bucket matches .env".into(),
            }),
            IpcResponse::GlobalRulesList(GlobalRulesListData {
                rules: vec![GlobalRuleInfo {
                    id: 1,
                    bucket: "deny".into(),
                    pattern: "*.env".into(),
                    created_at: "2026-01-01 00:00".into(),
                }],
            }),
            IpcResponse::Event(StreamingEvent::AuditEvent(AuditEventView {
                id: 0,
                agent_pid: 1234,
                agent_label: "Definite".into(),
                file_path: "/test/.env".into(),
                operation: "read".into(),
                decision: "deny".into(),
                source: "project".into(),
                timestamp: 1700000000,
            })),
            IpcResponse::Event(StreamingEvent::AgentDetected(ActiveAgent {
                pid: 1234,
                image_name: "cursor.exe".into(),
                label: AgentLabel::Definite,
                workspace: Some(PathBuf::from("/test")),
                started_at: 1700000000,
            })),
            IpcResponse::Event(StreamingEvent::AgentExited { pid: 1234 }),
            IpcResponse::Event(StreamingEvent::StatusUpdate {
                events_today: 42,
                blocks_today: 7,
                active_agents_count: 2,
                projects_count: 3,
            }),
            IpcResponse::Stats(DashboardStats {
                total_events: 100,
                blocks: 10,
                allows: 80,
                asks: 10,
                top_agents: vec![AgentStat {
                    agent_label: "DEFINITE".into(),
                    count: 50,
                }],
                timestamp: 1700000000,
            }),
            IpcResponse::Policy(PolicyData {
                project_name: "my-app".into(),
                default_mode: "conservative".into(),
                deny: vec![".env".into(), "*.key".into()],
                ask: vec!["Cargo.lock".into()],
                full: vec![],
                delete: vec!["target/**".into()],
                write: vec!["src/**".into()],
                read: vec!["docs/**".into()],
            }),
            IpcResponse::AgentRulesList(AgentRulesListData {
                rules: vec![AgentRuleInfo {
                    id: 1,
                    agent_image: "cursor.exe".into(),
                    bucket: "deny".into(),
                    pattern: "*.env".into(),
                }],
            }),
            IpcResponse::ProtectionReport(ProtectionReportData {
                schema_version: 1,
                workspace: PathBuf::from("/test"),
                warnings: vec![],
                total_deny_paths: 2,
                healthy_paths: 1,
                    unhealthy_paths: vec![ProtectionPathHealth {
                        path: PathBuf::from("/test/.env"),
                        exists: true,
                        content_deny: false,
                        metadata_deny: false,
                        effective_deny: false,
                        healthy: false,
                    }],
                effective_deny_paths: 1,
            }),
        ];

        for resp in responses {
            let (mut a, mut b) = duplex(4096);
            send(&mut a, &resp).await.unwrap();
            let decoded: IpcResponse = recv(&mut b).await.unwrap();
            let _ = decoded;
        }
    }

    // ─── edge cases ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn recv_rejects_oversized_message() {
        let (mut client, mut server) = duplex(65536);
        // Send a length prefix claiming 5MB
        let huge_len: u32 = 5 * 1024 * 1024 + 1;
        client.write_all(&huge_len.to_le_bytes()).await.unwrap();
        let err = recv::<IpcRequest>(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[tokio::test]
    async fn recv_rejects_invalid_json() {
        let (mut client, mut server) = duplex(4096);
        let garbage = b"not json at all";
        let len = garbage.len() as u32;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(garbage);
        client.write_all(&buf).await.unwrap();

        let err = recv::<IpcRequest>(&mut server).await.unwrap_err();
        assert!(err.to_string().contains("invalid JSON"));
    }

    #[tokio::test]
    async fn recv_zero_length_payload() {
        let (mut client, mut server) = duplex(4096);
        let zero: u32 = 0;
        client.write_all(&zero.to_le_bytes()).await.unwrap();
        // 0-length payload is technically valid if the type can deserialize from empty
        // serde_json will fail b/c no JSON -> "invalid JSON" error
        let result = recv::<IpcRequest>(&mut server).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn multiple_messages_pipelined() {
        let (mut client, mut server) = duplex(4096);
        let r1 = IpcRequest::GetStatus;
        let r2 = IpcRequest::Shutdown;

        send(&mut client, &r1).await.unwrap();
        send(&mut client, &r2).await.unwrap();

        let d1: IpcRequest = recv(&mut server).await.unwrap();
        let d2: IpcRequest = recv(&mut server).await.unwrap();

        assert!(matches!(d1, IpcRequest::GetStatus));
        assert!(matches!(d2, IpcRequest::Shutdown));
    }

    #[tokio::test]
    async fn status_response_roundtrip_preserves_data() {
        let (mut a, mut b) = duplex(4096);
        let status = test_status();
        let resp = IpcResponse::Status(status.clone());

        send(&mut a, &resp).await.unwrap();
        let decoded: IpcResponse = recv(&mut b).await.unwrap();

        match decoded {
            IpcResponse::Status(s) => {
                assert!(s.running);
                assert_eq!(s.version, "0.1.0");
                assert_eq!(s.projects.len(), 1);
                assert_eq!(s.projects[0].path, PathBuf::from("/test"));
                assert_eq!(s.projects[0].toml_hash, "abc123");
                assert_eq!(s.active_agents.len(), 1);
                assert_eq!(s.active_agents[0].pid, 1234);
                assert_eq!(s.active_agents[0].image_name, "claude.exe");
                assert!(matches!(s.active_agents[0].label, AgentLabel::Definite));
                assert_eq!(s.events_today, 42);
                assert_eq!(s.blocks_today, 7);
            }
            _ => panic!("expected Status"),
        }
    }

    #[tokio::test]
    async fn ask_response_all_combinations() {
        let combos = vec![
            (1, true, false),
            (2, true, true),
            (3, false, false),
            (4, false, true),
        ];
        for (id, allowed, remember) in combos {
            let (mut a, mut b) = duplex(4096);
            let req = IpcRequest::AskResponse {
                request_id: id,
                allowed,
                remember,
            };
            send(&mut a, &req).await.unwrap();
            let decoded: IpcRequest = recv(&mut b).await.unwrap();
            match decoded {
                IpcRequest::AskResponse {
                    request_id,
                    allowed: al,
                    remember: rm,
                } => {
                    assert_eq!(request_id, id);
                    assert_eq!(al, allowed);
                    assert_eq!(rm, remember);
                }
                _ => panic!("expected AskResponse"),
            }
        }
    }

    #[test]
    fn pipe_name_default_is_valid() {
        // Default pipe name should not be empty
        let name = pipe_name();
        assert!(!name.is_empty());
    }

    // Helper: get the "type" tag from serde_json::Value
    impl IpcRequest {
        fn discriminant(&self) -> String {
            let val = serde_json::to_value(self).unwrap();
            val["type"].as_str().unwrap_or("").to_string()
        }
    }
}
