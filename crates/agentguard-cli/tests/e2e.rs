//! End-to-end integration tests against a running AgentGuard daemon.
//!
//! REQUIRES: `agentguard-daemon` running with `\\.\pipe\agentguard` available.
//!
//! Usage:
//!   1. Start daemon: cargo run -p agentguard-daemon
//!   2. Run tests:   cargo test -p agentguard-cli --test e2e -- --test-threads=1

#![allow(clippy::unwrap_used, clippy::expect_used)]

use agentguard_core::PolicyDecision;
use agentguard_ipc::{IpcClient, IpcRequest, IpcResponse};

fn client() -> IpcClient {
    IpcClient::new()
}

fn assert_ok(resp: &IpcResponse) {
    if let IpcResponse::Error { message } = resp {
        panic!("Expected Ok, got Error: {message}");
    }
}

fn assert_error(resp: &IpcResponse) {
    if matches!(resp, IpcResponse::Ok) {
        panic!("Expected Error, got Ok");
    }
}

#[tokio::test]
async fn e2e_get_status() {
    let resp = client().send(IpcRequest::GetStatus).await.unwrap();
    if let IpcResponse::Status(status) = resp {
        assert!(status.running);
        assert!(!status.version.is_empty());
    } else {
        panic!("Expected Status, got {:?}", resp);
    }
}

#[tokio::test]
async fn e2e_global_rule_crud() {
    let c = client();

    let resp = c
        .send(IpcRequest::AddGlobalRule {
            bucket: "deny".to_string(),
            pattern: "*.e2e-secret".to_string(),
        })
        .await
        .unwrap();
    assert_ok(&resp);

    match c.send(IpcRequest::ListGlobalRules).await.unwrap() {
        IpcResponse::GlobalRulesList(data) => {
            let rule = data
                .rules
                .iter()
                .find(|r| r.pattern == "*.e2e-secret")
                .expect("Rule not found in list");
            assert_eq!(rule.bucket, "deny");

            let resp = c
                .send(IpcRequest::RemoveGlobalRule { id: rule.id })
                .await
                .unwrap();
            assert_ok(&resp);
        }
        other => panic!("Expected GlobalRulesList, got {:?}", other),
    }
}

#[tokio::test]
async fn e2e_global_rule_invalid_bucket() {
    let c = client();
    let resp = c
        .send(IpcRequest::AddGlobalRule {
            bucket: "bogus".to_string(),
            pattern: "*.test".to_string(),
        })
        .await
        .unwrap();
    assert_error(&resp);
}

#[tokio::test]
async fn e2e_agent_rule_crud() {
    let c = client();

    let resp = c
        .send(IpcRequest::AddAgentRule {
            agent_image: "e2e-test.exe".to_string(),
            bucket: "ask".to_string(),
            pattern: "e2e-lockfile".to_string(),
        })
        .await
        .unwrap();
    assert_ok(&resp);

    match c
        .send(IpcRequest::ListAgentRules {
            agent_image: Some("e2e-test.exe".to_string()),
        })
        .await
        .unwrap()
    {
        IpcResponse::AgentRulesList(data) => {
            let rule = data
                .rules
                .iter()
                .find(|r| r.agent_image == "e2e-test.exe")
                .expect("Agent rule not found");
            assert_eq!(rule.bucket, "ask");
            assert_eq!(rule.pattern, "e2e-lockfile");

            let resp = c
                .send(IpcRequest::RemoveAgentRule { id: rule.id })
                .await
                .unwrap();
            assert_ok(&resp);
        }
        other => panic!("Expected AgentRulesList, got {:?}", other),
    }
}

#[tokio::test]
async fn e2e_check_file_access() {
    let c = client();

    c.send(IpcRequest::AddGlobalRule {
        bucket: "deny".to_string(),
        pattern: "*.e2e-check".to_string(),
    })
    .await
    .unwrap();

    let resp = c
        .send(IpcRequest::CheckFileAccess {
            path: std::env::temp_dir().join("test.e2e-check"),
            op: "read".to_string(),
        })
        .await
        .unwrap();

    match resp {
        IpcResponse::FileCheck(check) => {
            assert_eq!(check.decision, PolicyDecision::Deny);
        }
        other => panic!("Expected FileCheck, got {:?}", other),
    }

    // Cleanup
    if let IpcResponse::GlobalRulesList(data) = c.send(IpcRequest::ListGlobalRules).await.unwrap() {
        if let Some(rule) = data.rules.iter().find(|r| r.pattern == "*.e2e-check") {
            c.send(IpcRequest::RemoveGlobalRule { id: rule.id })
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn e2e_get_stats() {
    let c = client();
    let resp = c.send(IpcRequest::GetStats).await.unwrap();
    if let IpcResponse::Stats(stats) = resp {
        let _ = stats.total_events;
        let _ = stats.blocks;
    } else {
        panic!("Expected Stats, got {:?}", resp);
    }
}

#[tokio::test]
async fn e2e_get_policy_unknown_project() {
    let c = client();
    let resp = c
        .send(IpcRequest::GetPolicy {
            path: std::path::PathBuf::from("/nonexistent/project"),
        })
        .await;
    match resp {
        Ok(IpcResponse::Error { .. }) => {}
        Ok(IpcResponse::Policy(_)) => {}
        Ok(other) => panic!("Expected Error or Policy, got {:?}", other),
        Err(e) => panic!("IPC connection failed: {e}"),
    }
}

/// Register + unregister project E2E cycle.
/// Requires ACE application to succeed (non-Windows or elevated on Windows).
#[cfg(not(windows))]
#[tokio::test]
async fn e2e_register_and_unregister_project() {
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("e2e-project");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(
        ws.join("agentguard.toml"),
        r#"
[project]
name = "e2e-test"
default = "conservative"

[deny]
files = ["*.e2e-deny"]
"#,
    )
    .unwrap();

    let c = client();
    let resp = c
        .send(IpcRequest::RegisterProject { path: ws.clone() })
        .await
        .unwrap();
    assert_ok(&resp);

    match c.send(IpcRequest::GetStatus).await.unwrap() {
        IpcResponse::Status(status) => {
            assert!(status.projects.len() > 0, "Project not registered");
        }
        other => panic!("Expected Status, got {:?}", other),
    }

    let resp = c
        .send(IpcRequest::UnregisterProject { path: ws })
        .await
        .unwrap();
    assert_ok(&resp);
}
