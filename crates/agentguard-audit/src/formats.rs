use agentguard_core::AuditEvent;
use agentguard_core::PolicyDecision;

pub fn to_ocsf(event: &AuditEvent, device_hostname: &str) -> serde_json::Value {
    let ts_ms = event.timestamp.timestamp_millis();
    let decision_str = match &event.decision {
        PolicyDecision::Allow => "Allow",
        PolicyDecision::Deny => "Deny",
        PolicyDecision::Ask { .. } => "Ask",
    };
    let activity_id = match &event.decision {
        PolicyDecision::Allow => 1,
        PolicyDecision::Deny => 6,
        PolicyDecision::Ask { .. } => 5,
    };
    let activity_name = match &event.decision {
        PolicyDecision::Allow => "Allow",
        PolicyDecision::Deny => "Deny",
        PolicyDecision::Ask { .. } => "Prompt",
    };

    serde_json::json!({
        "metadata": {
            "version": "1.4.0",
            "product": {
                "name": "Phylax",
                "vendor_name": "Phylax",
                "version": env!("CARGO_PKG_VERSION")
            },
            "profiles": ["osint", "cloud"]
        },
        "class_uid": 4005,
        "class_name": "File System Activity",
        "activity_id": activity_id,
        "activity_name": activity_name,
        "time": ts_ms,
        "device": {
            "hostname": device_hostname,
            "os": {
                "type": "Windows",
                "type_id": 100
            }
        },
        "actor": {
            "process": {
                "pid": event.agent_pid,
                "name": "unknown",
                "integrity": "Medium",
                "xattributes": {
                    "agent_label": event.agent_label.as_str()
                }
            }
        },
        "file": {
            "name": event.file_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            "path": event.file_path.to_string_lossy().to_string(),
            "type": "Regular",
            "type_id": 1
        },
        "policy": {
            "name": "phylax_policy",
            "desc": format!("Phylax {} rule from {}", event.operation.as_str(), event.source.as_str()),
            "source": event.source.as_str()
        },
        "decision": {
            "action": decision_str,
            "reason": format!("Phylax policy evaluation: {} {} on {} → {}",
                event.agent_label.as_str(), event.operation.as_str(), event.file_path.display(), decision_str),
            "override_available": matches!(&event.decision, PolicyDecision::Ask { .. })
        },
        "unmapped": {
            "phylax_source": event.source.as_str(),
            "phylax_operation": event.operation.as_str(),
        }
    })
}

pub fn to_cef(event: &AuditEvent) -> String {
    let vendor = "Phylax";
    let product = "Phylax";
    let version = env!("CARGO_PKG_VERSION");
    let signature_id = match &event.decision {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::Deny => "DENY",
        PolicyDecision::Ask { .. } => "ASK",
    };
    let name = format!("Agent {} {} on {}",
        event.agent_label.as_str(),
        event.operation.as_str(),
        event.file_path.display());
    let severity = match &event.decision {
        PolicyDecision::Deny => "8",
        PolicyDecision::Ask { .. } => "5",
        PolicyDecision::Allow => "1",
    };

    let ts = event.timestamp.timestamp_millis();

    let extension = format!(
        "suser={} spid={} filePath={} fname={} act={} outcome={} source={} start={}",
        event.agent_label.as_str(),
        event.agent_pid,
        event.file_path.display(),
        event.file_path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        event.operation.as_str(),
        map_outcome(signature_id),
        event.source.as_str(),
        ts,
    );

    format!(
        "CEF:0|{vendor}|{product}|{version}|{signature_id}|{name}|{severity}|{extension}"
    )
}

fn map_outcome(sig_id: &str) -> &str {
    match sig_id {
        "DENY" => "blocked",
        "ALLOW" => "allowed",
        _ => "prompted",
    }
}

pub fn events_to_ocsf(events: &[AuditEvent], device_hostname: &str) -> String {
    let entries: Vec<serde_json::Value> = events.iter().map(|e| to_ocsf(e, device_hostname)).collect();
    serde_json::to_string_pretty(&serde_json::json!({ "events": entries })).unwrap_or_default()
}

pub fn events_to_cef(events: &[AuditEvent]) -> String {
    events.iter().map(|e| to_cef(e)).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::{AgentLabel, FileOp, PolicySource};
    use std::path::PathBuf;
    use chrono::Utc;

    fn sample_event(pid: u32, path: &str, decision: PolicyDecision) -> AuditEvent {
        AuditEvent {
            id: Some(1),
            agent_pid: pid,
            agent_label: AgentLabel::Definite,
            file_path: PathBuf::from(path),
            operation: FileOp::Read,
            decision,
            source: PolicySource::Project,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn ocsf_deny_event() {
        let evt = sample_event(1234, "C:\\workspace\\.env", PolicyDecision::Deny);
        let json = to_ocsf(&evt, "test-host");
        assert_eq!(json["class_uid"], 4005);
        assert_eq!(json["activity_name"], "Deny");
        assert_eq!(json["activity_id"], 6);
        assert_eq!(json["actor"]["process"]["pid"], 1234);
    }

    #[test]
    fn ocsf_allow_event() {
        let evt = sample_event(5678, "/workspace/src/main.rs", PolicyDecision::Allow);
        let json = to_ocsf(&evt, "test-host");
        assert_eq!(json["activity_name"], "Allow");
        assert_eq!(json["activity_id"], 1);
    }

    #[test]
    fn ocsf_ask_event() {
        let evt = sample_event(9999, "/workspace/Cargo.lock", PolicyDecision::Ask {
            path: PathBuf::from("/workspace/Cargo.lock"),
            op: FileOp::Write,
        });
        let json = to_ocsf(&evt, "test-host");
        assert_eq!(json["activity_name"], "Prompt");
        assert_eq!(json["activity_id"], 5);
    }

    #[test]
    fn cef_deny_event() {
        let evt = sample_event(1234, "C:\\workspace\\.env", PolicyDecision::Deny);
        let cef = to_cef(&evt);
        assert!(cef.starts_with("CEF:0|Phylax|Phylax|"));
        assert!(cef.contains("DENY"));
        assert!(cef.contains("outcome=blocked"));
    }

    #[test]
    fn cef_allow_event() {
        let evt = sample_event(5678, "/workspace/src/main.rs", PolicyDecision::Allow);
        let cef = to_cef(&evt);
        assert!(cef.contains("ALLOW"));
        assert!(cef.contains("outcome=allowed"));
    }

    #[test]
    fn events_to_ocsf_batch() {
        let events = vec![
            sample_event(1, "/a.txt", PolicyDecision::Deny),
            sample_event(2, "/b.txt", PolicyDecision::Allow),
        ];
        let json = events_to_ocsf(&events, "host");
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn events_to_cef_batch() {
        let events = vec![
            sample_event(1, "/a.txt", PolicyDecision::Deny),
            sample_event(2, "/b.txt", PolicyDecision::Allow),
        ];
        let cef = events_to_cef(&events);
        let lines: Vec<&str> = cef.lines().collect();
        assert_eq!(lines.len(), 2);
    }
}
