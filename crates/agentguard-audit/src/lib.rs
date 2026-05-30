//! Escribe eventos de auditoria en agentguard-store.
//!
//! Cada decision de enforcement (allow, deny, ask) produce un AuditEvent.
//! Fail-closed: si la DB no esta disponible, se aplica deny por defecto.

use agentguard_core::{AgentLabel, AuditEvent, FileOp, GuardResult, PolicyDecision, PolicySource};
use agentguard_store::Store;
use chrono::Utc;
use std::path::Path;

pub struct Auditor {
    store: Store,
}

impl Auditor {
    pub fn new(store: Store) -> Self {
        Auditor { store }
    }

    pub fn log_decision(
        &self,
        agent_pid: u32,
        agent_label: AgentLabel,
        file_path: &Path,
        operation: FileOp,
        decision: &PolicyDecision,
        source: PolicySource,
    ) -> GuardResult<()> {
        let event = AuditEvent {
            id: None,
            agent_pid,
            agent_label,
            file_path: file_path.to_path_buf(),
            operation,
            decision: decision.clone(),
            source,
            timestamp: Utc::now(),
        };
        self.store.insert_audit_event(&event).map(|_| ())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn log_deny_persists() {
        let store = Store::open_in_memory().unwrap();
        let verify = store.clone();
        let auditor = Auditor::new(store);

        auditor
            .log_decision(
                1234,
                AgentLabel::Definite,
                Path::new("/workspace/.env"),
                FileOp::Read,
                &PolicyDecision::Deny,
                PolicySource::Project,
            )
            .unwrap();

        let events = verify.recent_audit_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_pid, 1234);
        assert_eq!(events[0].decision, PolicyDecision::Deny);
    }

    #[test]
    fn log_allow_persists() {
        let store = Store::open_in_memory().unwrap();
        let verify = store.clone();
        let auditor = Auditor::new(store);

        auditor
            .log_decision(
                5678,
                AgentLabel::Probable,
                Path::new("/workspace/src/main.rs"),
                FileOp::Write,
                &PolicyDecision::Allow,
                PolicySource::Project,
            )
            .unwrap();

        let events = verify.recent_audit_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, PolicyDecision::Allow);
        assert_eq!(events[0].source, PolicySource::Project);
    }

    #[test]
    fn log_ask_persists() {
        let store = Store::open_in_memory().unwrap();
        let verify = store.clone();
        let auditor = Auditor::new(store);

        let ask_decision = PolicyDecision::Ask {
            path: Path::new("/workspace/Cargo.lock").to_path_buf(),
            op: FileOp::Write,
        };

        auditor
            .log_decision(
                9999,
                AgentLabel::Human,
                Path::new("/workspace/Cargo.lock"),
                FileOp::Write,
                &ask_decision,
                PolicySource::Global,
            )
            .unwrap();

        let events = verify.recent_audit_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].decision, PolicyDecision::Ask { .. }));
    }

    #[test]
    fn log_multiple_decisions_are_ordered() {
        let store = Store::open_in_memory().unwrap();
        let verify = store.clone();
        let auditor = Auditor::new(store);

        for i in 0..5 {
            auditor
                .log_decision(
                    1000 + i,
                    AgentLabel::Definite,
                    Path::new("/workspace/file.txt"),
                    FileOp::Read,
                    &PolicyDecision::Allow,
                    PolicySource::Default,
                )
                .unwrap();
        }

        let events = verify.recent_audit_events(10).unwrap();
        assert_eq!(events.len(), 5);
        // recent_audit_events returns ORDER BY ts DESC, so oldest is last
        for (i, event) in events.iter().enumerate() {
            assert_eq!(event.agent_pid, 1000 + (4 - i as u32));
        }
    }

    #[test]
    fn log_all_operations() {
        let store = Store::open_in_memory().unwrap();
        let verify = store.clone();
        let auditor = Auditor::new(store);

        auditor
            .log_decision(
                1,
                AgentLabel::Definite,
                Path::new("/f"),
                FileOp::Read,
                &PolicyDecision::Allow,
                PolicySource::Project,
            )
            .unwrap();
        auditor
            .log_decision(
                2,
                AgentLabel::Probable,
                Path::new("/f"),
                FileOp::Write,
                &PolicyDecision::Deny,
                PolicySource::Global,
            )
            .unwrap();
        auditor
            .log_decision(
                3,
                AgentLabel::Inherited,
                Path::new("/f"),
                FileOp::Delete,
                &PolicyDecision::Ask {
                    path: PathBuf::from("/f"),
                    op: FileOp::Delete,
                },
                PolicySource::Project,
            )
            .unwrap();

        let events = verify.recent_audit_events(10).unwrap();
        assert_eq!(events.len(), 3);
        // recent_audit_events returns ORDER BY ts DESC (newest first)
        assert_eq!(events[2].operation, FileOp::Read);
        assert_eq!(events[1].operation, FileOp::Write);
        assert_eq!(events[0].operation, FileOp::Delete);
    }
}
