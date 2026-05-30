use agentguard_core::{AgentLabel, AgentSession};
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::classifier::{ProcessInfo, SubjectClassifier};

#[derive(Clone)]
pub struct AgentSessionTracker {
    inner: Arc<RwLock<TrackerInner>>,
    pub classifier: Arc<SubjectClassifier>,
}

struct TrackerInner {
    sessions: HashMap<u32, TrackedProcess>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TrackedProcess {
    pub pid: u32,
    pub label: AgentLabel,
    pub image_name: String,
    pub workspace: Option<PathBuf>,
    pub started_at: chrono::DateTime<Utc>,
    pub parent_pid: Option<u32>,
}

impl AgentSessionTracker {
    pub fn new(classifier: SubjectClassifier) -> Self {
        Self {
            inner: Arc::new(RwLock::new(TrackerInner {
                sessions: HashMap::new(),
            })),
            classifier: Arc::new(classifier),
        }
    }

    pub fn on_process_start(&self, info: &ProcessInfo, workspace: Option<PathBuf>) -> AgentLabel {
        let mut label = self.classifier.classify(info);

        if label == AgentLabel::Human {
            if let Some(parent_pid) = info.parent_pid {
                let inner = self.inner.read().unwrap_or_else(|e| e.into_inner());
                if let Some(parent) = inner.sessions.get(&parent_pid) {
                    if parent.label.is_agent() {
                        label = AgentLabel::Inherited;
                    }
                }
            }
        }

        if label.is_agent() {
            let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
            inner.sessions.insert(
                info.pid,
                TrackedProcess {
                    pid: info.pid,
                    label,
                    image_name: info.image_name.clone(),
                    workspace,
                    started_at: Utc::now(),
                    parent_pid: info.parent_pid,
                },
            );
        }

        label
    }

    pub fn on_process_exit(&self, pid: u32) -> Option<AgentSession> {
        let mut inner = self.inner.write().unwrap_or_else(|e| e.into_inner());
        inner.sessions.remove(&pid).map(|p| AgentSession {
            id: None,
            pid: p.pid,
            image_name: p.image_name,
            label: p.label,
            workspace: p.workspace,
            started_at: p.started_at,
            ended_at: Some(Utc::now()),
        })
    }

    pub fn get_label(&self, pid: u32) -> Option<AgentLabel> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .get(&pid)
            .map(|p| p.label)
    }

    pub fn get_image_name(&self, pid: u32) -> Option<String> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .get(&pid)
            .map(|p| p.image_name.clone())
    }

    pub fn active_sessions(&self) -> Vec<AgentSession> {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .values()
            .map(|p| AgentSession {
                id: None,
                pid: p.pid,
                image_name: p.image_name.clone(),
                label: p.label,
                workspace: p.workspace.clone(),
                started_at: p.started_at,
                ended_at: None,
            })
            .collect()
    }

    pub fn active_count(&self) -> usize {
        self.inner
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::classifier::ProcessInfo;

    fn make_info(pid: u32, image: &str, parent: Option<u32>) -> ProcessInfo {
        ProcessInfo {
            pid,
            image_name: image.to_string(),
            cmdline: String::new(),
            env_vars: vec![],
            session_id: 1,
            has_window: true,
            parent_pid: parent,
        }
    }

    #[test]
    fn cursor_tracked_and_removed() {
        let tracker = AgentSessionTracker::new(SubjectClassifier::with_defaults());

        let label = tracker.on_process_start(
            &make_info(100, "cursor.exe", None),
            Some(PathBuf::from("/my/project")),
        );
        assert_eq!(label, AgentLabel::Definite);
        assert_eq!(tracker.active_count(), 1);

        let session = tracker.on_process_exit(100).unwrap();
        assert_eq!(session.pid, 100);
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn child_of_agent_is_inherited() {
        let tracker = AgentSessionTracker::new(SubjectClassifier::with_defaults());

        tracker.on_process_start(&make_info(100, "cursor.exe", None), None);

        let label = tracker.on_process_start(&make_info(101, "git.exe", Some(100)), None);
        assert_eq!(label, AgentLabel::Inherited);
    }

    #[test]
    fn human_process_not_tracked() {
        let tracker = AgentSessionTracker::new(SubjectClassifier::with_defaults());

        let label = tracker.on_process_start(&make_info(200, "notepad.exe", None), None);
        assert_eq!(label, AgentLabel::Human);
        assert_eq!(tracker.active_count(), 0);
    }
}
