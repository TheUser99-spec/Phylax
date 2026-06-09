use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Permission Buckets ───────────────────────────────────────────────────────

/// The six permission buckets, ordered by priority (lower number = higher priority).
/// Priority: deny(1) > ask(2) > full(3) > delete(4) > write(5) > read(6)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Bucket {
    Deny = 1,
    Ask = 2,
    Full = 3,
    Delete = 4,
    Write = 5,
    Read = 6,
}

impl Bucket {
    pub fn priority(&self) -> u8 {
        *self as u8
    }

    pub fn beats(&self, other: &Bucket) -> bool {
        self.priority() < other.priority()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Bucket::Deny => "deny",
            Bucket::Ask => "ask",
            Bucket::Full => "full",
            Bucket::Delete => "delete",
            Bucket::Write => "write",
            Bucket::Read => "read",
        }
    }
}

impl std::fmt::Display for Bucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── File Operations ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileOp {
    Read,
    Write,
    Delete,
}

impl FileOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileOp::Read => "read",
            FileOp::Write => "write",
            FileOp::Delete => "delete",
        }
    }
}

impl std::fmt::Display for FileOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Policy Decision ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDecision {
    Allow,
    Deny,
    Ask { path: PathBuf, op: FileOp },
}

impl PolicyDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyDecision::Allow => "allow",
            PolicyDecision::Deny => "deny",
            PolicyDecision::Ask { .. } => "ask",
        }
    }
}

impl std::fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Default Mode (when no bucket rule matches) ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DefaultMode {
    #[default]
    Conservative,
    Unrestricted,
}

// ─── Agent Classification ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentLabel {
    Definite,
    Probable,
    Inherited,
    Human,
}

impl AgentLabel {
    pub fn is_agent(&self) -> bool {
        matches!(
            self,
            AgentLabel::Definite | AgentLabel::Probable | AgentLabel::Inherited
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AgentLabel::Definite => "DEFINITE",
            AgentLabel::Probable => "PROBABLE",
            AgentLabel::Inherited => "INHERITED",
            AgentLabel::Human => "HUMAN",
        }
    }
}

impl std::fmt::Display for AgentLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ─── Policy Source ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicySource {
    Agent,
    Global,
    Project,
    Default,
}

impl PolicySource {
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicySource::Agent => "agent",
            PolicySource::Global => "global",
            PolicySource::Project => "project",
            PolicySource::Default => "default",
        }
    }
}

// ─── Agent Event ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    pub pid: u32,
    pub label: AgentLabel,
    pub image: String,
    pub path: PathBuf,
    pub op: FileOp,
    pub workspace: Option<PathBuf>,
    pub timestamp: DateTime<Utc>,
}

// ─── Audit Event ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Option<i64>,
    pub agent_pid: u32,
    pub agent_label: AgentLabel,
    pub file_path: PathBuf,
    pub operation: FileOp,
    pub decision: PolicyDecision,
    pub source: PolicySource,
    pub timestamp: DateTime<Utc>,
}

// ─── Agent Session ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub id: Option<i64>,
    pub pid: u32,
    pub image_name: String,
    pub label: AgentLabel,
    pub workspace: Option<PathBuf>,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

// ─── Global Rule ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRule {
    pub id: Option<i64>,
    pub bucket: Bucket,
    pub pattern: String,
    pub created: DateTime<Utc>,
}

// ─── Watched Project ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchedProject {
    pub id: Option<i64>,
    pub root: PathBuf,
    pub name: String,
    pub registered_at: DateTime<Utc>,
    pub active: bool,
}

// ─── Ask Response ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AskResponse {
    AllowOnce,
    AllowSession,
    Deny,
}

// ─── Default permissions (no explicit rule) ───────────────────────────────────

pub fn default_decision(op: FileOp, path: PathBuf) -> PolicyDecision {
    match op {
        FileOp::Read => PolicyDecision::Allow,
        FileOp::Write => PolicyDecision::Ask { path, op },
        FileOp::Delete => PolicyDecision::Deny,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_priority_order() {
        assert!(Bucket::Deny.beats(&Bucket::Ask));
        assert!(Bucket::Ask.beats(&Bucket::Full));
        assert!(Bucket::Full.beats(&Bucket::Delete));
        assert!(Bucket::Delete.beats(&Bucket::Write));
        assert!(Bucket::Write.beats(&Bucket::Read));
        assert!(!Bucket::Read.beats(&Bucket::Deny));
    }

    #[test]
    fn bucket_deny_beats_all() {
        let all = [
            Bucket::Ask,
            Bucket::Full,
            Bucket::Delete,
            Bucket::Write,
            Bucket::Read,
        ];
        for b in &all {
            assert!(Bucket::Deny.beats(b), "deny should beat {b}");
        }
    }

    #[test]
    fn default_decision_read_is_allow() {
        let d = default_decision(FileOp::Read, PathBuf::from("/any/path"));
        assert_eq!(d, PolicyDecision::Allow);
    }

    #[test]
    fn default_decision_delete_is_deny() {
        let d = default_decision(FileOp::Delete, PathBuf::from("/any/path"));
        assert_eq!(d, PolicyDecision::Deny);
    }

    #[test]
    fn agent_label_is_agent() {
        assert!(AgentLabel::Definite.is_agent());
        assert!(AgentLabel::Probable.is_agent());
        assert!(AgentLabel::Inherited.is_agent());
        assert!(!AgentLabel::Human.is_agent());
    }
}
