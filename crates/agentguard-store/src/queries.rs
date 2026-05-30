use agentguard_core::{
    AgentLabel, AgentSession, AuditEvent, Bucket, FileOp, GlobalRule, GuardError, PolicyDecision,
    PolicySource, WatchedProject,
};
use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection};
use std::path::PathBuf;
use tracing::debug;

use crate::Store;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn ts_to_dt(ts: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(ts, 0).single().unwrap_or_else(Utc::now)
}

fn dt_to_ts(dt: &DateTime<Utc>) -> i64 {
    dt.timestamp()
}

fn str_to_bucket(s: &str) -> Result<Bucket, GuardError> {
    match s {
        "deny" => Ok(Bucket::Deny),
        "ask" => Ok(Bucket::Ask),
        "full" => Ok(Bucket::Full),
        "delete" => Ok(Bucket::Delete),
        "write" => Ok(Bucket::Write),
        "read" => Ok(Bucket::Read),
        other => Err(GuardError::Database(format!("unknown bucket: {other}"))),
    }
}

fn str_to_file_op(s: &str) -> Result<FileOp, GuardError> {
    match s {
        "read" => Ok(FileOp::Read),
        "write" => Ok(FileOp::Write),
        "delete" => Ok(FileOp::Delete),
        other => Err(GuardError::Database(format!("unknown file op: {other}"))),
    }
}

fn str_to_label(s: &str) -> Result<AgentLabel, GuardError> {
    match s {
        "DEFINITE" => Ok(AgentLabel::Definite),
        "PROBABLE" => Ok(AgentLabel::Probable),
        "INHERITED" => Ok(AgentLabel::Inherited),
        "HUMAN" => Ok(AgentLabel::Human),
        other => Err(GuardError::Database(format!("unknown label: {other}"))),
    }
}

fn str_to_source(s: &str) -> Result<PolicySource, GuardError> {
    match s {
        "global" => Ok(PolicySource::Global),
        "project" => Ok(PolicySource::Project),
        "default" => Ok(PolicySource::Default),
        other => Err(GuardError::Database(format!("unknown source: {other}"))),
    }
}

fn decision_str(d: &PolicyDecision) -> &'static str {
    match d {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Deny => "deny",
        PolicyDecision::Ask { .. } => "ask",
    }
}

// ─── Global Rules ─────────────────────────────────────────────────────────────

impl Store {
    pub fn insert_global_rule(&self, bucket: Bucket, pattern: &str) -> Result<i64, GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO global_rules (bucket, pattern) VALUES (?1, ?2)",
            params![bucket.as_str(), pattern],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        let id = conn.last_insert_rowid();
        debug!("inserted global rule id={id} bucket={bucket} pattern={pattern}");
        Ok(id)
    }

    pub fn delete_global_rule(&self, id: i64) -> Result<(), GuardError> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM global_rules WHERE id = ?1", params![id])
            .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn list_global_rules(&self) -> Result<Vec<GlobalRule>, GuardError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT id, bucket, pattern, created FROM global_rules ORDER BY id")
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let mut rules = Vec::new();
        for row in rows {
            let (id, bucket_str, pattern, ts) =
                row.map_err(|e| GuardError::Database(e.to_string()))?;
            rules.push(GlobalRule {
                id: Some(id),
                bucket: str_to_bucket(&bucket_str)?,
                pattern,
                created: ts_to_dt(ts),
            });
        }
        Ok(rules)
    }
}

// ─── Audit Events ─────────────────────────────────────────────────────────────

impl Store {
    pub fn insert_audit_event(&self, event: &AuditEvent) -> Result<i64, GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO audit_events (agent_pid, agent_label, file_path, operation, decision, source, ts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event.agent_pid,
                event.agent_label.as_str(),
                event.file_path.to_string_lossy().as_ref(),
                event.operation.as_str(),
                decision_str(&event.decision),
                event.source.as_str(),
                dt_to_ts(&event.timestamp),
            ],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    pub fn recent_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, GuardError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, agent_pid, agent_label, file_path, operation, decision, source, ts
                 FROM audit_events
                 ORDER BY ts DESC, id DESC
                 LIMIT ?1",
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            let (id, pid, label_str, path_str, op_str, decision_str, source_str, ts) =
                row.map_err(|e| GuardError::Database(e.to_string()))?;

            let path = PathBuf::from(&path_str);
            let op = str_to_file_op(&op_str)?;

            let decision = match decision_str.as_str() {
                "allow" => PolicyDecision::Allow,
                "deny" => PolicyDecision::Deny,
                "ask" => PolicyDecision::Ask {
                    path: path.clone(),
                    op,
                },
                other => return Err(GuardError::Database(format!("unknown decision: {other}"))),
            };

            events.push(AuditEvent {
                id: Some(id),
                agent_pid: pid,
                agent_label: str_to_label(&label_str)?,
                file_path: path,
                operation: op,
                decision,
                source: str_to_source(&source_str)?,
                timestamp: ts_to_dt(ts),
            });
        }
        Ok(events)
    }

    pub fn rotate_audit_events(&self, max_rows: usize) -> Result<u64, GuardError> {
        let conn = self.lock()?;
        let deleted = conn
            .execute(
                "DELETE FROM audit_events
             WHERE id NOT IN (
                 SELECT id FROM audit_events ORDER BY ts DESC, id DESC LIMIT ?1
             )",
                params![max_rows as i64],
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(deleted as u64)
    }
}

// ─── Agent Sessions ───────────────────────────────────────────────────────────

impl Store {
    pub fn start_session(&self, session: &AgentSession) -> Result<i64, GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO agent_sessions (pid, image_name, label, workspace, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session.pid,
                &session.image_name,
                session.label.as_str(),
                session
                    .workspace
                    .as_ref()
                    .map(|p| p.to_string_lossy().into_owned()),
                dt_to_ts(&session.started_at),
            ],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    pub fn end_session(&self, pid: u32) -> Result<(), GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE agent_sessions SET ended_at = unixepoch() WHERE pid = ?1 AND ended_at IS NULL",
            params![pid],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn active_sessions(&self) -> Result<Vec<AgentSession>, GuardError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, pid, image_name, label, workspace, started_at
                 FROM agent_sessions
                 WHERE ended_at IS NULL
                 ORDER BY started_at DESC",
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let mut sessions = Vec::new();
        for row in rows {
            let (id, pid, image, label_str, workspace, started_ts) =
                row.map_err(|e| GuardError::Database(e.to_string()))?;
            sessions.push(AgentSession {
                id: Some(id),
                pid,
                image_name: image,
                label: str_to_label(&label_str)?,
                workspace: workspace.map(PathBuf::from),
                started_at: ts_to_dt(started_ts),
                ended_at: None,
            });
        }
        Ok(sessions)
    }
}

// ─── Watched Projects ─────────────────────────────────────────────────────────

impl Store {
    pub fn register_project(&self, root: &std::path::Path, name: &str) -> Result<i64, GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO watched_projects (root, name, active)
             VALUES (?1, ?2, 1)
             ON CONFLICT(root) DO UPDATE SET active = 1, name = excluded.name",
            params![root.to_string_lossy().as_ref(), name],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    pub fn unregister_project(&self, root: &std::path::Path) -> Result<(), GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE watched_projects SET active = 0 WHERE root = ?1",
            params![root.to_string_lossy().as_ref()],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn active_projects(&self) -> Result<Vec<WatchedProject>, GuardError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, root, name, registered_at FROM watched_projects
                 WHERE active = 1 ORDER BY registered_at DESC",
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let mut projects = Vec::new();
        for row in rows {
            let (id, root, name, ts) = row.map_err(|e| GuardError::Database(e.to_string()))?;
            projects.push(WatchedProject {
                id: Some(id),
                root: PathBuf::from(root),
                name,
                registered_at: ts_to_dt(ts),
                active: true,
            });
        }
        Ok(projects)
    }
}

// ─── Registered Projects (for daemon) ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RegisteredProject {
    pub path: PathBuf,
    pub name: String,
    pub added_at: i64,
    pub toml_hash: String,
}

fn get_setting_inner(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row(
        "SELECT value FROM settings WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .ok()
}

impl Store {
    pub fn list_projects(&self) -> Result<Vec<RegisteredProject>, GuardError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT root, name, registered_at FROM watched_projects
                 WHERE active = 1 ORDER BY registered_at DESC",
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| GuardError::Database(e.to_string()))?;

        // Collect projects first, then query hashes separately to avoid
        // re-locking the mutex (std::sync::Mutex is not reentrant).
        let mut projects = Vec::new();
        for row in rows {
            let (root, name, ts) = row.map_err(|e| GuardError::Database(e.to_string()))?;
            let path = PathBuf::from(&root);
            let toml_hash =
                get_setting_inner(&conn, &format!("toml_hash:{root}")).unwrap_or_default();
            projects.push(RegisteredProject {
                path,
                name,
                added_at: ts,
                toml_hash,
            });
        }
        Ok(projects)
    }

    pub fn set_project_hash(&self, root: &::std::path::Path, hash: &str) -> Result<(), GuardError> {
        let key = format!("toml_hash:{}", root.to_string_lossy());
        self.set_setting(&key, hash)
    }

    pub fn count_events_today(&self) -> Result<(u64, u64), GuardError> {
        let conn = self.lock()?;
        // Daily stats are computed in local machine time for UI alignment.
        let total: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE date(ts, 'unixepoch', 'localtime') = date('now', 'localtime')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;
        let blocks: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_events
                 WHERE decision = 'deny'
                   AND date(ts, 'unixepoch', 'localtime') = date('now', 'localtime')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok((total, blocks))
    }

    pub fn stats_today(&self) -> Result<(u64, u64, u64, u64), GuardError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT
                    COUNT(*) as total,
                    COALESCE(SUM(CASE WHEN decision='deny'  THEN 1 ELSE 0 END), 0) as blocks,
                    COALESCE(SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END), 0) as allows,
                    COALESCE(SUM(CASE WHEN decision='ask'   THEN 1 ELSE 0 END), 0) as asks
                 FROM audit_events
                 WHERE date(ts, 'unixepoch', 'localtime') = date('now', 'localtime')",
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;

        stmt.query_row([], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })
        .map_err(|e| GuardError::Database(e.to_string()))
    }

    pub fn top_agents_today(&self, limit: usize) -> Result<Vec<(String, u64)>, GuardError> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT agent_label, COUNT(*) as cnt
                 FROM audit_events
                 WHERE date(ts, 'unixepoch', 'localtime') = date('now', 'localtime')
                 GROUP BY agent_label
                 ORDER BY cnt DESC
                 LIMIT ?1",
            )
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![limit as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(|e| GuardError::Database(e.to_string()))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| GuardError::Database(e.to_string()))?);
        }
        Ok(result)
    }
}

// ─── Settings ─────────────────────────────────────────────────────────────────

impl Store {
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, GuardError> {
        let conn = self.lock()?;
        let result = conn.query_row(
            "SELECT value FROM settings WHERE key = ?1",
            params![key],
            |row| row.get(0),
        );
        match result {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(GuardError::Database(e.to_string())),
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn tier(&self) -> Result<String, GuardError> {
        Ok(self
            .get_setting("tier")?
            .unwrap_or_else(|| "free".to_string()))
    }

    pub fn insert_ask_decision(
        &self,
        path: &std::path::Path,
        response: &str,
        session_id: i64,
    ) -> Result<(), GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO ask_decisions (path, response, session_id, decided_at)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                path.to_string_lossy().to_string(),
                response,
                session_id,
                chrono::Utc::now().timestamp(),
            ],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(())
    }

    // ── Agent rules ──────────────────────────────────────────────────────

    pub fn insert_agent_rule(
        &self,
        agent_image: &str,
        bucket: &str,
        pattern: &str,
    ) -> Result<i64, GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO agent_rules (agent_image, bucket, pattern) VALUES (?1, ?2, ?3)",
            rusqlite::params![agent_image, bucket, pattern],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(conn.last_insert_rowid())
    }

    pub fn delete_agent_rule(&self, id: i64) -> Result<(), GuardError> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM agent_rules WHERE id = ?1",
            rusqlite::params![id],
        )
        .map_err(|e| GuardError::Database(e.to_string()))?;
        Ok(())
    }

    pub fn list_agent_rules(
        &self,
        agent_image: Option<&str>,
    ) -> Result<Vec<AgentRuleRow>, GuardError> {
        let conn = self.lock()?;
        let mut rows_data: Vec<(i64, String, String, String)> = Vec::new();

        {
            let mut stmt = if let Some(_img) = agent_image {
                conn.prepare(
                    "SELECT id, agent_image, bucket, pattern FROM agent_rules WHERE agent_image = ?1 ORDER BY id",
                )
            } else {
                conn.prepare(
                    "SELECT id, agent_image, bucket, pattern FROM agent_rules ORDER BY agent_image, id",
                )
            }
            .map_err(|e| GuardError::Database(e.to_string()))?;

            let mut rows = if let Some(img) = agent_image {
                stmt.query(rusqlite::params![img])
            } else {
                stmt.query([])
            }
            .map_err(|e| GuardError::Database(e.to_string()))?;

            while let Some(row) = rows
                .next()
                .map_err(|e| GuardError::Database(e.to_string()))?
            {
                rows_data.push((
                    row.get::<_, i64>(0)
                        .map_err(|e| GuardError::Database(e.to_string()))?,
                    row.get::<_, String>(1)
                        .map_err(|e| GuardError::Database(e.to_string()))?,
                    row.get::<_, String>(2)
                        .map_err(|e| GuardError::Database(e.to_string()))?,
                    row.get::<_, String>(3)
                        .map_err(|e| GuardError::Database(e.to_string()))?,
                ));
            }
        }

        Ok(rows_data
            .into_iter()
            .map(|(id, agent_image, bucket, pattern)| AgentRuleRow {
                id,
                agent_image,
                bucket,
                pattern,
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct AgentRuleRow {
    pub id: i64,
    pub agent_image: String,
    pub bucket: String,
    pub pattern: String,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn store() -> Store {
        Store::open_in_memory().expect("in-memory store")
    }

    #[test]
    fn global_rules_crud() {
        let s = store();
        let id = s.insert_global_rule(Bucket::Deny, "**/.ssh/**").unwrap();
        assert!(id > 0);

        let rules = s.list_global_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].bucket, Bucket::Deny);
        assert_eq!(rules[0].pattern, "**/.ssh/**");

        s.delete_global_rule(id).unwrap();
        assert!(s.list_global_rules().unwrap().is_empty());
    }

    #[test]
    fn audit_event_roundtrip() {
        let s = store();
        let event = AuditEvent {
            id: None,
            agent_pid: 1234,
            agent_label: AgentLabel::Definite,
            file_path: PathBuf::from("/project/.env"),
            operation: FileOp::Read,
            decision: PolicyDecision::Deny,
            source: PolicySource::Project,
            timestamp: Utc::now(),
        };
        let id = s.insert_audit_event(&event).unwrap();
        assert!(id > 0);

        let recent = s.recent_audit_events(10).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].agent_pid, 1234);
        assert_eq!(recent[0].operation, FileOp::Read);
    }

    #[test]
    fn audit_rotation() {
        let s = store();
        for i in 0..20u32 {
            let event = AuditEvent {
                id: None,
                agent_pid: i,
                agent_label: AgentLabel::Definite,
                file_path: PathBuf::from("/x"),
                operation: FileOp::Read,
                decision: PolicyDecision::Allow,
                source: PolicySource::Default,
                timestamp: Utc::now(),
            };
            s.insert_audit_event(&event).unwrap();
        }
        let deleted = s.rotate_audit_events(10).unwrap();
        assert_eq!(deleted, 10);
        assert_eq!(s.recent_audit_events(100).unwrap().len(), 10);
    }

    #[test]
    fn session_lifecycle() {
        let s = store();
        let session = AgentSession {
            id: None,
            pid: 999,
            image_name: "claude.exe".into(),
            label: AgentLabel::Definite,
            workspace: Some(PathBuf::from("C:/projects/myapp")),
            started_at: Utc::now(),
            ended_at: None,
        };
        s.start_session(&session).unwrap();
        assert_eq!(s.active_sessions().unwrap().len(), 1);

        s.end_session(999).unwrap();
        assert!(s.active_sessions().unwrap().is_empty());
    }

    #[test]
    fn settings_roundtrip() {
        let s = store();
        s.set_setting("tier", "guardian").unwrap();
        assert_eq!(s.get_setting("tier").unwrap(), Some("guardian".to_string()));
        assert_eq!(s.tier().unwrap(), "guardian");
    }

    #[test]
    fn project_registration() {
        let s = store();
        let root = Path::new("C:/projects/myapp");
        s.register_project(root, "myapp").unwrap();
        let projects = s.active_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "myapp");

        s.unregister_project(root).unwrap();
        assert!(s.active_projects().unwrap().is_empty());
    }

    #[test]
    fn stats_today_initial_is_zero() {
        let s = store();
        let (total, blocks, allows, asks) = s.stats_today().unwrap();
        assert_eq!(total, 0);
        assert_eq!(blocks, 0);
        assert_eq!(allows, 0);
        assert_eq!(asks, 0);
    }

    #[test]
    fn stats_today_counts_by_decision() {
        let s = store();
        let event = |decision: &str| AuditEvent {
            id: None,
            agent_pid: 100,
            agent_label: AgentLabel::Definite,
            file_path: PathBuf::from("/test/file"),
            operation: FileOp::Read,
            decision: match decision {
                "deny" => PolicyDecision::Deny,
                "allow" => PolicyDecision::Allow,
                "ask" => PolicyDecision::Ask {
                    path: PathBuf::from("/test/file"),
                    op: FileOp::Read,
                },
                _ => PolicyDecision::Deny,
            },
            source: PolicySource::Project,
            timestamp: Utc::now(),
        };

        s.insert_audit_event(&event("deny")).unwrap();
        s.insert_audit_event(&event("deny")).unwrap();
        s.insert_audit_event(&event("allow")).unwrap();
        s.insert_audit_event(&event("ask")).unwrap();

        let (total, blocks, allows, asks) = s.stats_today().unwrap();
        assert_eq!(total, 4);
        assert_eq!(blocks, 2);
        assert_eq!(allows, 1);
        assert_eq!(asks, 1);
    }

    #[test]
    fn top_agents_today_counts_correctly() {
        let s = store();
        let mk = |label: AgentLabel| AuditEvent {
            id: None,
            agent_pid: 100,
            agent_label: label,
            file_path: PathBuf::from("/test/env"),
            operation: FileOp::Read,
            decision: PolicyDecision::Deny,
            source: PolicySource::Project,
            timestamp: Utc::now(),
        };

        s.insert_audit_event(&mk(AgentLabel::Definite)).unwrap();
        s.insert_audit_event(&mk(AgentLabel::Definite)).unwrap();
        s.insert_audit_event(&mk(AgentLabel::Definite)).unwrap();
        s.insert_audit_event(&mk(AgentLabel::Probable)).unwrap();
        s.insert_audit_event(&mk(AgentLabel::Probable)).unwrap();
        s.insert_audit_event(&mk(AgentLabel::Inherited)).unwrap();

        let top = s.top_agents_today(5).unwrap();
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0, "DEFINITE");
        assert_eq!(top[0].1, 3);
        assert_eq!(top[1].0, "PROBABLE");
        assert_eq!(top[1].1, 2);
        assert_eq!(top[2].0, "INHERITED");
        assert_eq!(top[2].1, 1);
    }

    #[test]
    fn top_agents_today_respects_limit() {
        let s = store();
        let mk = |label: AgentLabel| AuditEvent {
            id: None,
            agent_pid: 100,
            agent_label: label,
            file_path: PathBuf::from("/test/env"),
            operation: FileOp::Read,
            decision: PolicyDecision::Deny,
            source: PolicySource::Project,
            timestamp: Utc::now(),
        };

        for _ in 0..5 {
            s.insert_audit_event(&mk(AgentLabel::Definite)).unwrap();
        }
        s.insert_audit_event(&mk(AgentLabel::Probable)).unwrap();

        let top = s.top_agents_today(1).unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "DEFINITE");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn agent_rules_crud() {
        let s = store();
        let id = s.insert_agent_rule("cursor.exe", "deny", "*.env").unwrap();
        assert!(id > 0);

        let rules = s.list_agent_rules(None).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].agent_image, "cursor.exe");
        assert_eq!(rules[0].bucket, "deny");
        assert_eq!(rules[0].pattern, "*.env");

        s.delete_agent_rule(id).unwrap();
        assert!(s.list_agent_rules(None).unwrap().is_empty());
    }

    #[test]
    fn agent_rules_filter_by_image() {
        let s = store();
        s.insert_agent_rule("cursor.exe", "deny", "*.env").unwrap();
        s.insert_agent_rule("claude.exe", "ask", "*.key").unwrap();

        let cursor = s.list_agent_rules(Some("cursor.exe")).unwrap();
        assert_eq!(cursor.len(), 1);
        assert_eq!(cursor[0].agent_image, "cursor.exe");

        let all = s.list_agent_rules(None).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn list_projects_returns_registered_with_hash() {
        let s = store();
        let root = Path::new("/workspace/test-project");
        s.register_project(root, "test-project").unwrap();
        s.set_project_hash(root, "abc123").unwrap();

        let projects = s.list_projects().unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "test-project");
        assert_eq!(projects[0].toml_hash, "abc123");
        assert!(projects[0].path.ends_with("test-project"));
    }

    #[test]
    fn set_project_hash_updates_existing() {
        let s = store();
        let root = Path::new("/workspace/proj");
        s.register_project(root, "proj").unwrap();

        s.set_project_hash(root, "hash-v1").unwrap();
        assert_eq!(s.list_projects().unwrap()[0].toml_hash, "hash-v1");

        s.set_project_hash(root, "hash-v2").unwrap();
        assert_eq!(s.list_projects().unwrap()[0].toml_hash, "hash-v2");
    }

    #[test]
    fn count_events_today_counts_correctly() {
        let s = store();
        let now = chrono::Utc::now();

        for _ in 0..3 {
            s.insert_audit_event(&agentguard_core::AuditEvent {
                id: None,
                agent_pid: 1,
                agent_label: agentguard_core::AgentLabel::Definite,
                file_path: PathBuf::from("/f.txt"),
                operation: agentguard_core::FileOp::Read,
                decision: agentguard_core::PolicyDecision::Deny,
                source: agentguard_core::PolicySource::Project,
                timestamp: now,
            })
            .unwrap();
        }
        s.insert_audit_event(&agentguard_core::AuditEvent {
            id: None,
            agent_pid: 2,
            agent_label: agentguard_core::AgentLabel::Probable,
            file_path: PathBuf::from("/g.txt"),
            operation: agentguard_core::FileOp::Write,
            decision: agentguard_core::PolicyDecision::Allow,
            source: agentguard_core::PolicySource::Default,
            timestamp: now,
        })
        .unwrap();

        let (total, blocks) = s.count_events_today().unwrap();
        assert_eq!(total, 4);
        assert_eq!(blocks, 3);
    }

    #[test]
    fn insert_ask_decision_persists() {
        let s = store();

        let session = agentguard_core::AgentSession {
            id: None,
            pid: 42,
            image_name: "cursor.exe".to_string(),
            label: agentguard_core::AgentLabel::Definite,
            workspace: None,
            started_at: chrono::Utc::now(),
            ended_at: None,
        };
        let session_id = s.start_session(&session).unwrap();

        let path = Path::new("/workspace/.env");
        s.insert_ask_decision(path, "allow_once", session_id)
            .unwrap();
        s.insert_ask_decision(path, "deny", session_id).unwrap();

        let conn = s.lock().unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM ask_decisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);

        let (resp, sid): (String, i64) = conn
            .query_row(
                "SELECT response, session_id FROM ask_decisions ORDER BY id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(resp, "allow_once");
        assert_eq!(sid, session_id);
    }
}
