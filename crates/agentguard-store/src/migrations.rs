use agentguard_core::GuardError;
use rusqlite::Connection;
use tracing::info;

const MIGRATIONS: &[(u32, &str)] = &[(1, MIGRATION_001), (2, MIGRATION_002), (3, MIGRATION_003)];

const MIGRATION_001: &str = r#"
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER NOT NULL,
    applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS global_rules (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    bucket   TEXT    NOT NULL CHECK(bucket IN ('deny','ask','full','delete','write','read')),
    pattern  TEXT    NOT NULL,
    created  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_global_rules_bucket ON global_rules (bucket);

CREATE TABLE IF NOT EXISTS watched_projects (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    root          TEXT    NOT NULL UNIQUE,
    name          TEXT    NOT NULL,
    registered_at INTEGER NOT NULL DEFAULT (unixepoch()),
    active        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_pid   INTEGER NOT NULL,
    agent_label TEXT    NOT NULL CHECK(agent_label IN ('DEFINITE','PROBABLE','INHERITED','HUMAN')),
    file_path   TEXT    NOT NULL,
    operation   TEXT    NOT NULL CHECK(operation   IN ('read','write','delete')),
    decision    TEXT    NOT NULL CHECK(decision    IN ('allow','deny','ask')),
    source      TEXT    NOT NULL CHECK(source      IN ('global','project','default')),
    ts          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_audit_events_ts   ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_pid  ON audit_events (agent_pid);
CREATE INDEX IF NOT EXISTS idx_audit_events_path ON audit_events (file_path);

CREATE TABLE IF NOT EXISTS agent_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pid         INTEGER NOT NULL,
    image_name  TEXT    NOT NULL,
    label       TEXT    NOT NULL CHECK(label IN ('DEFINITE','PROBABLE','INHERITED','HUMAN')),
    workspace   TEXT,
    started_at  INTEGER NOT NULL DEFAULT (unixepoch()),
    ended_at    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sessions_pid ON agent_sessions (pid);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES
    ('tier',           'free'),
    ('schema_version', '1'),
    ('install_date',   unixepoch());
"#;

const MIGRATION_002: &str = r#"
CREATE TABLE IF NOT EXISTS ask_decisions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    path       TEXT    NOT NULL,
    response   TEXT    NOT NULL CHECK(response IN ('allow_once','allow_session','deny')),
    session_id INTEGER REFERENCES agent_sessions(id),
    decided_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_ask_decisions_path ON ask_decisions (path);
"#;

const MIGRATION_003: &str = r#"
CREATE TABLE IF NOT EXISTS agent_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_image TEXT    NOT NULL,
    bucket      TEXT    NOT NULL CHECK(bucket IN ('deny','ask','full','delete','write','read')),
    pattern     TEXT    NOT NULL,
    created     INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_agent_rules_image ON agent_rules (agent_image);
"#;

/// Apply all pending migrations in order.
pub fn run(conn: &mut Connection) -> Result<(), GuardError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER NOT NULL,
            applied_at INTEGER NOT NULL DEFAULT (unixepoch())
        );",
    )
    .map_err(|e| GuardError::Migration {
        version: 0,
        reason: e.to_string(),
    })?;

    let current_version: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    for (version, sql) in MIGRATIONS {
        if *version <= current_version {
            continue;
        }

        info!("applying migration v{version}");
        let tx = conn.transaction().map_err(|e| GuardError::Migration {
            version: *version,
            reason: e.to_string(),
        })?;

        tx.execute_batch(sql).map_err(|e| GuardError::Migration {
            version: *version,
            reason: e.to_string(),
        })?;

        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            rusqlite::params![version],
        )
        .map_err(|e| GuardError::Migration {
            version: *version,
            reason: e.to_string(),
        })?;

        tx.commit().map_err(|e| GuardError::Migration {
            version: *version,
            reason: e.to_string(),
        })?;

        info!("migration v{version} applied OK");
    }

    Ok(())
}
