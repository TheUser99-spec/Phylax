pub mod migrations;
pub mod queries;

pub use queries::{AgentRuleRow, RegisteredProject};

use agentguard_core::GuardError;
use rusqlite::{Connection, OpenFlags};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::info;

/// Thread-safe handle to the SQLite database.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Connection>>,
}

impl Store {
    /// Open (or create) the AgentGuard database at the given path.
    /// Runs all pending migrations automatically.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, GuardError> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                GuardError::Database(format!("cannot create db dir {}: {e}", parent.display()))
            })?;
        }

        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| GuardError::Database(format!("open {}: {e}", path.display())))?;

        conn.execute_batch("PRAGMA busy_timeout = 1000;")
            .map_err(|e| GuardError::Database(format!("PRAGMA busy_timeout: {e}")))?;

        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous  = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA cache_size   = -8000;",
        )
        .map_err(|e| GuardError::Database(format!("PRAGMA setup: {e}")))?;

        let store = Self {
            inner: Arc::new(Mutex::new(conn)),
        };

        store.migrate()?;
        info!("store opened at {}", path.display());
        Ok(store)
    }

    /// Open an in-memory database (for tests).
    pub fn open_in_memory() -> Result<Self, GuardError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| GuardError::Database(format!("open in-memory: {e}")))?;

        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(|e| GuardError::Database(format!("PRAGMA: {e}")))?;

        let store = Self {
            inner: Arc::new(Mutex::new(conn)),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), GuardError> {
        let mut guard = self.lock()?;
        migrations::run(&mut guard)
    }

    pub(crate) fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, GuardError> {
        self.inner
            .lock()
            .map_err(|e| GuardError::Database(format!("mutex poisoned: {e}")))
    }

    /// Default database path on Windows: %APPDATA%\AgentGuard\agentguard.db
    /// Falls back to %LOCALAPPDATA% → %USERPROFILE% → current directory.
    pub fn default_path() -> PathBuf {
        #[cfg(target_os = "windows")]
        {
            let appdata = std::env::var("APPDATA")
                .or_else(|_| std::env::var("LOCALAPPDATA"))
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            PathBuf::from(appdata)
                .join("AgentGuard")
                .join("agentguard.db")
        }
        #[cfg(not(target_os = "windows"))]
        {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("agentguard")
                .join("agentguard.db")
        }
    }
}
