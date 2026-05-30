use agentguard_core::GuardResult;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;

use crate::orchestrator::DaemonState;

#[derive(Debug)]
#[allow(dead_code)]
pub enum WatchEvent {
    ManifestChanged(PathBuf),
}

pub async fn run_watcher(
    state: Arc<DaemonState>,
    mut stop_rx: mpsc::Receiver<()>,
) -> GuardResult<()> {
    let mut last_modified: HashMap<PathBuf, SystemTime> = HashMap::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                for workspace in state.list_projects() {
                    let toml = workspace.join("agentguard.toml");
                    let meta = match std::fs::metadata(&toml) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if let Ok(modified) = meta.modified() {
                        let prev = last_modified.get(&workspace).copied();
                        if prev.map(|p| p != modified).unwrap_or(true) {
                            last_modified.insert(workspace.clone(), modified);
                            if prev.is_some() {
                                eprintln!(
                                    "[daemon] agentguard.toml changed, hot-reloading {}",
                                    workspace.display()
                                );
                                if let Err(e) = state.reload_project(&workspace) {
                                    tracing::error!("Hot-reload error: {e}");
                                }
                            }
                        }
                    }
                }
            }
            _ = stop_rx.recv() => break,
        }
    }
    Ok(())
}
