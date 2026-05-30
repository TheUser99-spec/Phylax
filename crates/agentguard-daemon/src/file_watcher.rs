use crate::orchestrator::DaemonState;
use agentguard_core::GuardResult;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub async fn run_file_watcher(
    state: Arc<DaemonState>,
    mut stop_rx: mpsc::Receiver<()>,
) -> GuardResult<()> {
    let mut snapshots: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(5000)) => {
                for workspace in state.list_projects() {
                    let current = list_files(&workspace);
                    let prev = snapshots.entry(workspace.clone()).or_default();

                    for path in &current {
                        if !prev.contains(path) {
                            state.protect_new_file(path);
                        }
                    }
                    *prev = current;
                }
            }
            _ = stop_rx.recv() => break,
        }
    }
    Ok(())
}

fn list_files(root: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_string_lossy();
            !matches!(n.as_ref(), ".git" | "node_modules" | "target" | "__pycache__" | ".venv")
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}
