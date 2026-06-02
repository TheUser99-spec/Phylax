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
            if e.file_type().is_dir() {
                let n = e.file_name().to_string_lossy();
                if matches!(n.as_ref(), "node_modules" | "target" | "__pycache__" | ".venv") {
                    return false;
                }
                if n.as_ref() == "objects" || n.as_ref() == "pack" {
                    if let Some(parent) = e.path().parent() {
                        let pn = parent.file_name().map(|p| p.to_string_lossy()).unwrap_or_default();
                        if pn.as_ref() == ".git" || pn.as_ref() == "objects" {
                            return false;
                        }
                    }
                }
            }
            true
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect()
}
