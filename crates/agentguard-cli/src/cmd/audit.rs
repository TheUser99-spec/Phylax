//! Audit commands: list, export, db path.

use agentguard_core::{GuardError, GuardResult};
use agentguard_ipc::IpcClient;
use std::path::PathBuf;

pub async fn list(limit: usize) -> GuardResult<()> {
    let client = IpcClient::new();
    let status = client
        .get_status()
        .await
        .map_err(|_| GuardError::DaemonNotRunning)?;

    let events = &status.recent_events;
    let shown = events.len().min(limit);

    if events.is_empty() {
        println!("No audit events recorded yet.");
        println!("Events are logged when agent access decisions are made.");
        return Ok(());
    }

    println!("{} events today, {} blocked", status.events_today, status.blocks_today);
    println!("Showing {} of {} recent events:", shown, events.len());
    println!(
        "{:<10} {:<8} {:<10} {:<8} {:<6} {}",
        "TIME", "VERDICT", "LABEL", "PID", "OP", "FILE"
    );
    println!("{}", "-".repeat(80));

    for e in events.iter().take(limit) {
        let ts = chrono::DateTime::from_timestamp(e.timestamp, 0)
            .map(|dt| dt.format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "--:--:--".into());

        let label = &e.agent_label;
        let pid = e.agent_pid;
        let op = &e.operation;
        let file = &e.file_path;

        let decision = match e.decision.as_str() {
            "deny" | "blocked" => format!("\x1b[31m{:>8}\x1b[0m", e.decision.to_uppercase()),
            "ask" | "asked" => format!("\x1b[33m{:>8}\x1b[0m", e.decision.to_uppercase()),
            "allow" | "allowed" => format!("\x1b[32m{:>8}\x1b[0m", e.decision.to_uppercase()),
            _ => format!("{:>8}", e.decision.to_uppercase()),
        };

        println!("{ts:<10} {decision} {label:<10} {pid:<8} {op:<6} {file}");
    }

    Ok(())
}

pub async fn export_logs(format: String, output: PathBuf, limit: Option<usize>) -> GuardResult<()> {
    let client = IpcClient::new();
    let status = client
        .get_status()
        .await
        .map_err(|_| GuardError::DaemonNotRunning)?;

    let events = &status.recent_events;
    let count = limit.unwrap_or(events.len()).min(events.len());

    if events.is_empty() {
        println!("No audit events to export.");
        return Ok(());
    }

    match format.as_str() {
        "csv" => {
            let mut w = String::new();
            w.push_str("TIME,VERDICT,LABEL,PID,OPERATION,FILE,SOURCE\n");
            for e in events.iter().take(count) {
                let ts = chrono::DateTime::from_timestamp(e.timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "--".into());
                let file = e.file_path.replace(',', "\\,");
                w.push_str(&format!(
                    "{ts},{},{},{},{},{},{}\n",
                    e.decision, e.agent_label, e.agent_pid, e.operation, file, e.source
                ));
            }
            std::fs::write(&output, w)
                .map_err(|e| GuardError::IpcError(format!("Cannot write {}: {e}", output.display())))?;
        }
        "txt" => {
            let mut w = String::new();
            w.push_str(&format!("Phylax Audit Log\n"));
            w.push_str(&format!("{} events, {} blocked\n\n", status.events_today, status.blocks_today));
            w.push_str(&format!(
                "{:<22} {:<8} {:<10} {:<8} {:<6} {}\n",
                "TIME", "VERDICT", "LABEL", "PID", "OP", "FILE"
            ));
            w.push_str(&format!("{}\n", "-".repeat(90)));
            for e in events.iter().take(count) {
                let ts = chrono::DateTime::from_timestamp(e.timestamp, 0)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|| "--".into());
                w.push_str(&format!(
                    "{ts:<22} {:<8} {:<10} {:<8} {:<6} {}\n",
                    e.decision.to_uppercase(), e.agent_label, e.agent_pid, e.operation, e.file_path
                ));
            }
            std::fs::write(&output, w)
                .map_err(|e| GuardError::IpcError(format!("Cannot write {}: {e}", output.display())))?;
        }
        _ => {
            return Err(GuardError::IpcError(
                "Unsupported format. Use: csv, txt".into(),
            ));
        }
    }

    println!("Exported {} events to {}", count, output.display());
    Ok(())
}

pub fn db_path() -> GuardResult<()> {
    let appdata = std::env::var("APPDATA")
        .or_else(|_| std::env::var("LOCALAPPDATA"))
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    let path = std::path::PathBuf::from(appdata)
        .join("phylax")
        .join("phylax.db");

    println!("Audit database: {}", path.display());
    println!();
    println!("Browse with any SQLite tool:");
    println!("  sqlite3 {} \"SELECT * FROM audit_events LIMIT 10;\"", path.display());
    println!();
    println!("Or open in DB Browser for SQLite (https://sqlitebrowser.org/)");
    println!("  File → Open Database → {}", path.display());
    Ok(())
}
