//! phylax serve — starts daemon + opens web dashboard.
//!
//! Spawns phylax-daemon.exe as a detached background process,
//! waits for IPC, then opens the dashboard in the default browser.

use agentguard_core::{GuardError, GuardResult};
use agentguard_ipc::IpcClient;
use std::time::Duration;

pub async fn serve(port: Option<u16>) -> GuardResult<()> {
    let port = port.unwrap_or(1977);
    let url = format!("http://127.0.0.1:{port}");

    if IpcClient::new().get_status().await.is_ok() {
        println!("+ Daemon already running, opening dashboard...");
        open_browser(&url);
        println!("  Dashboard: {url}");
        return Ok(());
    }

    let daemon_exe = daemon_binary_path();
    if !daemon_exe.exists() {
        return Err(GuardError::IpcError(format!(
            "Daemon binary not found at {:?}. Build or install Phylax first.",
            daemon_exe
        )));
    }

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        let mut cmd = std::process::Command::new(&daemon_exe);
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if port != 1977 {
            cmd.env("PHYLAX_WEB_PORT", port.to_string());
        }
        cmd.spawn()
            .map_err(|e| GuardError::IpcError(format!("Failed to spawn daemon: {e}")))?;
    }
    #[cfg(not(windows))]
    {
        let mut cmd = std::process::Command::new(&daemon_exe);
        cmd.stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if port != 1977 {
            cmd.env("PHYLAX_WEB_PORT", port.to_string());
        }
        cmd.spawn()
            .map_err(|e| GuardError::IpcError(format!("Failed to spawn daemon: {e}")))?;
    }

    eprintln!("+ Waiting for daemon...");
    let client = IpcClient::new();
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client.get_status().await.is_ok() {
            println!("+ Daemon ready. Opening dashboard...");
            open_browser(&url);
            println!();
            println!("  Phylax Dashboard");
            println!("  \u{2192} {url}");
            println!();
            println!("  Stop with: phylax daemon stop");
            return Ok(());
        }
    }

    Err(GuardError::IpcError("Daemon not responding after 3s".into()))
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", url])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

fn daemon_binary_path() -> std::path::PathBuf {
    let mut exe = std::env::current_exe().unwrap_or_default();
    exe.set_file_name("phylax-daemon.exe");
    exe
}
