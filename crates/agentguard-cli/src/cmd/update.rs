//! agentguard update — auto-update from GitHub Releases.
//!
//! Fetches latest release info via GitHub API, downloads new binaries
//! via PowerShell, and replaces current binaries via batch script.

use agentguard_core::{GuardError, GuardResult};

const REPO: &str = "TheUser99-spec/AgentGuard";
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub async fn run(check_only: bool) -> GuardResult<()> {
    let latest = fetch_latest_version().await?;

    if latest == CURRENT_VERSION {
        println!("+ AgentGuard is up to date (v{CURRENT_VERSION})");
        return Ok(());
    }

    if check_only {
        println!("+ Update available: v{latest} (current: v{CURRENT_VERSION})");
        println!("  Run `agentguard update` to install.");
        return Ok(());
    }

    println!("+ Updating from v{CURRENT_VERSION} to v{latest}...");
    download_and_replace(&latest).await?;
    println!("+ Update complete! Restart AgentGuard to use v{latest}.");
    Ok(())
}

async fn fetch_latest_version() -> GuardResult<String> {
    let ps = format!(
        r#"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {{
    $r = Invoke-RestMethod -Uri 'https://api.github.com/repos/{REPO}/releases/latest' -UserAgent 'agentguard-updater'
    Write-Output $r.tag_name
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}}"#
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
        .map_err(|e| GuardError::IpcError(format!("Failed to run powershell: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GuardError::IpcError(format!(
            "Failed to check updates: {stderr}"
        )));
    }

    let tag = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if tag.is_empty() {
        return Err(GuardError::IpcError("No tag_name in release".into()));
    }

    Ok(tag.trim_start_matches('v').to_string())
}

async fn download_and_replace(version: &str) -> GuardResult<()> {
    let exe_dir = std::env::current_exe()
        .map_err(|e| GuardError::IpcError(format!("current_exe: {e}")))?
        .parent()
        .ok_or_else(|| GuardError::IpcError("no parent dir".into()))?
        .to_path_buf();

    let tmp_dir = std::env::temp_dir();
    let new_exe = tmp_dir.join("agentguard-new.exe");
    let new_daemon = tmp_dir.join("agentguard-daemon-new.exe");
    let bat = tmp_dir.join("agentguard-update.bat");

    let exe_url = format!(
        "https://github.com/{REPO}/releases/download/v{version}/agentguard.exe"
    );

    // Download agentguard.exe via PowerShell
    download_via_ps(&exe_url, &new_exe)?;

    // Download daemon (optional)
    let daemon_url = format!(
        "https://github.com/{REPO}/releases/download/v{version}/agentguard-daemon.exe"
    );
    let _ = download_via_ps(&daemon_url, &new_daemon);

    // Write update batch script that replaces files after this process exits
    let new_exe_str = new_exe.display().to_string();
    let exe_dest = exe_dir.join("agentguard.exe");
    let daemon_dest = exe_dir.join("agentguard-daemon.exe");
    let new_daemon_str = new_daemon.display().to_string();

    let bat_content = format!(
        "@echo off\r\n\
         timeout /t 2 /nobreak >nul\r\n\
         move /Y \"{new_exe_str}\" \"{}\" >nul 2>&1\r\n\
         if exist \"{new_daemon_str}\" move /Y \"{new_daemon_str}\" \"{}\" >nul 2>&1\r\n\
         echo AgentGuard updated to v{version}\r\n\
         del \"%~f0\"\r\n",
        exe_dest.display(),
        daemon_dest.display()
    );

    std::fs::write(&bat, bat_content)
        .map_err(|e| GuardError::IpcError(format!("Cannot write update script: {e}")))?;

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        std::process::Command::new("cmd.exe")
            .args(["/C", &bat.to_string_lossy()])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| GuardError::IpcError(format!("Cannot launch updater: {e}")))?;
    }

    Ok(())
}

fn download_via_ps(url: &str, dest: &std::path::Path) -> GuardResult<()> {
    let ps = format!(
        r#"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {{
    Invoke-WebRequest -Uri '{}' -OutFile '{}' -UserAgent 'agentguard-updater'
    exit 0
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}}"#,
        url,
        dest.display()
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .output()
        .map_err(|e| GuardError::IpcError(format!("download failed: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(GuardError::IpcError(format!("download failed: {stderr}")));
    }

    Ok(())
}
