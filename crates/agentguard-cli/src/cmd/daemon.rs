use agentguard_core::{GuardError, GuardResult};
use agentguard_ipc::IpcClient;
use std::time::Duration;

pub async fn start() -> GuardResult<()> {
    #[cfg(windows)]
    {
        // Check if daemon is already running
        if let Ok(s) = IpcClient::new().get_status().await {
            println!(
                "+ Daemon already running (v{}, {} projects, {} agents)",
                s.version,
                s.projects.len(),
                s.active_agents.len()
            );
            return Ok(());
        }

        // If IPC is inaccessible but a daemon process exists, do NOT spawn
        // another one. This prevents split-brain/multi-daemon situations.
        if daemon_process_count() > 0 {
            return Err(GuardError::IpcError(
                "daemon process already exists but IPC is inaccessible; refusing to spawn a second instance. Run `agentguard daemon restart` from the same privilege/session.".into(),
            ));
        }

        let exe = daemon_exe_path();
        if !exe.exists() {
            return Err(GuardError::IpcError(format!(
                "Daemon binary not found at {:?}. Build it first: cargo build -p agentguard-daemon",
                exe
            )));
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
            std::process::Command::new(&exe)
                .creation_flags(CREATE_NEW_PROCESS_GROUP)
                .spawn()
                .map_err(|e| GuardError::IpcError(format!("Failed to spawn {:?}: {e}", exe)))?;
        }
        #[cfg(not(windows))]
        {
            std::process::Command::new(&exe)
                .spawn()
                .map_err(|e| GuardError::IpcError(format!("Failed to spawn {:?}: {e}", exe)))?;
        }

        let client = IpcClient::new();
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let ok = tokio::time::timeout(Duration::from_millis(500), client.get_status())
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);

            if ok {
                println!("+ Daemon started");
                return Ok(());
            }
        }
        Err(GuardError::IpcError(
            "Daemon not responding after 3s — check daemon output for errors".into(),
        ))
    }

    #[cfg(not(windows))]
    {
        println!("* Daemon only available on Windows.");
        println!("  Dev: cargo run -p agentguard-daemon");
        Ok(())
    }
}

pub async fn stop() -> GuardResult<()> {
    match IpcClient::new().shutdown().await {
        Ok(()) | Err(GuardError::IpcError { .. }) => {}
        Err(e) => {
            // Shutdown request failed — try killing by name
            kill_daemon_process();
            return Err(e);
        }
    }
    println!("+ Daemon stopped");
    Ok(())
}

pub async fn restart() -> GuardResult<()> {
    // Try graceful stop via IPC first
    let _ = IpcClient::new().shutdown().await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Force kill if still running
    kill_daemon_process();
    tokio::time::sleep(Duration::from_millis(500)).await;

    start().await
}

pub async fn emergency_stop() -> GuardResult<()> {
    #[cfg(windows)]
    {
        let before = daemon_process_count();
        if before == 0 {
            println!("+ Emergency stop: no active daemon processes");
            return Ok(());
        }

        for _ in 0..3 {
            let _ = kill_daemon_process_blocking(true);
            tokio::time::sleep(Duration::from_millis(200)).await;
            if daemon_process_count() == 0 {
                println!("+ Emergency stop complete: all daemon processes terminated");
                return Ok(());
            }
        }

        // If non-admin could not kill all processes, try one elevated kill pass.
        if !is_admin() {
            eprintln!("! Emergency stop: trying elevated kill for admin-owned daemon processes...");
            let elevated = kill_daemon_process_elevated();
            tokio::time::sleep(Duration::from_millis(300)).await;
            if elevated.is_ok() && daemon_process_count() == 0 {
                println!("+ Emergency stop complete (elevated): all daemon processes terminated");
                return Ok(());
            }
            if let Err(e) = elevated {
                let remaining = daemon_process_count();
                return Err(GuardError::IpcError(format!(
                    "Emergency stop could not elevate: {e}. Remaining daemon processes: {remaining}.",
                )));
            }
        }

        let remaining = daemon_process_count();
        return Err(GuardError::IpcError(format!(
            "Emergency stop failed: {remaining} daemon process(es) still running. Try from an Administrator terminal."
        )));
    }

    #[cfg(not(windows))]
    {
        println!("* Emergency stop only available on Windows.");
        Ok(())
    }
}

fn kill_daemon_process() {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", "agentguard-daemon.exe"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

#[cfg(windows)]
fn kill_daemon_process_blocking(kill_tree: bool) -> GuardResult<()> {
    let mut cmd = std::process::Command::new("taskkill");
    cmd.arg("/F").arg("/IM").arg("agentguard-daemon.exe");
    if kill_tree {
        cmd.arg("/T");
    }

    let output = cmd.output().map_err(|e| {
        GuardError::IpcError(format!(
            "failed to execute taskkill for emergency stop: {e}"
        ))
    })?;

    if output.status.success() {
        return Ok(());
    }

    // "No running instance" should still count as success.
    let stdout = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    let msg = format!("{stdout}\n{stderr}");
    if msg.contains("no hay ninguna instancia")
        || msg.contains("not found")
        || msg.contains("no running instance")
    {
        return Ok(());
    }

    Err(GuardError::IpcError(format!(
        "taskkill failed during emergency stop: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[cfg(windows)]
fn kill_daemon_process_elevated() -> GuardResult<()> {
    let ps = r#"
try {
  $p = Start-Process -FilePath 'taskkill.exe' -Verb RunAs -ArgumentList @('/F','/T','/IM','agentguard-daemon.exe') -PassThru -Wait
  if ($null -eq $p) { exit 1 }
  exit $p.ExitCode
} catch {
  # UAC cancel / launch failure
  exit 1223
}
"#;

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps])
        .output()
        .map_err(|e| {
            GuardError::IpcError(format!("failed to request elevated emergency stop: {e}"))
        })?;

    let code = output.status.code().unwrap_or(-1);
    if code == 0 || code == 128 {
        return Ok(());
    }
    if code == 1223 {
        return Err(GuardError::IpcError(
            "Emergency stop elevation was cancelled (UAC).".into(),
        ));
    }
    Err(GuardError::IpcError(format!(
        "Elevated emergency stop failed (exit code {code})."
    )))
}

#[cfg(windows)]
fn daemon_process_count() -> usize {
    let output = std::process::Command::new("tasklist")
        .args([
            "/FI",
            "IMAGENAME eq agentguard-daemon.exe",
            "/FO",
            "CSV",
            "/NH",
        ])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let count = stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .filter(|line| !line.starts_with("INFO:"))
                .count();
            return count;
        }
    }

    // Fallback for environments where tasklist returns ACCESS DENIED but
    // PowerShell can still enumerate process metadata.
    let ps = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-Process -Name 'agentguard-daemon' -ErrorAction SilentlyContinue | Measure-Object).Count",
        ])
        .output();

    let Ok(ps) = ps else {
        return 0;
    };
    if !ps.status.success() {
        return 0;
    }

    String::from_utf8_lossy(&ps.stdout)
        .trim()
        .parse::<usize>()
        .unwrap_or(0)
}

#[cfg(windows)]
fn daemon_exe_path() -> std::path::PathBuf {
    let mut exe = std::env::current_exe().unwrap_or_default();
    exe.set_file_name("agentguard-daemon.exe");
    exe
}

#[cfg(windows)]
pub(crate) fn is_admin() -> bool {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::CheckTokenMembership;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::Security::TOKEN_QUERY;

    let mut token = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
    if ok == 0 {
        return false;
    }

    let wide: Vec<u16> = OsStr::new("S-1-5-32-544")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut admin_sid: windows_sys::Win32::Security::PSID = std::ptr::null_mut();
    let ok = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut admin_sid) };
    if ok == 0 {
        return false;
    }

    let mut is_member: i32 = 0;
    let ok = unsafe { CheckTokenMembership(token, admin_sid, &mut is_member) };
    unsafe { LocalFree(admin_sid as *mut _) };

    ok != 0 && is_member != 0
}

#[cfg(not(windows))]
pub(crate) fn is_admin() -> bool {
    false
}

