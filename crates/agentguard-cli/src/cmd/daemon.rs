use agentguard_core::{GuardError, GuardResult};
use agentguard_ipc::IpcClient;
use std::time::Duration;

pub async fn start() -> GuardResult<()> {
    #[cfg(windows)]
    {
        // Fast check: if daemon process exists, try IPC to confirm it's responsive
        if daemon_process_count() > 0 {
            if let Ok(s) = IpcClient::new().get_status().await {
                println!(
                    "+ Daemon already running (v{}, {} project(s), {} agent(s))",
                    s.version,
                    s.projects.len(),
                    s.active_agents.len()
                );
                return Ok(());
            }
            // Process exists but IPC is dead — refuse to spawn second instance
            return Err(GuardError::IpcError(
                "daemon process already exists but IPC is inaccessible; refusing to spawn a second instance. Run `phylax daemon restart` from the same privilege/session.".into(),
            ));
        }

        let exe = daemon_exe_path();
        if !exe.exists() {
            return Err(GuardError::IpcError(format!(
                "Daemon binary not found at {:?}. Build it first: cargo build -p phylax-daemon",
                exe
            )));
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            std::process::Command::new(&exe)
                .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
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
        eprint!("  Waiting for daemon");
        for _ in 0..30 {
            eprint!(".");
            tokio::time::sleep(Duration::from_millis(100)).await;
            let ok = tokio::time::timeout(Duration::from_millis(500), client.get_status())
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);

            if ok {
                eprintln!(" ready");
                return Ok(());
            }
        }
        eprintln!();
        Err(GuardError::IpcError(
            "Daemon not responding after 3s — check daemon output for errors".into(),
        ))
    }

    #[cfg(not(windows))]
    {
        println!("* Daemon only available on Windows.");
        println!("  Dev: cargo run -p phylax-daemon");
        Ok(())
    }
}

pub async fn stop() -> GuardResult<()> {
    // Send shutdown — daemon releases ACEs before responding
    match IpcClient::new().shutdown().await {
        Ok(()) => {}
        Err(_) => {
            // IPC failed, daemon may be dead or unresponsive — force kill
            force_kill_all_daemon_processes();
        }
    }

    // Wait up to 2s for process to exit naturally (ACEs already released)
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if daemon_process_count() == 0 {
            println!("+ Daemon stopped");
            return Ok(());
        }
    }

    // Still running after ACE release — force kill (safe, ACEs already gone)
    force_kill_all_daemon_processes();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let remaining = daemon_process_count();
    if remaining == 0 {
        println!("+ Daemon stopped (forced)");
        Ok(())
    } else {
        Err(GuardError::IpcError(format!(
            "Failed to kill {remaining} daemon process(es). Run as Administrator: phylax daemon emergency-stop"
        )))
    }
}

pub async fn restart() -> GuardResult<()> {
    let _ = IpcClient::new().shutdown().await;
    // Wait up to 3s for graceful exit
    for _ in 0..15 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if daemon_process_count() == 0 { break; }
    }
    kill_daemon_process();
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if daemon_process_count() == 0 { break; }
    }
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
    force_kill_all_daemon_processes();
}

#[cfg(windows)]
fn force_kill_all_daemon_processes() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if handle == std::ptr::null_mut()
        || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
    {
        // Fallback to taskkill
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/T", "/IM", "phylax-daemon.exe"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output();
        return;
    }

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };

    let mut ok = unsafe { Process32FirstW(handle, &mut entry) };
    while ok != 0 {
        let name = OsString::from_wide(trim_null(&entry.szExeFile))
            .to_string_lossy()
            .to_ascii_lowercase();
        if name == "phylax-daemon.exe" {
            let pid = entry.th32ProcessID;
            let ph = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
            if !ph.is_null() {
                unsafe { TerminateProcess(ph, 1); }
                unsafe { CloseHandle(ph); }
            }
        }
        ok = unsafe { Process32NextW(handle, &mut entry) };
    }

    unsafe { CloseHandle(handle) };
}

#[cfg(not(windows))]
fn force_kill_all_daemon_processes() {
    let _ = std::process::Command::new("pkill").arg("-f").arg("phylax-daemon").output();
}

#[cfg(windows)]
fn kill_daemon_process_blocking(kill_tree: bool) -> GuardResult<()> {
    let mut cmd = std::process::Command::new("taskkill");
    cmd.arg("/F").arg("/IM").arg("phylax-daemon.exe");
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
  $p = Start-Process -FilePath 'taskkill.exe' -Verb RunAs -ArgumentList @('/F','/T','/IM','phylax-daemon.exe') -PassThru -Wait
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
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    let handle = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if handle == std::ptr::null_mut()
        || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
    {
        return 0;
    }

    let mut count = 0usize;
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..unsafe { std::mem::zeroed() }
    };

    let mut ok = unsafe { Process32FirstW(handle, &mut entry) };
    while ok != 0 {
        let name = OsString::from_wide(trim_null(&entry.szExeFile))
            .to_string_lossy()
            .to_ascii_lowercase();
        if name == "phylax-daemon.exe" {
            count += 1;
        }
        ok = unsafe { Process32NextW(handle, &mut entry) };
    }

    unsafe { CloseHandle(handle) };
    count
}

#[cfg(windows)]
fn trim_null(wide: &[u16]) -> &[u16] {
    match wide.iter().position(|&c| c == 0) {
        Some(pos) => &wide[..pos],
        None => wide,
    }
}

#[cfg(windows)]
fn daemon_exe_path() -> std::path::PathBuf {
    let mut exe = std::env::current_exe().unwrap_or_default();
    exe.set_file_name("phylax-daemon.exe");
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

