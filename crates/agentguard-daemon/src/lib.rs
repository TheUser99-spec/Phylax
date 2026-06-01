//! Phylax Daemon library (crate name agentguard-daemon retained for backward compatibility).
//!
//! Orchestrates: probe + policy + enforce + notify + audit.
//! IPC server for CLI + watcher for hot-reload of phylax.toml.
//! File watcher to protect new files in workspaces.

#![allow(unsafe_code)]

mod file_watcher;
mod handler;
mod orchestrator;
mod watcher;

use agentguard_ipc::{IpcResponse, IpcServer};
use agentguard_probe::ProcessPoller;
use orchestrator::DaemonState;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

#[cfg(windows)]
struct SingleInstanceGuard {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl SingleInstanceGuard {
    fn acquire() -> Result<Self, String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows_sys::Win32::System::Threading::CreateMutexW;

        let name = std::ffi::OsStr::new("Global\\Phylax.Daemon.Singleton")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();

        let handle = unsafe { CreateMutexW(std::ptr::null_mut(), 0, name.as_ptr()) };
        if handle.is_null() {
            return Err("CreateMutexW failed".into());
        }

        let last = unsafe { GetLastError() };
        if last == ERROR_ALREADY_EXISTS {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
            return Err("another daemon instance is already running".into());
        }

        Ok(Self { handle })
    }
}

#[cfg(windows)]
impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
        }
    }
}

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Run the Phylax daemon. Blocks until shutdown is requested.
/// On Windows this acquires a singleton mutex to prevent double-start.
pub async fn run_daemon() {
    #[cfg(windows)]
    let _singleton = match SingleInstanceGuard::acquire() {
        Ok(g) => g,
        Err(e) => {
            eprintln!("[daemon] Singleton lock failed: {e}");
            std::process::exit(1);
        }
    };

    let db_path = agentguard_store::Store::default_path();
    eprintln!("[daemon] DB path: {}", db_path.display());

    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let (watcher_shutdown_tx, watcher_shutdown_rx) = mpsc::channel(1);
    let (file_watcher_shutdown_tx, file_watcher_shutdown_rx) = mpsc::channel(1);

    let (event_tx, _event_rx) = broadcast::channel::<IpcResponse>(1024);

    eprintln!("[daemon] Initialising DaemonState...");
    let state = match DaemonState::new(&db_path, shutdown_tx.clone(), event_tx.clone()) {
        Ok(s) => {
            eprintln!("[daemon] DaemonState ready.");
            s
        }
        Err(e) => {
            eprintln!("Failed to initialise daemon: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(state);

    let ipc_state = Arc::clone(&state);
    let handler: agentguard_ipc::RequestHandler =
        Arc::new(move |req| handler::handle(Arc::clone(&ipc_state), req));

    let server = IpcServer::with_events(handler, event_tx);

    let watcher_state = Arc::clone(&state);
    let file_watcher_state = Arc::clone(&state);

    let poller = ProcessPoller::new(state.tracker.classifier.clone(), state.tracker.clone());
    let (poller_tx, mut poller_rx) = mpsc::channel(64);
    let (poller_stop_tx, poller_stop_rx) = mpsc::channel(1);

    let poller_task = tokio::spawn(poller.run(poller_tx, poller_stop_rx, 2000));

    let event_state = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(event) = poller_rx.recv().await {
            if SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
                break;
            }
            event_state.on_process_event(&event);
        }
    });

    println!("Phylax Daemon v{} started", env!("CARGO_PKG_VERSION"));
    println!("Agent detection: ACTIVE (2000ms polling)");
    println!("File watcher: ACTIVE (5000ms polling)");

    tokio::select! {
        result = server.run(shutdown_rx) => {
            if let Err(e) = result {
                eprintln!("IPC server error: {e}");
            }
        }
        result = watcher::run_watcher(watcher_state, watcher_shutdown_rx) => {
            if let Err(e) = result {
                eprintln!("Watcher error: {e}");
            }
        }
        result = file_watcher::run_file_watcher(file_watcher_state, file_watcher_shutdown_rx) => {
            if let Err(e) = result {
                eprintln!("File watcher error: {e}");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nCtrl+C received, shutting down...");
            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        }
    }

    eprintln!("[daemon] Releasing all project protections...");
    state.release_all_projects();
    eprintln!("[daemon] All ACEs released.");

    let _ = shutdown_tx.try_send(());
    drop(poller_stop_tx);
    drop(watcher_shutdown_tx);
    drop(file_watcher_shutdown_tx);

    let _ = poller_task.await;

    println!("Phylax Daemon stopped.");
}

pub fn is_daemon_running() -> bool {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    if let Ok(rt) = rt {
        rt.block_on(async {
            agentguard_ipc::IpcClient::new().get_status().await.is_ok()
        })
    } else {
        false
    }
}

pub fn kill_daemon_by_name() {
    #[cfg(windows)]
    {
        // Try graceful shutdown first
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        if let Ok(rt) = rt {
            let _ = rt.block_on(async {
                agentguard_ipc::IpcClient::new().shutdown().await
            });
            std::thread::sleep(std::time::Duration::from_millis(500));
        }

        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/IM", "phylax-daemon.exe"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}
