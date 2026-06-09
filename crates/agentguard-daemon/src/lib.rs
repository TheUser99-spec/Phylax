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
    let (poller_tx, _poller_rx) = mpsc::channel(64);
    let (poller_stop_tx, poller_stop_rx) = mpsc::channel(1);

    let poller_task = tokio::spawn(poller.run(poller_tx.clone(), poller_stop_rx, 2000));

    let etw_tx = poller_tx.clone();
    let (etw_stop_tx, etw_stop_rx) = mpsc::channel(1);
    let etw_task = tokio::spawn(agentguard_probe::run_etw_notifier(etw_tx, etw_stop_rx));

    let cloud_store = state.store.clone();
    let (cloud_stop_tx, _cloud_stop_rx) = mpsc::channel::<()>(1);
    let cloud_stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cloud_task: Option<tokio::task::JoinHandle<()>> =
        match load_cloud_config() {
            Some(config) if config.enabled => {
                println!("Cloud audit sync: ACTIVE ({} -> {})",
                    config.format.as_deref().unwrap_or("ocsf"), config.endpoint);
                let engine = agentguard_cloud::CloudSyncEngine::new(
                    (&*cloud_store).clone(),
                    config,
                );
                let s = cloud_stopped.clone();
                Some(tokio::spawn(async move {
                    engine.run(s).await;
                }))
            }
            _ => {
                println!("Cloud audit sync: DISABLED (add [audit.cloud] to phylax.toml)");
                None
            }
        };

    let web_store = (&*state.store).clone();
    let web_port: u16 = std::env::var("PHYLAX_WEB_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(1977);
    let _web_task = tokio::spawn(async move {
        let server = agentguard_web::WebServer::new(web_store, web_port);
        server.run().await;
    });

    println!("Phylax Daemon v{} started", env!("CARGO_PKG_VERSION"));
    println!("Agent detection: ACTIVE (ETW real-time + 2000ms polling)");
    println!("File watcher: ACTIVE (5000ms polling)");
    println!("Web Dashboard: http://127.0.0.1:{web_port}");

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
    let release_state = Arc::clone(&state);
    let release_done = tokio::task::spawn_blocking(move || {
        release_state.release_all_projects();
    });
    match tokio::time::timeout(std::time::Duration::from_secs(3), release_done).await {
        Ok(Ok(())) => eprintln!("[daemon] All ACEs released."),
        Ok(Err(e)) => eprintln!("[daemon] WARN: ACE release join error: {e}"),
        Err(_) => eprintln!("[daemon] WARN: ACE release timed out after 3s — files may remain protected until next daemon start"),
    }

    let _ = shutdown_tx.try_send(());
    drop(poller_stop_tx);
    drop(etw_stop_tx);
    cloud_stopped.store(true, Ordering::SeqCst);
    drop(cloud_stop_tx);
    drop(watcher_shutdown_tx);
    drop(file_watcher_shutdown_tx);

    let _ = poller_task.await;
    let _ = etw_task.await;
    if let Some(t) = cloud_task { let _ = t.await; }

    println!("Phylax Daemon stopped.");
}

fn load_cloud_config() -> Option<agentguard_cloud::CloudSinkConfig> {
    let cwd = std::env::current_dir().ok()?;
    let phylax_path = cwd.join("phylax.toml");
    if phylax_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&phylax_path) {
            return agentguard_cloud::CloudSinkConfig::from_phylax_toml(&content);
        }
    }
    None
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
