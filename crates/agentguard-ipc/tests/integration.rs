#![allow(clippy::unwrap_used, clippy::expect_used)]

use agentguard_core::{AgentLabel, PolicyDecision};
use agentguard_ipc::{
    ActiveAgent, DaemonStatus, FileCheckResult, IpcClient, IpcRequest, IpcResponse, IpcServer,
    PolicySummary, ValidationResult,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

use std::sync::atomic::AtomicU64;

static PIPE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_pipe() -> String {
    let id = PIPE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    #[cfg(windows)]
    {
        format!("\\\\.\\pipe\\phylax-test-{id}")
    }
    #[cfg(not(windows))]
    {
        format!("/tmp/phylax-test-{id}.sock")
    }
}

// ─── Helpers to build test data ──────────────────────────────────────────

fn test_status() -> DaemonStatus {
    DaemonStatus {
        running: true,
        version: "0.1.0".into(),
        recent_events: vec![],
        projects: vec![],
        active_agents: vec![ActiveAgent {
            pid: 42,
            image_name: "claude.exe".into(),
            label: AgentLabel::Definite,
            workspace: Some(PathBuf::from("/test")),
            started_at: 1700000000,
        }],
        events_today: 100,
        blocks_today: 10,
    }
}

fn test_validation() -> ValidationResult {
    ValidationResult {
        valid: true,
        errors: vec![],
        warnings: vec![],
        summary: PolicySummary {
            deny_patterns: 3,
            ask_patterns: 1,
            write_patterns: 2,
            delete_patterns: 0,
            read_patterns: 5,
            full_patterns: 0,
            default_mode: "conservative".into(),
        },
    }
}

fn test_file_check() -> FileCheckResult {
    FileCheckResult {
        path: PathBuf::from("/test/.env"),
        op: "read".into(),
        decision: PolicyDecision::Deny,
        source: "project".into(),
        reason: "deny bucket matches .env".into(),
    }
}

// ─── Integration tests ───────────────────────────────────────────────────

#[tokio::test]
async fn server_responds_to_single_request() {
    let pipe = unique_pipe();

    let handler: agentguard_ipc::RequestHandler = Arc::new(|req| match req {
        IpcRequest::GetStatus => IpcResponse::Status(test_status()),
        _ => IpcResponse::Error {
            message: "unexpected".into(),
        },
    });

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    // Start server in background
    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    // Give server time to bind
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Client connects and sends request
    let client = IpcClient::with_pipe(pipe);
    let result = client.get_status().await;

    // Shutdown server
    let _ = shutdown_tx.send(()).await;

    let status = result.expect("get_status should succeed");
    assert!(status.running);
    assert_eq!(status.events_today, 100);
    assert_eq!(status.active_agents.len(), 1);
    assert_eq!(status.active_agents[0].pid, 42);

    // Wait for server to stop
    let _ = server_handle.await;
}

#[tokio::test]
async fn server_handles_multiple_requests_on_one_connection() {
    let pipe = unique_pipe();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = Arc::clone(&counter);

    let handler: agentguard_ipc::RequestHandler = Arc::new(move |req| match req {
        IpcRequest::GetStatus => {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            IpcResponse::Status(test_status())
        }
        _ => IpcResponse::Error {
            message: "unexpected".into(),
        },
    });

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = IpcClient::with_pipe(pipe);

    // Send 3 requests on the same connection
    for _ in 0..3 {
        client.get_status().await.expect("get_status failed");
    }

    let _ = shutdown_tx.send(()).await;
    let _ = server_handle.await;

    assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 3);
}

#[tokio::test]
async fn server_responds_with_error() {
    let pipe = unique_pipe();

    let handler: agentguard_ipc::RequestHandler = Arc::new(|_req| IpcResponse::Error {
        message: "not found".into(),
    });

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = IpcClient::with_pipe(pipe);
    let result = client.get_status().await;

    let _ = shutdown_tx.send(()).await;
    let _ = server_handle.await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn server_shutdown_cleans_up() {
    let pipe = unique_pipe();

    let handler: agentguard_ipc::RequestHandler = Arc::new(|_req| IpcResponse::Ok);

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Send shutdown signal
    shutdown_tx.send(()).await.expect("send shutdown");

    // Server should stop within timeout
    tokio::time::timeout(std::time::Duration::from_secs(3), server_handle)
        .await
        .expect("server did not stop in time")
        .expect("server task panicked");

    // Clean up socket file on Unix
    #[cfg(not(windows))]
    {
        let _ = std::fs::remove_file(&pipe);
    }
}

#[tokio::test]
async fn validate_project_roundtrip() {
    let pipe = unique_pipe();

    let handler: agentguard_ipc::RequestHandler = Arc::new(|req| match req {
        IpcRequest::ValidateProject { .. } => IpcResponse::ProjectValidation(test_validation()),
        _ => IpcResponse::Error {
            message: "unexpected".into(),
        },
    });

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = IpcClient::with_pipe(pipe);
    let result = client
        .validate_project(PathBuf::from("/test"))
        .await
        .expect("validate_project should succeed");

    let _ = shutdown_tx.send(()).await;
    let _ = server_handle.await;

    assert!(result.valid);
    assert_eq!(result.summary.deny_patterns, 3);
    assert_eq!(result.summary.default_mode, "conservative");
}

#[tokio::test]
async fn check_file_access_roundtrip() {
    let pipe = unique_pipe();

    let handler: agentguard_ipc::RequestHandler = Arc::new(|req| match req {
        IpcRequest::CheckFileAccess { .. } => IpcResponse::FileCheck(test_file_check()),
        _ => IpcResponse::Error {
            message: "unexpected".into(),
        },
    });

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = IpcClient::with_pipe(pipe);
    let result = client
        .check_file(PathBuf::from("/test/.env"), "read".into(), Some("cursor.exe".into()))
        .await
        .expect("check_file should succeed");

    let _ = shutdown_tx.send(()).await;
    let _ = server_handle.await;

    assert!(matches!(result.decision, PolicyDecision::Deny));
    assert_eq!(result.source, "project");
}

#[tokio::test]
async fn register_unregister_roundtrip() {
    let pipe = unique_pipe();
    let registered = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let reg = Arc::clone(&registered);
    let handler: agentguard_ipc::RequestHandler = Arc::new(move |req| match req {
        IpcRequest::RegisterProject { .. } => {
            reg.store(true, std::sync::atomic::Ordering::SeqCst);
            IpcResponse::Ok
        }
        IpcRequest::UnregisterProject { .. } => {
            reg.store(false, std::sync::atomic::Ordering::SeqCst);
            IpcResponse::Ok
        }
        _ => IpcResponse::Error {
            message: "unexpected".into(),
        },
    });

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = IpcClient::with_pipe(pipe);

    client
        .register_project(PathBuf::from("/test"))
        .await
        .expect("register should succeed");
    assert!(registered.load(std::sync::atomic::Ordering::SeqCst));

    client
        .unregister_project(PathBuf::from("/test"))
        .await
        .expect("unregister should succeed");
    assert!(!registered.load(std::sync::atomic::Ordering::SeqCst));

    let _ = shutdown_tx.send(()).await;
    let _ = server_handle.await;
}

#[tokio::test]
async fn shutdown_tolerates_no_server() {
    // shutdown() should not panic or return error when server is not running
    let client = IpcClient::with_pipe(unique_pipe());
    let result = client.shutdown().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn client_timeout_when_no_server() {
    // Client should timeout after 5s when no server is running
    let client = IpcClient::with_pipe(unique_pipe());
    let result = client.get_status().await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("timeout") || err.to_string().contains("daemon"));
}

#[tokio::test]
async fn unexpected_response_returns_error() {
    let pipe = unique_pipe();

    let handler: agentguard_ipc::RequestHandler =
        Arc::new(|_req| IpcResponse::FileCheck(test_file_check()));

    let server = IpcServer::with_pipe(handler, pipe.clone());
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

    let server_handle = tokio::spawn(async move {
        let _ = server.run(shutdown_rx).await;
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let client = IpcClient::with_pipe(pipe);
    // get_status expects IpcResponse::Status, but server returns FileCheck
    let result = client.get_status().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unexpected"));

    let _ = shutdown_tx.send(()).await;
    let _ = server_handle.await;
}
