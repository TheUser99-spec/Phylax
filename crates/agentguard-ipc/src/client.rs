use agentguard_core::{GuardError, GuardResult};
use std::path::PathBuf;
use std::time::Duration;

use crate::protocol::{self, IpcRequest, IpcResponse};

#[derive(Clone)]
pub struct IpcClient {
    pipe: Option<String>,
}

impl Default for IpcClient {
    fn default() -> Self {
        Self::new()
    }
}

impl IpcClient {
    pub fn new() -> Self {
        Self { pipe: None }
    }

    pub fn with_pipe(pipe: String) -> Self {
        Self { pipe: Some(pipe) }
    }

    fn pipe_name(&self) -> String {
        self.pipe
            .clone()
            .unwrap_or_else(|| crate::protocol::pipe_name().to_string())
    }

    pub async fn send(&self, request: IpcRequest) -> GuardResult<IpcResponse> {
        tokio::time::timeout(Duration::from_secs(6), self.send_inner(&request))
            .await
            .map_err(|_| GuardError::IpcError("timeout connecting to daemon (6s)".into()))?
    }

    async fn send_inner(&self, request: &IpcRequest) -> GuardResult<IpcResponse> {
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;
            let pipe_name = self.pipe_name();
            let started = tokio::time::Instant::now();
            let mut pipe = loop {
                match ClientOptions::new().open(&pipe_name) {
                    Ok(pipe) => break pipe,
                    Err(e) if started.elapsed() >= Duration::from_secs(5) => {
                        return Err(GuardError::IpcError(format!(
                            "failed to open daemon pipe {pipe_name}: {e}"
                        )));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            };
            protocol::send(&mut pipe, request).await?;
            protocol::recv(&mut pipe).await
        }

        #[cfg(not(windows))]
        {
            use tokio::net::UnixStream;
            let pipe_name = self.pipe_name();
            let started = tokio::time::Instant::now();
            let mut stream = loop {
                match UnixStream::connect(&pipe_name).await {
                    Ok(stream) => break stream,
                    Err(e) if started.elapsed() >= Duration::from_secs(5) => {
                        return Err(GuardError::IpcError(format!(
                            "failed to open daemon socket {pipe_name}: {e}"
                        )));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            };
            protocol::send(&mut stream, request).await?;
            protocol::recv(&mut stream).await
        }
    }

    pub async fn register_project(&self, path: PathBuf) -> GuardResult<()> {
        match self.send(IpcRequest::RegisterProject { path }).await? {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn unregister_project(&self, path: PathBuf) -> GuardResult<()> {
        match self.send(IpcRequest::UnregisterProject { path }).await? {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn get_status(&self) -> GuardResult<crate::protocol::DaemonStatus> {
        match self.send(IpcRequest::GetStatus).await? {
            IpcResponse::Status(s) => Ok(s),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn validate_project(
        &self,
        path: PathBuf,
    ) -> GuardResult<crate::protocol::ValidationResult> {
        match self.send(IpcRequest::ValidateProject { path }).await? {
            IpcResponse::ProjectValidation(v) => Ok(v),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn check_file(
        &self,
        path: PathBuf,
        op: String,
    ) -> GuardResult<crate::protocol::FileCheckResult> {
        match self.send(IpcRequest::CheckFileAccess { path, op }).await? {
            IpcResponse::FileCheck(r) => Ok(r),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn shutdown(&self) -> GuardResult<()> {
        let _ = self.send(IpcRequest::Shutdown).await;
        Ok(())
    }

    pub async fn enable_protection(&self, path: PathBuf) -> GuardResult<()> {
        match self.send(IpcRequest::EnableProtection { path }).await? {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn disable_protection(&self, path: PathBuf) -> GuardResult<()> {
        match self.send(IpcRequest::DisableProtection { path }).await? {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn verify_protection(
        &self,
        path: PathBuf,
    ) -> GuardResult<crate::protocol::ProtectionReportData> {
        match self.send(IpcRequest::VerifyProtection { path }).await? {
            IpcResponse::ProtectionReport(r) => Ok(r),
            IpcResponse::Error { message } => Err(GuardError::IpcError(message)),
            other => Err(GuardError::IpcError(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn subscribe_events(&self) -> GuardResult<tokio::sync::mpsc::Receiver<IpcResponse>> {
        tokio::time::timeout(Duration::from_secs(6), self.subscribe_inner())
            .await
            .map_err(|_| GuardError::IpcError("timeout subscribing to events (6s)".into()))?
    }

    async fn subscribe_inner(&self) -> GuardResult<tokio::sync::mpsc::Receiver<IpcResponse>> {
        let pipe_name = self.pipe_name();

        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;
            let started = tokio::time::Instant::now();
            let mut pipe = loop {
                match ClientOptions::new().open(&pipe_name) {
                    Ok(pipe) => break pipe,
                    Err(e) if started.elapsed() >= Duration::from_secs(5) => {
                        return Err(GuardError::IpcError(format!(
                            "failed to open daemon pipe {pipe_name}: {e}"
                        )));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            };

            protocol::send(&mut pipe, &IpcRequest::SubscribeEvents).await?;
            match protocol::recv::<IpcResponse>(&mut pipe).await? {
                IpcResponse::Ok => {}
                IpcResponse::Error { message } => {
                    return Err(GuardError::IpcError(message));
                }
                _ => {
                    return Err(GuardError::IpcError(
                        "unexpected response to SubscribeEvents".into(),
                    ));
                }
            }

            let (tx, rx) = tokio::sync::mpsc::channel::<IpcResponse>(128);
            tokio::spawn(async move {
                while let Ok(event) = protocol::recv::<IpcResponse>(&mut pipe).await {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            });

            Ok(rx)
        }

        #[cfg(not(windows))]
        {
            use tokio::net::UnixStream;
            let started = tokio::time::Instant::now();
            let mut stream = loop {
                match UnixStream::connect(&pipe_name).await {
                    Ok(stream) => break stream,
                    Err(e) if started.elapsed() >= Duration::from_secs(5) => {
                        return Err(GuardError::IpcError(format!(
                            "failed to open daemon socket {pipe_name}: {e}"
                        )));
                    }
                    Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            };

            protocol::send(&mut stream, &IpcRequest::SubscribeEvents).await?;
            match protocol::recv::<IpcResponse>(&mut stream).await? {
                IpcResponse::Ok => {}
                IpcResponse::Error { message } => {
                    return Err(GuardError::IpcError(message));
                }
                _ => {
                    return Err(GuardError::IpcError(
                        "unexpected response to SubscribeEvents".into(),
                    ));
                }
            }

            let (tx, rx) = tokio::sync::mpsc::channel::<IpcResponse>(128);
            tokio::spawn(async move {
                while let Ok(event) = protocol::recv::<IpcResponse>(&mut stream).await {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            });

            Ok(rx)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn client_default_is_new() {
        let c = IpcClient::default();
        let c2 = IpcClient::new();
        // Both should have no pipe override
        assert!(c.pipe.is_none());
        assert!(c2.pipe.is_none());
    }

    #[test]
    fn client_with_pipe_stores_override() {
        let c = IpcClient::with_pipe("\\\\.\\pipe\\test".into());
        assert_eq!(c.pipe_name(), "\\\\.\\pipe\\test");
    }

    #[test]
    fn client_new_uses_default_pipe_name() {
        let c = IpcClient::new();
        let name = c.pipe_name();
        assert!(!name.is_empty());
        #[cfg(windows)]
        assert!(name.contains("agentguard"));
        #[cfg(not(windows))]
        assert!(name.contains("agentguard"));
    }
}
