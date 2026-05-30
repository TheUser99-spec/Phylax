//! IPC daemon <-> CLI via Named Pipe (Windows) / Unix Domain Socket.
//!
//! Protocolo de mensajes:
//!   - RegisterProject / UnregisterProject
//!   - ValidateProject / CheckFileAccess
//!   - GetStatus / Shutdown / ReloadPolicy / AskResponse

#![cfg_attr(windows, allow(unsafe_code))]

pub mod client;
pub mod protocol;
pub mod server;

pub use client::IpcClient;
pub use protocol::{
    pipe_name, ActiveAgent, AgentRuleInfo, AgentRulesListData, AgentStat, AuditEventView,
    DaemonStatus, DashboardStats, FileCheckResult, GlobalRuleInfo, GlobalRulesListData, IpcRequest,
    IpcResponse, PolicyData, PolicySummary, ProjectInfo, ProtectionPathHealth,
    ProtectionReportData, StreamingEvent, ValidationResult,
};
pub use server::{IpcServer, RequestHandler};
