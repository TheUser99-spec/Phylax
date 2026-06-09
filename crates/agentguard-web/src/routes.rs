use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State, Query},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::sync::Arc;

use crate::AppState;

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/status", get(api_status))
        .route("/api/compliance", get(api_compliance))
        .route("/api/events", get(api_events))
        .route("/ws", get(ws_handler))
        .with_state(state)
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<usize>,
}

async fn api_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (total, blocks) = state.store.count_events_today().unwrap_or((0, 0));
    let sessions = state.store.active_sessions().unwrap_or_default();
    let recent = state.store.recent_audit_events(20).unwrap_or_default();

    let events: Vec<serde_json::Value> = recent.iter().map(|e| {
        serde_json::json!({
            "pid": e.agent_pid,
            "label": e.agent_label.as_str(),
            "path": e.file_path.to_string_lossy(),
            "op": e.operation.as_str(),
            "decision": match &e.decision {
                agentguard_core::PolicyDecision::Allow => "allow",
                agentguard_core::PolicyDecision::Deny => "deny",
                agentguard_core::PolicyDecision::Ask { .. } => "ask",
            },
            "source": e.source.as_str(),
            "ts": e.timestamp.timestamp(),
        })
    }).collect();

    Response::builder()
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&serde_json::json!({
            "events_today": total,
            "blocks_today": blocks,
            "active_agents": sessions.len(),
            "agents": sessions.iter().map(|s| serde_json::json!({
                "pid": s.pid,
                "image": s.image_name,
                "label": s.label.as_str(),
                "started": s.started_at.timestamp(),
            })).collect::<Vec<_>>(),
            "recent_events": events,
        })).unwrap())
        .unwrap()
}

async fn api_compliance(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let (total, blocks) = state.store.count_events_today().unwrap_or((0, 0));
    let active = state.store.active_sessions().map(|v| v.len() as u64).unwrap_or(0);

    let engine = agentguard_compliance::ComplianceEngine::with_data(
        agentguard_compliance::AuditCounts {
            total_events: total,
            deny_count: blocks,
            ask_count: 0,
            active_agents: active,
        },
        vec![],
        false,
    );

    let report = engine.evaluate("eu-ai-act");
    let report_json = serde_json::to_value(&report).unwrap_or_default();

    Response::builder()
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&report_json).unwrap())
        .unwrap()
}

async fn api_events(State(state): State<Arc<AppState>>, Query(q): Query<EventsQuery>) -> impl IntoResponse {
    let limit = q.limit.unwrap_or(50).min(5000);
    let events = state.store.recent_audit_events(limit).unwrap_or_default();

    let data: Vec<serde_json::Value> = events.iter().map(|e| {
        serde_json::json!({
            "pid": e.agent_pid,
            "label": e.agent_label.as_str(),
            "path": e.file_path.to_string_lossy(),
            "op": e.operation.as_str(),
            "decision": match &e.decision {
                agentguard_core::PolicyDecision::Allow => "allow",
                agentguard_core::PolicyDecision::Deny => "deny",
                agentguard_core::PolicyDecision::Ask { .. } => "ask",
            },
            "source": e.source.as_str(),
            "ts": e.timestamp.timestamp(),
        })
    }).collect();

    Response::builder()
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(serde_json::to_string(&data).unwrap())
        .unwrap()
}

async fn ws_handler(State(state): State<Arc<AppState>>, ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws(socket, state))
}

async fn handle_ws(socket: WebSocket, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

    let _recv_task = tokio::spawn(async move {
        while let Some(Ok(_msg)) = receiver.next().await {}
    });

    loop {
        interval.tick().await;
        let (total, blocks) = state.store.count_events_today().unwrap_or((0, 0));
        let sessions = state.store.active_sessions().unwrap_or_default();
        let recent = state.store.recent_audit_events(5).unwrap_or_default();

        let events: Vec<serde_json::Value> = recent.iter().map(|e| {
            serde_json::json!({
                "pid": e.agent_pid,
                "label": e.agent_label.as_str(),
                "path": e.file_path.to_string_lossy(),
                "op": e.operation.as_str(),
                "decision": match &e.decision {
                    agentguard_core::PolicyDecision::Allow => "allow",
                    agentguard_core::PolicyDecision::Deny => "deny",
                    agentguard_core::PolicyDecision::Ask { .. } => "ask",
                },
                "source": e.source.as_str(),
                "ts": e.timestamp.timestamp(),
            })
        }).collect();

        let payload = serde_json::json!({
            "type": "tick",
            "events_today": total,
            "blocks_today": blocks,
            "active_agents": sessions.len(),
            "agents": sessions.iter().map(|s| serde_json::json!({
                "pid": s.pid,
                "image": s.image_name,
                "label": s.label.as_str(),
                "started": s.started_at.timestamp(),
            })).collect::<Vec<_>>(),
            "recent_events": events,
        });

        let text = serde_json::to_string(&payload).unwrap_or_default();
        if sender.send(Message::Text(text.into())).await.is_err() {
            break;
        }
    }
}

const DASHBOARD_HTML: &str = include_str!("dashboard.html");
