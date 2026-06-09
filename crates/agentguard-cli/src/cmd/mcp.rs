use agentguard_core::GuardResult;
use agentguard_ipc::{IpcClient, IpcRequest};

pub async fn discover() -> GuardResult<()> {
    let client = IpcClient::new();
    let response = client.send(IpcRequest::DiscoverMcpServers).await?;
    match response {
        agentguard_ipc::IpcResponse::McpDiscovery(data) => {
            println!("\n  === MCP Server Discovery ===\n");
            println!("  Config files scanned : {}", data.config_files_scanned);
            println!("  Config files found   : {}", data.config_files_found);
            println!("  MCP servers detected : {}", data.servers_found);
            println!();

            if data.servers_found > 0 {
                let servers: Vec<serde_json::Value> = serde_json::from_str(&data.servers_json).unwrap_or_default();
                for s in &servers {
                    let name = s.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let command = s.get("command").and_then(|v| v.as_str()).unwrap_or("?");
                    let host = s.get("agent_host").and_then(|v| v.as_str()).unwrap_or("?");
                    let risk = s.get("risk_level").and_then(|v| v.as_str()).unwrap_or("unknown");
                    let transport = s.get("transport").and_then(|v| v.as_str()).unwrap_or("?");
                    let config = s.get("config_path").and_then(|v| v.as_str()).unwrap_or("?");

                    let risk_icon = match risk {
                        "malicious" => "\x1b[31m\u{26A0}\x1b[0m",
                        "suspicious" => "\x1b[33m?\x1b[0m",
                        "verified" => "\x1b[32m\u{2713}\x1b[0m",
                        _ => "\x1b[90m~\x1b[0m",
                    };

                    println!("  {risk_icon} {name} [{host}]");
                    println!("       command  : {command}");
                    println!("       transport: {transport}");
                    println!("       risk     : {risk}");
                    println!("       config   : {config}");
                    println!();
                }
            } else {
                println!("  No MCP servers found on this system.");
                println!();
            }
            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => Err(agentguard_core::GuardError::IpcError(message)),
        other => Err(agentguard_core::GuardError::IpcError(format!("unexpected: {other:?}"))),
    }
}

pub async fn add_rule(name: String, action: String) -> GuardResult<()> {
    let client = IpcClient::new();
    match client.send(IpcRequest::AddMcpRule { server_name: name.clone(), action: action.clone() }).await? {
        agentguard_ipc::IpcResponse::Ok => {
            println!("+ MCP rule added: [{action}] {name}");
            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => Err(agentguard_core::GuardError::IpcError(message)),
        other => Err(agentguard_core::GuardError::IpcError(format!("unexpected: {other:?}"))),
    }
}

pub async fn remove_rule(id: i64) -> GuardResult<()> {
    let client = IpcClient::new();
    match client.send(IpcRequest::RemoveMcpRule { id }).await? {
        agentguard_ipc::IpcResponse::Ok => {
            println!("+ MCP rule removed: {id}");
            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => Err(agentguard_core::GuardError::IpcError(message)),
        other => Err(agentguard_core::GuardError::IpcError(format!("unexpected: {other:?}"))),
    }
}

pub async fn list_rules() -> GuardResult<()> {
    let client = IpcClient::new();
    let response = client.send(IpcRequest::GetMcpRules).await?;
    match response {
        agentguard_ipc::IpcResponse::McpRulesList(data) => {
            let rules: Vec<serde_json::Value> = serde_json::from_str(&data.rules_json).unwrap_or_default();
            if rules.is_empty() {
                println!("\n  No MCP-specific rules defined.\n");
            } else {
                println!("\n  === MCP Governance Rules ===\n");
                for r in &rules {
                    let id = r.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                    let bucket = r.get("bucket").and_then(|v| v.as_str()).unwrap_or("?");
                    let pattern = r.get("pattern").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("  [{id}] {bucket:>8}  {pattern}");
                }
                println!();
            }
            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => Err(agentguard_core::GuardError::IpcError(message)),
        other => Err(agentguard_core::GuardError::IpcError(format!("unexpected: {other:?}"))),
    }
}
