use agentguard_core::GuardResult;
use agentguard_ipc::{IpcClient, IpcRequest};

pub async fn add(agent_image: String, bucket: String, pattern: String) -> GuardResult<()> {
    let client = IpcClient::new();
    match client
        .send(IpcRequest::AddAgentRule {
            agent_image: agent_image.clone(),
            bucket: bucket.clone(),
            pattern: pattern.clone(),
        })
        .await?
    {
        agentguard_ipc::IpcResponse::Ok => {
            println!("+ Agent rule added: [{agent_image}] [{bucket}] {pattern}");
            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => {
            Err(agentguard_core::GuardError::IpcError(message))
        }
        other => Err(agentguard_core::GuardError::IpcError(format!(
            "unexpected response: {other:?}"
        ))),
    }
}

pub async fn remove(id: i64) -> GuardResult<()> {
    let client = IpcClient::new();
    match client.send(IpcRequest::RemoveAgentRule { id }).await? {
        agentguard_ipc::IpcResponse::Ok => {
            println!("+ Agent rule {id} removed");
            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => {
            Err(agentguard_core::GuardError::IpcError(message))
        }
        other => Err(agentguard_core::GuardError::IpcError(format!(
            "unexpected response: {other:?}"
        ))),
    }
}

pub async fn list(image: Option<String>) -> GuardResult<()> {
    let client = IpcClient::new();
    match client
        .send(IpcRequest::ListAgentRules {
            agent_image: image.clone(),
        })
        .await?
    {
        agentguard_ipc::IpcResponse::AgentRulesList(data) => {
            let rules = data.rules;
            if rules.is_empty() {
                if let Some(img) = image {
                    println!("  No agent rules for '{img}'.");
                } else {
                    println!("  No per-agent rules defined.");
                    println!("  Add one: agentguard agent add cursor.exe deny \"*.env\"");
                }
            } else {
                let label = if let Some(ref img) = image {
                    format!("Agent rules for '{img}'")
                } else {
                    "Agent rules".to_string()
                };
                println!("{} ({}):", label, rules.len());
                for r in &rules {
                    println!(
                        "  [{id:>3}] {image:<20} [{bucket:<6}] {pattern}",
                        id = r.id,
                        image = r.agent_image,
                        bucket = r.bucket,
                        pattern = r.pattern,
                    );
                }
            }
            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => {
            Err(agentguard_core::GuardError::IpcError(message))
        }
        other => Err(agentguard_core::GuardError::IpcError(format!(
            "unexpected response: {other:?}"
        ))),
    }
}
