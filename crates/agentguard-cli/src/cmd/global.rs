use agentguard_core::GuardResult;
use agentguard_ipc::{IpcClient, IpcRequest};

pub async fn add(bucket: String, pattern: String) -> GuardResult<()> {
    let client = IpcClient::new();
    match client
        .send(IpcRequest::AddGlobalRule {
            bucket: bucket.clone(),
            pattern: pattern.clone(),
        })
        .await?
    {
        agentguard_ipc::IpcResponse::Ok => {
            println!("+ Global rule added: [{bucket}] {pattern}");
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
    match client.send(IpcRequest::RemoveGlobalRule { id }).await? {
        agentguard_ipc::IpcResponse::Ok => {
            println!("+ Global rule {id} removed");
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

pub async fn list() -> GuardResult<()> {
    let client = IpcClient::new();
    match client.send(IpcRequest::ListGlobalRules).await? {
        agentguard_ipc::IpcResponse::GlobalRulesList(data) => {
            let rules = data.rules;
            if rules.is_empty() {
                println!("  No global rules defined.");
                println!("  Add one: phylax global add deny \"C:\\Users\\*\\.ssh\\**\"");
            } else {
                println!("Global rules ({}):", rules.len());
                for r in &rules {
                    println!(
                        "  [{id:>3}] {bucket:<8} {pattern}",
                        id = r.id,
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
