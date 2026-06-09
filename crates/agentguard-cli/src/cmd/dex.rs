use agentguard_core::GuardResult;
use agentguard_ipc::IpcClient;

pub async fn status() -> GuardResult<()> {
    let client = IpcClient::new();
    let response = client.send(agentguard_ipc::IpcRequest::CheckDexStatus).await?;
    match response {
        agentguard_ipc::IpcResponse::DexStatus(data) => {
            println!("\n  === DEX — Data Exfiltration Prevention ===\n");
            println!("  Total connections    : {}", data.total_connections);
            println!("  Suspicious connections: {}", data.suspicious_connections);
            println!("  Agents with network  : {}", data.active_agents_online);
            println!("  USB devices detected : {}", data.usb_devices);
            println!();

            let risk_icon = match data.risk_level.as_str() {
                "critical" => "\x1b[31mCRITICAL\x1b[0m",
                "warning" => "\x1b[33mWARNING\x1b[0m",
                _ => "\x1b[32mSAFE\x1b[0m",
            };
            println!("  Risk Level: {risk_icon}");
            println!();

            if let Ok(report) = serde_json::from_str::<serde_json::Value>(&data.report_json) {
                if let Some(agents) = report["active_agents_online"].as_array() {
                    for agent in agents {
                        let pid = agent["pid"].as_u64().unwrap_or(0);
                        let name = agent["image_name"].as_str().unwrap_or("?");
                        let has_ext = agent["has_external_connection"].as_bool().unwrap_or(false);
                        let icon = if has_ext { "\x1b[31m[EXT]\x1b[0m" } else { "\x1b[32m[LOCAL]\x1b[0m" };

                        println!("  {icon} {name} (PID {pid})");
                        if let Some(factors) = agent["risk_factors"].as_array() {
                            for f in factors {
                                println!("       \x1b[33m!\x1b[0m {}", f.as_str().unwrap_or("?"));
                            }
                        }
                        if let Some(conns) = agent["connections"].as_array() {
                            for c in conns.iter().take(3) {
                                let remote = c["remote_addr"].as_str().unwrap_or("?");
                                let rport = c["remote_port"].as_u64().unwrap_or(0);
                                let proto = c["protocol"].as_str().unwrap_or("?");
                                println!("         {} -> {}:{} ({})", proto, remote, rport, c["state"].as_str().unwrap_or("?"));
                            }
                            if conns.len() > 3 {
                                println!("         ... and {} more connections", conns.len() - 3);
                            }
                        }
                        println!();
                    }
                }
                if let Some(usbs) = report["usb_devices"].as_array() {
                    if !usbs.is_empty() {
                        println!("  --- USB Devices ---");
                        for u in usbs {
                            let letter = u["drive_letter"].as_str().unwrap_or("?");
                            let vol = u["volume_name"].as_str().unwrap_or("?");
                            println!("  {}: {} ({})", letter, vol, if u["is_removable"].as_bool().unwrap_or(false) { "removable" } else { "fixed" });
                        }
                        println!();
                    }
                }
            }

            Ok(())
        }
        agentguard_ipc::IpcResponse::Error { message } => Err(agentguard_core::GuardError::IpcError(message)),
        other => Err(agentguard_core::GuardError::IpcError(format!("unexpected: {other:?}"))),
    }
}
