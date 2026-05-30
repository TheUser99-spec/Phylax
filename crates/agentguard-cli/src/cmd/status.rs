use agentguard_core::{GuardError, GuardResult};
use agentguard_ipc::IpcClient;

pub async fn run() -> GuardResult<()> {
    let status = IpcClient::new().get_status().await.map_err(|e| match e {
        GuardError::IpcError(_) => e,
        _ => GuardError::DaemonNotRunning,
    })?;

    println!("AgentGuard v{}", status.version);
    println!();

    if status.projects.is_empty() {
        println!("  Sin proyectos registrados.");
        println!("  Ejecuta agentguard init en un proyecto.");
    } else {
        println!("Proyectos vigilados ({}):", status.projects.len());
        for p in &status.projects {
            println!(
                "  + {}  [deny:{} ask:{} write:{} read:{}]",
                p.path.display(),
                p.deny_count,
                p.ask_count,
                p.write_count,
                p.read_count,
            );
        }
    }

    println!();

    if status.active_agents.is_empty() {
        println!("  Sin agentes activos en este momento.");
    } else {
        println!("Agentes activos ({}):", status.active_agents.len());
        for a in &status.active_agents {
            println!(
                "  * {} (PID {})  {:?}  {}",
                a.image_name,
                a.pid,
                a.label,
                a.workspace
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "--".into()),
            );
        }
    }

    println!();
    println!(
        "  Eventos hoy: {}  Bloqueos: {}",
        status.events_today, status.blocks_today,
    );

    Ok(())
}
