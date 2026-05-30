use agentguard_core::GuardResult;
use agentguard_ipc::IpcClient;

pub async fn run(no_create: bool, allow_unhealthy: bool) -> GuardResult<()> {
    let cwd = std::env::current_dir().map_err(agentguard_core::GuardError::Io)?;

    let toml_path = cwd.join("agentguard.toml");
    if !no_create && !toml_path.exists() {
        eprint!("  Scanning project");
        let manifest = agentguard_manifest::auto_detect(&cwd);
        eprintln!("\r  Scanning project... done.");
        let content = manifest.to_toml_string();

        let lang = agentguard_manifest::detect_language(&cwd);
        let name = manifest.project.name.as_deref().unwrap_or("my-project");
        println!("  Language: {}", lang.as_str());
        println!("  Project:  {}", name);
        println!(
            "  Patterns: deny={}, ask={}, write={}, delete={}, read={}",
            manifest.deny.files.len(),
            manifest.ask.files.len(),
            manifest.write.files.len(),
            manifest.delete.files.len(),
            manifest.read.files.len(),
        );

        std::fs::write(&toml_path, content).map_err(agentguard_core::GuardError::Io)?;
        println!();
        println!("+ Creado agentguard.toml (auto-detected)");
    } else if toml_path.exists() {
        println!("- agentguard.toml already exists, skipping creation");
    }

    match ensure_daemon_running().await {
        Ok(()) => {}
        Err(e) => {
            println!("- Daemon not available: {e}");
            println!("  Start it manually: cargo run -p agentguard-daemon");
            println!("  Or: agentguard daemon start");
            return Ok(());
        }
    }

    IpcClient::new().register_project(cwd.clone()).await?;

    println!("+ Proyecto registrado: {}", cwd.display());
    println!("+ AgentGuard activo -- los agentes seran vigilados en este workspace");
    match IpcClient::new().verify_protection(cwd.clone()).await {
        Ok(report) => {
            if report.unhealthy_paths.is_empty() {
                println!(
                    "+ Protection audit OK: full={}/{} effective={}/{} deny paths",
                    report.healthy_paths,
                    report.total_deny_paths,
                    report.effective_deny_paths,
                    report.total_deny_paths
                );
            } else {
                println!(
                    "! Protection audit WARNING: {}/{} deny paths unhealthy (effective deny: {}/{})",
                    report.unhealthy_paths.len(),
                    report.total_deny_paths,
                    report.effective_deny_paths,
                    report.total_deny_paths
                );
                println!("  Run `agentguard project verify` for detailed path diagnostics.");
                if !allow_unhealthy {
                    return Err(agentguard_core::GuardError::IpcError(
                        "init aborted: protection audit found unhealthy deny paths. \
Use `agentguard project verify` to inspect and fix, or re-run with `--allow-unhealthy` (insecure)."
                            .to_string(),
                    ));
                }
            }
        }
        Err(e) => {
            println!("! Could not run post-init protection audit: {e}");
            println!("  Run `agentguard project verify` once daemon is ready.");
        }
    }
    println!();
    println!("  Edita agentguard.toml para personalizar los permisos.");
    println!("  El daemon recargara automaticamente cuando guardes cambios.");
    println!();
    println!("  agentguard status              -> ver estado");
    println!("  agentguard project check ...   -> dry-run de una operacion");

    Ok(())
}

async fn ensure_daemon_running() -> GuardResult<()> {
    if IpcClient::new().get_status().await.is_ok() {
        return Ok(());
    }
    super::daemon::start().await
}
