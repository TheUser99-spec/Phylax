use agentguard_core::GuardResult;
use agentguard_ipc::IpcClient;

pub async fn run(no_create: bool, allow_unhealthy: bool) -> GuardResult<()> {
    let cwd = std::env::current_dir().map_err(agentguard_core::GuardError::Io)?;

    let toml_path = cwd.join("phylax.toml");
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
        println!("+ Created phylax.toml (auto-detected)");
    } else if toml_path.exists() {
        println!("- phylax.toml already exists, skipping creation");
    }

    match ensure_daemon_running().await {
        Ok(()) => {}
        Err(e) => {
            eprintln!();
            eprintln!("! DAEMON UNAVAILABLE: {e}");
            eprintln!("  The daemon is required to register and protect this project.");
            eprintln!("  Start it:  phylax daemon start");
            eprintln!("  Or launch:  phylax run");
            return Err(agentguard_core::GuardError::IpcError(
                "init aborted: daemon is not running. Project was NOT registered. Start the daemon and re-run `phylax init --no-create`.".to_string(),
            ));
        }
    }

    IpcClient::new().register_project(cwd.clone()).await?;

    println!("+ Project registered: {}", cwd.display());
    println!("+ Phylax active -- agents will be monitored in this workspace");
    match IpcClient::new().verify_protection(cwd.clone()).await {
        Ok(report) => {
            if report.total_deny_paths == 0 {
                println!();
                println!("! WARNING: 0 deny paths found in workspace.");
                println!("  Phylax is NOT actively blocking any files right now.");
                println!("  This happens when no files match deny patterns (e.g. .env, *.pem, *.key).");
                println!("  Create a file matching a deny pattern or add targeted patterns in phylax.toml.");
                println!("  Run `phylax project check <file>` to test a specific path.");
            } else if report.unhealthy_paths.is_empty() {
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
                println!("  Run `phylax project verify` for detailed path diagnostics.");
                if !allow_unhealthy {
                    return Err(agentguard_core::GuardError::IpcError(
                        "init aborted: protection audit found unhealthy deny paths. \
Use `phylax project verify` to inspect and fix, or re-run with `--allow-unhealthy` (insecure)."
                            .to_string(),
                    ));
                }
            }
        }
        Err(e) => {
            println!("! Could not run post-init protection audit: {e}");
            println!("  Run `phylax project verify` once daemon is ready.");
        }
    }
    println!();
    println!("  Edit phylax.toml to customize permissions.");
    println!("  The daemon will reload automatically when you save changes.");
    println!();
    println!("  phylax status              -> view state");
    println!("  phylax serve               -> open web dashboard");
    println!("  phylax project check ...   -> dry-run an operation");

    Ok(())
}

async fn ensure_daemon_running() -> GuardResult<()> {
    super::daemon::start().await
}
