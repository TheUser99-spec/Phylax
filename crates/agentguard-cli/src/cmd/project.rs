use agentguard_core::GuardResult;
use agentguard_ipc::IpcClient;
use std::path::PathBuf;

pub async fn validate(path: PathBuf) -> GuardResult<()> {
    let abs = resolve_existing_path(path);

    let client = IpcClient::new();
    let result = client.validate_project(abs).await?;

    if result.valid {
        println!("+ agentguard.toml valido");
    } else {
        println!("- agentguard.toml invalido");
        for e in &result.errors {
            println!("  error: {e}");
        }
    }

    for w in &result.warnings {
        println!("  warning: {w}");
    }

    let s = &result.summary;
    println!();
    println!("  Resumen de politica:");
    println!("  default_mode : {}", s.default_mode);
    println!("  [deny]       : {} patrones", s.deny_patterns);
    println!("  [ask]        : {} patrones", s.ask_patterns);
    println!("  [write]      : {} patrones", s.write_patterns);
    println!("  [delete]     : {} patrones", s.delete_patterns);
    println!("  [read]       : {} patrones", s.read_patterns);

    Ok(())
}

pub async fn check(file: PathBuf, op: String) -> GuardResult<()> {
    let abs = resolve_path_allow_missing(file);

    let client = IpcClient::new();
    let result = client.check_file(abs, op).await?;

    let (icon, color) = match &result.decision {
        agentguard_core::PolicyDecision::Allow => ("+", "\x1b[32m"),
        agentguard_core::PolicyDecision::Deny => ("-", "\x1b[31m"),
        agentguard_core::PolicyDecision::Ask { .. } => ("?", "\x1b[33m"),
    };

    println!(
        "{color}{icon} {} -- {} -> {}\x1b[0m",
        result.path.display(),
        result.op,
        result.decision,
    );
    println!("  fuente : {}", result.source);
    println!("  razon  : {}", result.reason);

    Ok(())
}

pub async fn unregister(path: PathBuf) -> GuardResult<()> {
    let abs = resolve_existing_path(path);

    IpcClient::new().unregister_project(abs.clone()).await?;
    println!("+ Proyecto eliminado de la vigilancia: {}", abs.display());

    Ok(())
}

pub async fn off(path: PathBuf) -> GuardResult<()> {
    let abs = resolve_existing_path(path);
    IpcClient::new().disable_protection(abs.clone()).await?;
    println!("+ Protecciones desactivadas: {}", abs.display());
    Ok(())
}

pub async fn on(path: PathBuf) -> GuardResult<()> {
    let abs = resolve_existing_path(path);
    IpcClient::new().enable_protection(abs.clone()).await?;
    println!("+ Protecciones reactivadas: {}", abs.display());
    Ok(())
}

pub async fn reload(path: PathBuf) -> GuardResult<()> {
    let abs = resolve_existing_path(path);
    let resp = IpcClient::new()
        .send(agentguard_ipc::IpcRequest::ReloadPolicy { path: abs.clone() })
        .await?;
    match resp {
        agentguard_ipc::IpcResponse::Ok => {
            println!("+ Policy reloaded from disk: {}", abs.display());
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

pub async fn show() -> GuardResult<()> {
    let cwd = std::env::current_dir().map_err(agentguard_core::GuardError::Io)?;

    let client = IpcClient::new();
    let resp = client
        .send(agentguard_ipc::IpcRequest::GetPolicy { path: cwd.clone() })
        .await?;

    match resp {
        agentguard_ipc::IpcResponse::Policy(policy) => {
            println!(
                "Project policy: {} (default: {})",
                policy.project_name, policy.default_mode
            );
            println!();

            print_bucket("deny", &policy.deny);
            print_bucket("ask", &policy.ask);
            print_bucket("full", &policy.full);
            print_bucket("delete", &policy.delete);
            print_bucket("write", &policy.write);
            print_bucket("read", &policy.read);

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

pub async fn verify(path: PathBuf, json: bool) -> GuardResult<()> {
    let abs = resolve_existing_path(path);
    let report = IpcClient::new().verify_protection(abs.clone()).await?;

    if json {
        let body = serde_json::to_string_pretty(&report).map_err(|e| {
            agentguard_core::GuardError::IpcError(format!("json encode failed: {e}"))
        })?;
        println!("{body}");
        if report.unhealthy_paths.is_empty() {
            return Ok(());
        }
        return Err(agentguard_core::GuardError::IpcError(format!(
            "{} deny paths are not fully protected",
            report.unhealthy_paths.len()
        )));
    }

    println!("Project: {}", report.workspace.display());
    println!(
        "Protected deny paths (full health): {}/{}",
        report.healthy_paths, report.total_deny_paths
    );
    println!(
        "Protected deny paths (effective deny): {}/{}",
        report.effective_deny_paths, report.total_deny_paths
    );

    if report.unhealthy_paths.is_empty() {
        println!("+ All deny paths have active protection.");
        return Ok(());
    }

    println!("- Unhealthy deny paths: {}", report.unhealthy_paths.len());
    for item in &report.unhealthy_paths {
        println!("  {}", item.path.display());
        println!(
            "    exists={} content_deny={} metadata_deny={} effective_deny={}",
            item.exists, item.content_deny, item.metadata_deny, item.effective_deny
        );
    }

    Err(agentguard_core::GuardError::IpcError(format!(
        "{} deny paths are not fully protected",
        report.unhealthy_paths.len()
    )))
}

fn print_bucket(name: &str, files: &[String]) {
    if files.is_empty() {
        return;
    }
    let color = match name {
        "deny" => "\x1b[31m",
        "ask" => "\x1b[33m",
        "write" => "\x1b[36m",
        _ => "\x1b[0m",
    };
    println!("{color}[{name}]\x1b[0m ({})", files.len());
    for f in files {
        println!("    {f}");
    }
    println!();
}

fn resolve_existing_path(path: PathBuf) -> PathBuf {
    let base = absolutize(path);
    match base.canonicalize() {
        Ok(p) => strip_verbatim_prefix(p),
        Err(_) => strip_verbatim_prefix(base),
    }
}

fn resolve_path_allow_missing(path: PathBuf) -> PathBuf {
    let base = absolutize(path);
    match base.canonicalize() {
        Ok(p) => strip_verbatim_prefix(p),
        Err(_) => strip_verbatim_prefix(base),
    }
}

fn absolutize(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path
    }
}

fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix("\\\\?\\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}
