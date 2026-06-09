use agentguard_core::Bucket;
use agentguard_core::{FileOp, GuardResult, PolicyDecision};
use agentguard_ipc::{
    ActiveAgent, AgentRuleInfo, AgentRulesListData, AgentStat, AuditEventsData,
    AuditEventView, ComplianceGapData, ComplianceReportData, ComplianceStatusData, DaemonStatus,
    DashboardStats, DexStatusData, FileCheckResult, GlobalRuleInfo, GlobalRulesListData,
    IntegrityReportData, IpcRequest, IpcResponse, McpDiscoveryData, McpRulesListData,
    PolicyData, PolicySummary, ProjectInfo, ProtectionPathHealth, ProtectionReportData,
    ValidationResult,
};
use agentguard_manifest::{
    enforce_mandatory_denies, missing_mandatory_denies, CompiledManifest, ProjectManifest,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::orchestrator::DaemonState;

pub fn handle(state: Arc<DaemonState>, req: IpcRequest) -> IpcResponse {
    match handle_inner(state, req) {
        Ok(resp) => resp,
        Err(e) => IpcResponse::Error {
            message: e.to_string(),
        },
    }
}

fn handle_inner(state: Arc<DaemonState>, req: IpcRequest) -> GuardResult<IpcResponse> {
    match req {
        IpcRequest::RegisterProject { path } => {
            state.register_project(path)?;
            Ok(IpcResponse::Ok)
        }

        IpcRequest::UnregisterProject { path } => {
            state.unregister_project(&path)?;
            Ok(IpcResponse::Ok)
        }

        IpcRequest::ReloadPolicy { path } => {
            state.reload_project(&path)?;
            Ok(IpcResponse::Ok)
        }

        IpcRequest::GetStatus => {
            let projects: Vec<ProjectInfo> = state
                .store
                .list_projects()?
                .into_iter()
                .map(|p| {
                    let counts = load_counts_from_memory(state.as_ref(), &p.path);
                    ProjectInfo {
                        path: p.path,
                        toml_hash: p.toml_hash,
                        added_at: p.added_at,
                        deny_count: counts.0,
                        ask_count: counts.1,
                        write_count: counts.2,
                        delete_count: counts.3,
                        read_count: counts.4,
                    }
                })
                .collect();

            let active_agents: Vec<ActiveAgent> = state
                .tracker
                .active_sessions()
                .into_iter()
                .map(|s| ActiveAgent {
                    pid: s.pid,
                    image_name: s.image_name,
                    label: s.label,
                    workspace: s.workspace,
                    started_at: s.started_at.timestamp(),
                })
                .collect();

            let (events, blocks) = state.store.count_events_today().unwrap_or((0, 0));

            let recent_events: Vec<AuditEventView> = state
                .store
                .recent_audit_events(50)
                .unwrap_or_default()
                .into_iter()
                .map(|e| AuditEventView {
                    id: e.id.unwrap_or(0),
                    agent_pid: e.agent_pid,
                    agent_label: e.agent_label.as_str().to_string(),
                    file_path: e.file_path.to_string_lossy().to_string(),
                    operation: e.operation.as_str().to_string(),
                    decision: e.decision.as_str().to_string(),
                    source: e.source.as_str().to_string(),
                    timestamp: e.timestamp.timestamp(),
                })
                .collect();

            Ok(IpcResponse::Status(DaemonStatus {
                running: true,
                version: env!("CARGO_PKG_VERSION").to_string(),
                projects,
                active_agents,
                events_today: events,
                blocks_today: blocks,
                recent_events,
            }))
        }

        IpcRequest::ValidateProject { path } => {
            let manifest = match find_and_read_manifest_with_daemon_access(&path) {
                Ok(m) => m,
                Err(e) => {
                    return Ok(IpcResponse::ProjectValidation(ValidationResult {
                        valid: false,
                        errors: vec![e.to_string()],
                        warnings: vec![],
                        summary: empty_summary(),
                    }))
                }
            };

            let mut errors = vec![];
            let mut warnings = vec![];

            for (bucket, patterns) in [
                ("deny", &manifest.deny.files),
                ("ask", &manifest.ask.files),
                ("write", &manifest.write.files),
                ("delete", &manifest.delete.files),
                ("read", &manifest.read.files),
                ("full", &manifest.full.files),
            ] {
                for p in patterns {
                    if globset::Glob::new(p).is_err() {
                        errors.push(format!("[{bucket}] invalid glob: '{p}'"));
                    }
                    if p == "**" || p == "**/*" {
                        warnings.push(format!("[{bucket}] '**' matches EVERYTHING — intentional?"));
                    }
                }
            }

            // Runtime hardening injects these patterns even if TOML omits them.
            // Treat omissions as validation errors so policy files stay explicit.
            for pat in missing_mandatory_denies(&manifest) {
                errors.push(format!("[deny] missing mandatory pattern '{pat}'"));
            }

            Ok(IpcResponse::ProjectValidation(ValidationResult {
                valid: errors.is_empty(),
                errors,
                warnings,
                summary: PolicySummary {
                    deny_patterns: manifest.deny.files.len(),
                    ask_patterns: manifest.ask.files.len(),
                    write_patterns: manifest.write.files.len(),
                    delete_patterns: manifest.delete.files.len(),
                    read_patterns: manifest.read.files.len(),
                    full_patterns: manifest.full.files.len(),
                    default_mode: format!("{:?}", manifest.project.default),
                },
            }))
        }

        IpcRequest::CheckFileAccess { path, op, agent_image } => {
            let file_op = match op.as_str() {
                "read" => FileOp::Read,
                "write" => FileOp::Write,
                "delete" => FileOp::Delete,
                other => {
                    return Err(agentguard_core::GuardError::IpcError(format!(
                        "Invalid op: '{other}'. Use: read, write, delete"
                    )))
                }
            };

            let decision = match evaluate_manifest_dry_run(&path, &file_op)? {
                Some(d) => d,
                None => state.evaluate_access_for_agent(&path, &file_op, agent_image.as_deref())?,
            };

            Ok(IpcResponse::FileCheck(FileCheckResult {
                path: path.clone(),
                op: op.clone(),
                decision,
                source: "policy".to_string(),
                reason: format!("dry-run evaluation for {op} on {}", path.display()),
            }))
        }

        IpcRequest::Shutdown => {
            eprintln!("[daemon] Shutdown requested via CLI — releasing all ACEs first...");
            state.release_all_projects();
            eprintln!("[daemon] ACEs released, signalling shutdown.");
            state.signal_shutdown();
            Ok(IpcResponse::Ok)
        }

        IpcRequest::AskResponse {
            request_id,
            allowed,
            remember,
        } => {
            let _ = state.process_ask_response(request_id, allowed, remember);
            Ok(IpcResponse::Ok)
        }

        IpcRequest::AddGlobalRule { bucket, pattern } => {
            const MAX_PATTERN_LEN: usize = 1024;
            if pattern.trim().is_empty() {
                return Err(agentguard_core::GuardError::IpcError(
                    "Pattern cannot be empty".into(),
                ));
            }
            if pattern.len() > MAX_PATTERN_LEN {
                return Err(agentguard_core::GuardError::IpcError(format!(
                    "Pattern too long (max {MAX_PATTERN_LEN} chars)"
                )));
            }
            if globset::Glob::new(&pattern).is_err() {
                return Err(agentguard_core::GuardError::IpcError(format!(
                    "Invalid glob pattern: '{pattern}'"
                )));
            }

            let bucket = match bucket.as_str() {
                "deny" => Bucket::Deny,
                "ask" => Bucket::Ask,
                "full" => Bucket::Full,
                "delete" => Bucket::Delete,
                "write" => Bucket::Write,
                "read" => Bucket::Read,
                other => {
                    return Err(agentguard_core::GuardError::IpcError(format!(
                        "Invalid bucket: '{other}'. Use: deny, ask, full, delete, write, read"
                    )))
                }
            };
            let id = state.add_global_rule(bucket, &pattern)?;
            eprintln!("[daemon] Global rule added: id={id} [{bucket}] {pattern}");
            Ok(IpcResponse::Ok)
        }

        IpcRequest::RemoveGlobalRule { id } => {
            let before = state.store.list_global_rules()?.len();
            state.remove_global_rule(id)?;
            let after = state.store.list_global_rules()?.len();
            if before == after {
                return Err(agentguard_core::GuardError::IpcError(format!(
                    "Global rule {id} not found"
                )));
            }
            eprintln!("[daemon] Global rule removed: id={id}");
            Ok(IpcResponse::Ok)
        }

        IpcRequest::EnableProtection { path } => {
            state.enable_protection(&path)?;
            Ok(IpcResponse::Ok)
        }

        IpcRequest::DisableProtection { path } => {
            state.disable_protection(&path)?;
            Ok(IpcResponse::Ok)
        }

        IpcRequest::ListGlobalRules => {
            let rules: Vec<GlobalRuleInfo> = state
                .store
                .list_global_rules()?
                .into_iter()
                .map(|r| GlobalRuleInfo {
                    id: r.id.unwrap_or(0),
                    bucket: r.bucket.as_str().to_string(),
                    pattern: r.pattern,
                    created_at: r.created.format("%Y-%m-%d %H:%M").to_string(),
                })
                .collect();
            Ok(IpcResponse::GlobalRulesList(GlobalRulesListData { rules }))
        }

        IpcRequest::GetPolicy { path } => {
            let mut manifest = find_and_read_manifest_with_daemon_access(&path)?;
            enforce_mandatory_denies(&mut manifest);

            Ok(IpcResponse::Policy(PolicyData {
                project_name: manifest.project.name.unwrap_or_default(),
                default_mode: format!("{:?}", manifest.project.default),
                deny: manifest.deny.files,
                ask: manifest.ask.files,
                full: manifest.full.files,
                delete: manifest.delete.files,
                write: manifest.write.files,
                read: manifest.read.files,
            }))
        }

        IpcRequest::SubscribeEvents => {
            // Handled directly by the IPC server — this arm should not be reached.
            Ok(IpcResponse::Ok)
        }

        IpcRequest::AddAgentRule {
            agent_image,
            bucket,
            pattern,
        } => {
            if pattern.trim().is_empty() || agent_image.trim().is_empty() {
                return Err(agentguard_core::GuardError::IpcError(
                    "agent_image and pattern cannot be empty".into(),
                ));
            }
            let bucket = parse_bucket(&bucket)?;
            let _id = state.add_agent_rule(&agent_image, bucket, &pattern)?;
            state.system_msg(
                "info",
                &format!("Agent rule added: [{agent_image}] [{bucket}] {pattern}"),
            );
            Ok(IpcResponse::Ok)
        }

        IpcRequest::RemoveAgentRule { id } => {
            let before = state.store.list_agent_rules(None).map(|r| r.len()).unwrap_or(0);
            state.remove_agent_rule(id)?;
            let after = state.store.list_agent_rules(None).map(|r| r.len()).unwrap_or(0);
            if before == after {
                return Err(agentguard_core::GuardError::IpcError(format!("Agent rule id={id} not found")));
            }
            state.system_msg("info", &format!("Agent rule removed: id={id}"));
            Ok(IpcResponse::Ok)
        }

        IpcRequest::ListAgentRules { agent_image } => {
            let rules = state.list_agent_rules(agent_image.as_deref())?;
            Ok(IpcResponse::AgentRulesList(AgentRulesListData { rules }))
        }

        IpcRequest::GetStats => {
            let (total, blocks, allows, asks) = state.store.stats_today()?;
            let top_agents: Vec<AgentStat> = state
                .store
                .top_agents_today(5)?
                .into_iter()
                .map(|(label, count)| AgentStat {
                    agent_label: label,
                    count,
                })
                .collect();

            Ok(IpcResponse::Stats(DashboardStats {
                total_events: total,
                blocks,
                allows,
                asks,
                top_agents,
                timestamp: chrono::Utc::now().timestamp(),
            }))
        }
        IpcRequest::VerifyProtection { path } => {
            let workspace = path.clone();
            let audited = state.verify_project_protection(&path)?;
            let total = audited.len();
            let mut healthy = 0usize;
            let mut effective = 0usize;
            let mut unhealthy_paths = Vec::new();
            for item in audited {
                let effective_deny = item.health.content_deny && item.health.metadata_deny;
                if effective_deny {
                    effective += 1;
                }
                if item.health.healthy() {
                    healthy += 1;
                } else {
                    unhealthy_paths.push(ProtectionPathHealth {
                        path: item.path,
                        exists: item.health.exists,
                        content_deny: item.health.content_deny,
                        metadata_deny: item.health.metadata_deny,
                        effective_deny,
                        healthy: false,
                    });
                }
            }

            let mut warnings = Vec::new();

            if effective == 0 {
                warnings.push(
                    "No effective deny paths. \
                    Phylax is not actively protecting any files.".to_string(),
                );
            }

            Ok(IpcResponse::ProtectionReport(ProtectionReportData {
                schema_version: 1,
                workspace,
                total_deny_paths: total,
                healthy_paths: healthy,
                effective_deny_paths: effective,
                unhealthy_paths,
                warnings,
            }))
        }

        IpcRequest::GetComplianceStatus { standard } => {
            let (total, blocks) = state.store.count_events_today().unwrap_or((0, 0));
            let (_stat_total, _stat_blocks, _stat_allows, stat_asks) = state.store.stats_today().unwrap_or((0, 0, 0, 0));
            let active = state.store.active_sessions().map(|v| v.len() as u64).unwrap_or(0);
            let engine = agentguard_compliance::ComplianceEngine::with_data(
                agentguard_compliance::AuditCounts {
                    total_events: total,
                    deny_count: blocks,
                    ask_count: stat_asks,
                    active_agents: active,
                },
                state.list_projects().iter().map(|p| p.display().to_string()).collect(),
                false,
            );
            let report = engine.evaluate(&standard);
            let gaps: Vec<ComplianceGapData> = engine.check_gaps(&standard).into_iter().map(|g| ComplianceGapData {
                article: g.article, control_id: g.control_id, description: g.description,
                remediation: g.remediation, severity: g.severity.as_str().to_string(),
            }).collect();
            let controls_impl: usize = report.articles.iter().map(|a| a.controls_implemented).sum();
            let controls_part: usize = report.articles.iter().map(|a| a.controls_partial).sum();
            let controls_miss: usize = report.articles.iter().map(|a| a.controls_missing).sum();
            Ok(IpcResponse::ComplianceStatus(ComplianceStatusData {
                standard: report.standard,
                overall_status: report.overall_status.as_str().to_string(),
                articles_count: report.articles.len(),
                controls_implemented: controls_impl,
                controls_partial: controls_part,
                controls_missing: controls_miss,
                gaps,
            }))
        }

        IpcRequest::GetComplianceReport { standard, format: _format } => {
            let (total, _blocks) = state.store.count_events_today().unwrap_or((0, 0));
            let engine = agentguard_compliance::ComplianceEngine::with_data(
                agentguard_compliance::AuditCounts {
                    total_events: total, deny_count: 0, ask_count: 0, active_agents: 0,
                },
                state.list_projects().iter().map(|p| p.display().to_string()).collect(),
                false,
            );
            let report = engine.evaluate(&standard);
            let report_json = serde_json::to_string_pretty(&report).unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {}\"}}", e));
            Ok(IpcResponse::ComplianceReport(ComplianceReportData {
                standard: report.standard,
                generated_at: report.generated_at,
                overall_status: report.overall_status.as_str().to_string(),
                report_json,
            }))
        }

        IpcRequest::GetAuditEvents { cursor: _, limit, filter: _ } => {
            let events = state.store.recent_audit_events(limit as usize).unwrap_or_default();
            let count = events.len() as u64;
            let json = serde_json::to_string_pretty(&events).unwrap_or_else(|_| "[]".to_string());
            Ok(IpcResponse::AuditEvents(AuditEventsData {
                events: json,
                next_cursor: None,
                has_more: false,
                event_count: count,
            }))
        }

        IpcRequest::ExportAuditLog { format, filter: _, limit } => {
            let max = limit.unwrap_or(1000).min(10000);
            let events = state.store.recent_audit_events(max).unwrap_or_default();
            let host = std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "unknown".to_string());
            let count = events.len() as u64;
            let output = match format.as_str() {
                "ocsf" => agentguard_audit::formats::events_to_ocsf(&events, &host),
                "cef" => agentguard_audit::formats::events_to_cef(&events),
                _ => serde_json::to_string_pretty(&events).unwrap_or_else(|_| "[]".to_string()),
            };
            Ok(IpcResponse::AuditEvents(AuditEventsData {
                events: output,
                next_cursor: None,
                has_more: false,
                event_count: count,
            }))
        }

        IpcRequest::VerifyAuditIntegrity => {
            let report = state.store.verify_audit_integrity()?;
            Ok(IpcResponse::AuditIntegrity(IntegrityReportData {
                total_events: report.total_events,
                verified_events: report.verified_events,
                tampered_events: report.tampered_events,
                chain_intact: report.chain_intact,
                first_hash: report.first_hash,
                last_hash: report.last_hash,
            }))
        }

        IpcRequest::DiscoverMcpServers => {
            let report = agentguard_mcp::discover_mcp_servers();
            let servers_json = serde_json::to_string_pretty(&report.servers).unwrap_or_else(|_| "[]".into());
            Ok(IpcResponse::McpDiscovery(McpDiscoveryData {
                servers_found: report.servers_found,
                config_files_scanned: report.config_files_scanned,
                config_files_found: report.config_files_found,
                servers_json,
            }))
        }

        IpcRequest::GetMcpRules => {
            let rules: Vec<serde_json::Value> = state.store.list_global_rules()
                .unwrap_or_default()
                .iter()
                .filter(|r| r.pattern.starts_with(".mcp") || r.pattern.starts_with(".claude/") || r.pattern.starts_with(".cursor/") || r.pattern.starts_with(".gemini/"))
                .map(|r| serde_json::json!({
                    "id": r.id,
                    "bucket": r.bucket.to_string(),
                    "pattern": r.pattern,
                    "created_at": r.created.timestamp(),
                }))
                .collect();
            let rules_json = serde_json::to_string_pretty(&rules).unwrap_or_else(|_| "[]".into());
            Ok(IpcResponse::McpRulesList(McpRulesListData { rules_json }))
        }

        IpcRequest::AddMcpRule { server_name, action } => {
            let bucket = match action.as_str() {
                "deny" => Bucket::Deny,
                "ask" => Bucket::Ask,
                "read" => Bucket::Read,
                other => return Err(agentguard_core::GuardError::IpcError(
                    format!("Invalid MCP action: '{other}'. Use: deny, ask, read")
                )),
            };
            if server_name.is_empty() {
                return Err(agentguard_core::GuardError::IpcError("Server name cannot be empty".into()));
            }
            let pattern = format!("**/{server_name}");
            state.add_global_rule(bucket, &pattern)?;
            Ok(IpcResponse::Ok)
        }

        IpcRequest::RemoveMcpRule { id } => {
            state.remove_global_rule(id)?;
            Ok(IpcResponse::Ok)
        }

        IpcRequest::CheckDexStatus => {
            let pids: Vec<u32> = state.store.active_sessions()
                .unwrap_or_default()
                .iter()
                .map(|s| s.pid)
                .collect();
            let mut monitor = agentguard_dex::DexMonitor::new();
            for pid in &pids {
                monitor.track_agent(*pid);
            }
            let result = monitor.check_all();
            let report_json = serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".into());
            Ok(IpcResponse::DexStatus(DexStatusData {
                total_connections: result.total_connections,
                suspicious_connections: result.suspicious_connections,
                active_agents_online: result.active_agents_online.len(),
                usb_devices: result.usb_devices.len(),
                risk_level: result.risk_level.as_str().to_string(),
                report_json,
            }))
        }
    }
}

fn load_counts_from_memory(
    state: &DaemonState,
    path: &std::path::Path,
) -> (usize, usize, usize, usize, usize) {
    let projects = state.projects.read().unwrap_or_else(|e| e.into_inner());
    projects
        .get(path)
        .map(|entry| entry.manifest.bucket_counts())
        .unwrap_or((0, 0, 0, 0, 0))
}

fn empty_summary() -> PolicySummary {
    PolicySummary {
        deny_patterns: 0,
        ask_patterns: 0,
        write_patterns: 0,
        delete_patterns: 0,
        read_patterns: 0,
        full_patterns: 0,
        default_mode: "conservative".to_string(),
    }
}

fn parse_bucket(s: &str) -> Result<Bucket, agentguard_core::GuardError> {
    match s {
        "deny" => Ok(Bucket::Deny),
        "ask" => Ok(Bucket::Ask),
        "full" => Ok(Bucket::Full),
        "delete" => Ok(Bucket::Delete),
        "write" => Ok(Bucket::Write),
        "read" => Ok(Bucket::Read),
        other => Err(agentguard_core::GuardError::IpcError(format!(
            "Invalid bucket: '{other}'. Use: deny, ask, full, delete, write, read"
        ))),
    }
}

fn read_manifest_with_daemon_access(
    workspace: &Path,
    toml_path: &Path,
    assume_protected_on_probe_error: bool,
) -> GuardResult<ProjectManifest> {
    #[cfg(windows)]
    {
        let enforcer = agentguard_enforce::Enforcer::new(workspace.to_path_buf());
        let had_protection = match agentguard_enforce::ace::verify_ace(toml_path) {
            Ok(health) => health.content_deny || health.metadata_deny,
            Err(e) => {
                eprintln!(
                    "[daemon] WARN: failed to inspect ACE on {} before IPC read: {e}",
                    toml_path.display()
                );
                assume_protected_on_probe_error
            }
        };

        if had_protection {
            enforcer.temporarily_allow(toml_path)?;
        }

        let result = ProjectManifest::from_file(toml_path);

        if had_protection {
            if let Err(e) = enforcer.reapply_ask(toml_path) {
                eprintln!(
                    "[daemon] WARN: failed to reapply ACE after IPC read on {}: {e}",
                    toml_path.display()
                );
                if result.is_ok() {
                    return Err(e);
                }
            }
        }

        result
    }

    #[cfg(not(windows))]
    {
        let _ = workspace;
        let _ = assume_protected_on_probe_error;
        ProjectManifest::from_file(toml_path)
    }
}

fn find_and_read_manifest_with_daemon_access(start: &Path) -> GuardResult<ProjectManifest> {
    let mut current = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };

    loop {
        let candidate = current.join("phylax.toml");
        match read_manifest_with_daemon_access(&current, &candidate, false) {
            Ok(manifest) => return Ok(manifest),
            Err(e) => {
                if candidate.is_file() {
                    return Err(e);
                }
            }
        }

        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                return Err(agentguard_core::GuardError::ManifestNotFound {
                    path: start.display().to_string(),
                })
            }
        }
    }
}

fn find_manifest_path_with_daemon_access(start: &Path) -> GuardResult<(PathBuf, ProjectManifest)> {
    let mut current = if start.is_file() {
        start.parent().unwrap_or(start).to_path_buf()
    } else {
        start.to_path_buf()
    };

    loop {
        let candidate = current.join("phylax.toml");
        match read_manifest_with_daemon_access(&current, &candidate, false) {
            Ok(manifest) => return Ok((candidate, manifest)),
            Err(e) => {
                if candidate.is_file() {
                    return Err(e);
                }
            }
        }

        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                return Err(agentguard_core::GuardError::ManifestNotFound {
                    path: start.display().to_string(),
                })
            }
        }
    }
}

fn evaluate_manifest_dry_run(
    path: &std::path::Path,
    op: &FileOp,
) -> GuardResult<Option<PolicyDecision>> {
    let probe_dir = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| path.to_path_buf()))
    };

    let (manifest_path, mut manifest) = match find_manifest_path_with_daemon_access(&probe_dir) {
        Ok(found) => found,
        Err(_) => return Ok(None),
    };

    let workspace_root = manifest_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| probe_dir.clone());

    let workspace_root = std::fs::canonicalize(&workspace_root).unwrap_or(workspace_root);
    enforce_mandatory_denies(&mut manifest);
    let compiled = CompiledManifest::compile(&manifest, workspace_root.clone())?;

    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };
    let abs_path = std::fs::canonicalize(&abs_path).unwrap_or(abs_path);

    // If caller asked about a path outside the discovered workspace, skip.
    if !abs_path.starts_with(&workspace_root) {
        return Ok(None);
    }

    let (decision, _source) = compiled.evaluate(&abs_path, op);
    Ok(Some(decision))
}


#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use agentguard_manifest::MANDATORY_DENY_PATTERNS;

    #[test]
    fn enforce_mandatory_denies_adds_all_patterns() {
        let mut m = ProjectManifest::default();
        enforce_mandatory_denies(&mut m);
        for pat in MANDATORY_DENY_PATTERNS {
            assert!(
                m.deny.files.iter().any(|p| p == pat),
                "missing mandatory deny pattern: {pat}"
            );
        }
    }

    #[test]
    fn enforce_mandatory_denies_deduplicates_existing() {
        let mut m = ProjectManifest::default();
        m.deny.files.push(".env".into());
        m.deny.files.push(".env".into());
        m.deny.files.push(".git/**".into());
        enforce_mandatory_denies(&mut m);

        let env_count = m.deny.files.iter().filter(|p| p.as_str() == ".env").count();
        let git_count = m
            .deny
            .files
            .iter()
            .filter(|p| p.as_str() == ".git/**")
            .count();
        assert_eq!(env_count, 1);
        assert_eq!(git_count, 1);
    }

    #[test]
    fn missing_mandatory_denies_detects_omissions() {
        let mut m = ProjectManifest::default();
        m.deny.files.push(".env".into());
        let missing = missing_mandatory_denies(&m);
        assert!(missing.contains(&"phylax.toml"));
        assert!(missing.contains(&".git/**"));
        assert!(!missing.contains(&".env"));
    }

    #[test]
    fn missing_mandatory_denies_is_empty_when_complete() {
        let mut m = ProjectManifest::default();
        enforce_mandatory_denies(&mut m);
        let missing = missing_mandatory_denies(&m);
        assert!(missing.is_empty());
    }

    #[test]
    fn evaluate_manifest_dry_run_applies_mandatory_deny_when_omitted() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(
            ws.join("phylax.toml"),
            r#"
[project]
name = "x"
default = "conservative"
"#,
        )
        .unwrap();

        let target = ws.join(".env");
        std::fs::write(&target, "SECRET=1").unwrap();

        let decision = evaluate_manifest_dry_run(&target, &FileOp::Read)
            .unwrap()
            .expect("manifest should be found");
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn find_manifest_from_nested_path_uses_selected_workspace_context() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("workspace");
        let nested = ws.join("src").join("deep");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(
            ws.join("phylax.toml"),
            r#"
[project]
name = "selected"
default = "conservative"

[read]
files = ["src/**"]
"#,
        )
        .unwrap();

        let manifest = find_and_read_manifest_with_daemon_access(&nested).unwrap();
        assert_eq!(manifest.project.name.as_deref(), Some("selected"));
        assert!(manifest.read.files.iter().any(|p| p == "src/**"));
    }
}
