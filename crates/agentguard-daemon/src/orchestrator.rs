use agentguard_audit::Auditor;
use agentguard_core::{
    AgentLabel, AgentSession, Bucket, FileOp, GuardResult, PolicyDecision, PolicySource,
};
use agentguard_ipc::{ActiveAgent, AuditEventView, IpcResponse, StreamingEvent};
use agentguard_manifest::{enforce_mandatory_denies, find_manifest, CompiledManifest, ProjectManifest};
use agentguard_probe::{AgentSessionTracker, SubjectClassifier};
use agentguard_store::Store;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use tokio::sync::{broadcast, mpsc};

macro_rules! recover_lock { ($lock:expr, $lbl:expr) => { match $lock { Ok(g) => g, Err(e) => { eprintln!("[daemon] WARN: RwLock '{}' poisoned!", $lbl); e.into_inner() } } }; }
macro_rules! recover_enforcer_read { ($enf:expr) => { $enf.read().unwrap_or_else(|e| { eprintln!("[daemon] WARN: Enforcer read lock poisoned!"); e.into_inner() }) }; }
macro_rules! recover_enforcer_write { ($enf:expr) => { $enf.write().unwrap_or_else(|e| { eprintln!("[daemon] WARN: Enforcer write lock poisoned!"); e.into_inner() }) }; }

#[derive(Clone)]
pub struct DaemonState {
    pub store: Arc<Store>,
    pub tracker: Arc<AgentSessionTracker>,
    auditor: Arc<Auditor>,
    pub(crate) projects: Arc<RwLock<HashMap<PathBuf, ProjectEntry>>>,
    global_manifest: Arc<RwLock<Option<CompiledManifest>>>,
    shutdown_tx: Arc<mpsc::Sender<()>>,
    event_tx: broadcast::Sender<IpcResponse>,
    pending_asks: Arc<RwLock<HashMap<u64, AskState>>>,
    #[allow(dead_code)] next_request_id: Arc<AtomicU64>,
    agent_manifests: Arc<RwLock<HashMap<String, CompiledManifest>>>,
    protections_active: Arc<AtomicBool>,
}

#[derive(Clone)]
pub(crate) struct ProjectEntry { pub(crate) manifest: CompiledManifest, pub(crate) enforcer: Arc<RwLock<agentguard_enforce::Enforcer>>, pub(crate) toml_hash: String, }

#[derive(Clone)]
struct AskState { agent_label: AgentLabel, agent_pid: u32, file_path: PathBuf, operation: FileOp, #[allow(dead_code)] created_at: chrono::DateTime<chrono::Utc>, }

impl DaemonState {
    pub fn new(db_path: &Path, shutdown_tx: mpsc::Sender<()>, event_tx: broadcast::Sender<IpcResponse>) -> GuardResult<Self> {
        let store = Arc::new(Store::open(db_path)?); let aud = Arc::new(Auditor::new(store.as_ref().clone())); let tracker = Arc::new(AgentSessionTracker::new(SubjectClassifier::with_defaults()));
        store.expire_all_sessions().ok();
        let s = Self { store, tracker, auditor: aud, projects: Arc::new(RwLock::new(HashMap::new())), global_manifest: Arc::new(RwLock::new(None)), shutdown_tx: Arc::new(shutdown_tx), event_tx, pending_asks: Arc::new(RwLock::new(HashMap::new())), next_request_id: Arc::new(AtomicU64::new(1)), agent_manifests: Arc::new(RwLock::new(HashMap::new())), protections_active: Arc::new(AtomicBool::new(false)) };
        s.restore_projects()?; s.restore_global_rules()?; restore_agent_rules(&s)?;
        Ok(s)
    }

    pub fn register_project(&self, workspace: PathBuf) -> GuardResult<()> {
        let w = normalize(workspace); let tp = find_manifest(&w)?;
        // phylax.toml may already have a DENY ACE from a previous daemon session
        let had_ace = agentguard_enforce::ace::verify_ace(&tp).map(|h| h.content_deny || h.metadata_deny).unwrap_or(false);
        if had_ace { agentguard_enforce::ace::remove_deny_ace(&tp)?; }
        let read = (|| -> GuardResult<_> {
            Ok((ProjectManifest::from_file(&tp)?, hash_file(&tp)?))
        })();
        if had_ace { let _ = agentguard_enforce::ace::apply_deny_ace(&tp); }
        let (mut mr, h) = read?;
        enforce_mandatory_denies(&mut mr);
        let n = w.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
        let c = CompiledManifest::compile(&mr, w.clone())?;
        let mut e = agentguard_enforce::Enforcer::new(w.clone()); e.apply_project_protections(&c)?;
        let ask_paths = e.collect_ask_paths(&c);
        self.store.register_project(&w, &n).map_err(|err| { if let Err(e) = e.release_project_protections() { eprintln!("[daemon] WARN: ACE rollback failed: {e}"); } err })?;
        self.store.set_project_hash(&w, &h).map_err(|err| { if let Err(e) = e.release_project_protections() { eprintln!("[daemon] WARN: ACE rollback failed: {e}"); } err })?;
        let e = Arc::new(RwLock::new(e)); emit_health(self, &w, &e, &c);
        recover_lock!(self.projects.write(), "projects").insert(w.clone(), ProjectEntry { manifest: c, enforcer: e, toml_hash: h });
        for fp in &ask_paths { self.emit_ask_prompt(AgentLabel::Definite, 0, fp, FileOp::Read); }
        eprintln!("[daemon] Project registered: {} ({} ask prompts emitted)", w.display(), ask_paths.len()); self.system_msg("success", &format!("Project registered: {}", w.display())); self.protections_active.store(true, Ordering::SeqCst); Ok(())
    }

    pub fn unregister_project(&self, workspace: &Path) -> GuardResult<()> {
        let p = normalize(workspace.to_path_buf()); let entry = recover_lock!(self.projects.read(), "projects").get(&p).cloned();
        if let Some(entry) = entry { recover_enforcer_read!(entry.enforcer).release_project_protections()?; }
        self.store.unregister_project(&p)?; recover_lock!(self.projects.write(), "projects").remove(&p); self.system_msg("info", &format!("Project unregistered: {}", p.display())); Ok(())
    }

    pub fn enable_protection(&self, ws: &Path) -> GuardResult<()> { let p = normalize(ws.to_path_buf()); if let Some(e) = recover_lock!(self.projects.read(), "projects").get(&p) { recover_enforcer_write!(e.enforcer).apply_project_protections(&e.manifest)?; self.protections_active.store(true, Ordering::SeqCst); } Ok(()) }
    pub fn disable_protection(&self, ws: &Path) -> GuardResult<()> { let p = normalize(ws.to_path_buf()); if let Some(e) = recover_lock!(self.projects.read(), "projects").get(&p) { recover_enforcer_read!(e.enforcer).release_project_protections()?; self.protections_active.store(false, Ordering::SeqCst); } Ok(()) }

    pub fn verify_project_protection(&self, ws: &Path) -> GuardResult<Vec<agentguard_enforce::PathProtectionHealth>> {
        let p = normalize(ws.to_path_buf()); let entry = recover_lock!(self.projects.read(), "projects").get(&p).cloned().ok_or_else(|| agentguard_core::GuardError::IpcError("project not registered".into()))?; let result = recover_enforcer_read!(entry.enforcer).audit_project_protections(&entry.manifest); result
    }

    pub fn reload_project(&self, ws: &Path) -> GuardResult<()> {
        let w = normalize(ws.to_path_buf());
        let old = { let p = recover_lock!(self.projects.read(), "projects"); p.get(&w).cloned().ok_or_else(|| agentguard_core::GuardError::IpcError("project not found".into()))? };
        let tp = w.join("phylax.toml");
        let (nh, c) = with_toml(&old.enforcer, &tp, true, || { let tp = find_manifest(&w)?; let nh = hash_file(&tp)?; let mut mr = ProjectManifest::from_file(&tp)?; enforce_mandatory_denies(&mut mr); Ok((nh, CompiledManifest::compile(&mr, w.clone())?)) })?;
        if old.toml_hash == nh { return Ok(()); }
        let mut e = agentguard_enforce::Enforcer::new(w.clone());
        recover_enforcer_read!(old.enforcer).release_project_protections()?;
        e.apply_project_protections(&c).map_err(|err| { let _ = recover_enforcer_write!(old.enforcer).apply_project_protections(&old.manifest); err })?;
        let ask_paths = e.collect_ask_paths(&c);
        self.store.set_project_hash(&w, &nh)?; let e = Arc::new(RwLock::new(e));
        recover_lock!(self.projects.write(), "projects").insert(w.clone(), ProjectEntry { manifest: c, enforcer: e, toml_hash: nh });
        for fp in &ask_paths { self.emit_ask_prompt(AgentLabel::Definite, 0, fp, FileOp::Read); }
        if let Some(entry) = recover_lock!(self.projects.read(), "projects").get(&w) { emit_health(self, &w, &entry.enforcer, &entry.manifest); }
        eprintln!("[daemon] Hot-reload: {} ({} ask prompts emitted)", w.display(), ask_paths.len()); self.system_msg("success", &format!("Policy reloaded: {}", w.display())); Ok(())
    }

    pub fn add_global_rule(&self, bucket: Bucket, pattern: &str) -> GuardResult<i64> { let id = self.store.insert_global_rule(bucket, pattern)?; rebuild_global(self)?; Ok(id) }
    pub fn remove_global_rule(&self, id: i64) -> GuardResult<()> { self.store.delete_global_rule(id)?; rebuild_global(self)?; Ok(()) }

    pub fn add_agent_rule(&self, img: &str, bucket: Bucket, pattern: &str) -> GuardResult<()> { self.store.insert_agent_rule(img, &bucket.to_string(), pattern)?; rebuild_agent(self, img)?; Ok(()) }
    pub fn remove_agent_rule(&self, id: i64) -> GuardResult<()> { self.store.delete_agent_rule(id)?; restore_agent_rules(self)?; Ok(()) }
    pub fn list_agent_rules(&self, img: Option<&str>) -> GuardResult<Vec<agentguard_ipc::AgentRuleInfo>> { self.store.list_agent_rules(img).map(|r| r.into_iter().map(|x| agentguard_ipc::AgentRuleInfo { id: x.id, agent_image: x.agent_image, bucket: x.bucket.to_string(), pattern: x.pattern }).collect()).map_err(|e| e.into()) }

    pub fn evaluate_access_dry_run(&self, path: &Path, op: &FileOp) -> GuardResult<PolicyDecision> {
        self.evaluate_access_for_agent(path, op, None)
    }
    pub fn evaluate_access_for_agent(&self, path: &Path, op: &FileOp, agent_image: Option<&str>) -> GuardResult<PolicyDecision> {
        let p = normalize(path.to_path_buf());
        if let Some(img) = agent_image {
            let (d, _) = eval_agent(self, &p, op, img);
            if d != PolicyDecision::Allow { return Ok(d); }
        }
        let (d, _) = eval_global(self, &p, op); if d != PolicyDecision::Allow { return Ok(d); }
        let projects = recover_lock!(self.projects.read(), "projects"); for (ws, entry) in projects.iter() { if p.starts_with(ws) || is_in_ws(&p, ws) { let (dd, _) = entry.manifest.evaluate(&p, op); if dd != PolicyDecision::Allow { return Ok(dd); } } }
        Ok(PolicyDecision::Allow)
    }

    pub fn process_ask_response(&self, rid: u64, allowed: bool, remember: bool) -> GuardResult<()> {
        let ask = { let mut p = self.pending_asks.write().unwrap_or_else(|e| e.into_inner()); p.remove(&rid).ok_or_else(|| agentguard_core::GuardError::IpcError(format!("unknown: {rid}")))? };
        if remember { let _ = self.store.insert_ask_decision(&ask.file_path, if allowed {"allow"} else {"deny"}, 0); }
        let decision = if allowed {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny
        };
        let _ = self.log_and_emit_audit(
            ask.agent_pid,
            ask.agent_label,
            &ask.file_path,
            ask.operation,
            &decision,
            PolicySource::Project,
        );
        self.system_msg(if allowed {"success"} else {"warn"}, &format!("Ask #{}: {} {} {} (PID={})", rid, if allowed {"ALLOWED"} else {"DENIED"}, ask.operation.as_str(), ask.file_path.display(), ask.agent_pid)); Ok(())
    }

    pub fn emit_ask_prompt(&self, label: AgentLabel, pid: u32, fp: &Path, op: FileOp) -> u64 {
        let id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        self.pending_asks.write().unwrap_or_else(|e| e.into_inner()).insert(id, AskState { agent_label: label, agent_pid: pid, file_path: fp.to_path_buf(), operation: op, created_at: chrono::Utc::now() });
        self.emit(IpcResponse::Event(StreamingEvent::AskPrompt { request_id: id, agent_label: label.to_string(), file_path: fp.to_string_lossy().to_string(), operation: op.to_string() })); id
    }

    pub fn on_process_event(&self, ev: &agentguard_probe::ProcessEvent) {
        match ev {
            agentguard_probe::ProcessEvent::Started(i) => {
                let l = self.tracker.on_process_start(i, None);
                if l.is_agent() {
                    self.persist_session_start(i.pid, &i.image_name, l, None);
                    let prim = matches!(l, AgentLabel::Definite | AgentLabel::Probable);
                    if prim {
                        let applied = self.protect_all_projects();
                        self.apply_agent_deny_aces(&i.image_name);
                        if applied {
                            self.system_msg("warn", &format!("BLOCKED: Agent {} (PID={}) detected - deny rules applied", i.image_name, i.pid));
                        } else {
                            self.system_msg("error", &format!("Agent {} (PID={}) detected but protection could not be applied — check daemon privileges", i.image_name, i.pid));
                        }
                    }
                    self.emit(IpcResponse::Event(StreamingEvent::AgentDetected(ActiveAgent{pid:i.pid,image_name:i.image_name.clone(),label:l,workspace:None,started_at:chrono::Utc::now().timestamp()})));
                    self.status_event();
                }
            }
            agentguard_probe::ProcessEvent::Exited(pid) => {
                if let Some(s) = self.tracker.on_process_exit(*pid) {
                    self.persist_session_end(*pid);
                    if matches!(s.label, AgentLabel::Definite | AgentLabel::Probable) {
                        self.release_agent_deny_aces(&s.image_name);
                        self.system_msg("info", &format!("Agent exited: {} PID={}", s.image_name, pid));
                    }
                    self.emit(IpcResponse::Event(StreamingEvent::AgentExited{pid:*pid}));
                    self.status_event();
                }
            }
        }
    }

    fn apply_agent_deny_aces(&self, image_name: &str) {
        let manifests = self.agent_manifests.read().unwrap_or_else(|e| e.into_inner());
        let agent = match manifests.get(image_name) {
            Some(a) if a.deny_count() > 0 => a,
            _ => return,
        };
        eprintln!("[daemon] Agent '{}' has {} per-agent deny patterns — applying ACEs", image_name, agent.deny_count());
        let projects = recover_lock!(self.projects.read(), "projects");
        for (ws, _entry) in projects.iter() {
            if let Ok(entries) = std::fs::read_dir(ws) {
                for entry in entries.flatten() {
                    let fp = entry.path();
                    if fp.is_file() {
                        if let Ok(canonical) = std::fs::canonicalize(&fp) {
                            if agent.path_matches_deny(&canonical) {
                                if let Err(e) = agentguard_enforce::ace::apply_deny_ace(&fp) {
                                    eprintln!("[daemon] WARN: agent deny for {}: {e}", fp.display());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn release_agent_deny_aces(&self, image_name: &str) {
        let manifests = self.agent_manifests.read().unwrap_or_else(|e| e.into_inner());
        let agent = match manifests.get(image_name) {
            Some(a) if a.deny_count() > 0 => a,
            _ => return,
        };
        let projects = recover_lock!(self.projects.read(), "projects");
        for (ws, _entry) in projects.iter() {
            if let Ok(entries) = std::fs::read_dir(ws) {
                for entry in entries.flatten() {
                    let fp = entry.path();
                    if fp.is_file() {
                        if let Ok(canonical) = std::fs::canonicalize(&fp) {
                            if agent.path_matches_deny(&canonical) {
                                let _ = agentguard_enforce::ace::remove_deny_ace(&fp);
                            }
                        }
                    }
                }
            }
        }
    }

    fn protect_all_projects(&self) -> bool { if self.protections_active.swap(true, Ordering::SeqCst) { return true; } let mut any_ok = false; for e in recover_lock!(self.projects.read(), "projects").values() { match recover_enforcer_write!(e.enforcer).apply_project_protections(&e.manifest) { Ok(()) => any_ok = true, Err(err) => { eprintln!("[daemon] WARN: protect failed: {err}"); } } } if !any_ok { self.protections_active.store(false, Ordering::SeqCst); } any_ok }
    pub(crate) fn release_all_projects(&self) { self.protections_active.store(false, Ordering::SeqCst); for e in recover_lock!(self.projects.read(), "projects").values() { if let Err(err) = recover_enforcer_read!(e.enforcer).release_project_protections() { eprintln!("[daemon] WARN: release failed: {err}"); } } }
    pub(crate) fn protect_new_file(&self, fp: &Path) { if !self.protections_active.load(Ordering::SeqCst) { return; } for (ws, entry) in recover_lock!(self.projects.read(), "projects").iter() { if !(fp.starts_with(ws) || is_in_ws(fp, ws)) { continue; } match entry.manifest.bucket_for_path(fp) { Some(Bucket::Deny) | Some(Bucket::Read) => { eprintln!("[daemon] New protected file: {}", fp.display()); if let Err(err) = recover_enforcer_write!(entry.enforcer).reapply_ask(fp) { eprintln!("[daemon] WARN: protect new file: {err}"); } recover_enforcer_write!(entry.enforcer).add_to_deny_cache(fp.to_path_buf()); } Some(Bucket::Write) => { eprintln!("[daemon] New write-protected file: {}", fp.display()); let _ = agentguard_enforce::ace::apply_delete_deny_ace(fp); } Some(Bucket::Delete) => { eprintln!("[daemon] New delete-protected file: {}", fp.display()); let _ = agentguard_enforce::ace::apply_write_deny_ace(fp); } Some(Bucket::Ask) => { eprintln!("[daemon] New ask-protected file: {}", fp.display()); if let Err(err) = agentguard_enforce::ace::apply_deny_ace(fp) { eprintln!("[daemon] WARN: ask ACE failed: {err}"); } let _ = recover_enforcer_write!(entry.enforcer).add_to_deny_cache(fp.to_path_buf()); self.emit_ask_prompt(AgentLabel::Definite, 0, fp, FileOp::Read); } _ => {} } } }

    pub fn signal_shutdown(&self) { self.shutdown_tx.try_send(()).ok(); }
    pub fn list_projects(&self) -> Vec<PathBuf> { recover_lock!(self.projects.read(), "projects").keys().cloned().collect() }
    pub fn project_bucket_counts(&self, workspace: &Path) -> Option<(usize, usize, usize, usize, usize)> {
        let ws = normalize(workspace.to_path_buf());
        recover_lock!(self.projects.read(), "projects")
            .get(&ws)
            .map(|entry| entry.manifest.bucket_counts())
    }

    fn emit(&self, event: IpcResponse) { if self.event_tx.send(event).is_err() { eprintln!("[daemon] WARN: event channel full"); } }
    fn status_event(&self) {
        let et = self.store.count_events_today().unwrap_or((0,0));
        self.emit(IpcResponse::Event(StreamingEvent::StatusUpdate { events_today: et.0, blocks_today: et.1, active_agents_count: self.tracker.active_count(), projects_count: self.list_projects().len() }));
    }
    pub(crate) fn system_msg(&self, level: &str, msg: &str) { self.emit(IpcResponse::Event(StreamingEvent::SystemMessage { message: msg.to_string(), level: level.to_string(), timestamp: chrono::Utc::now().timestamp() })); }
    fn log_and_emit_audit(
        &self,
        agent_pid: u32,
        agent_label: AgentLabel,
        file_path: &Path,
        operation: FileOp,
        decision: &PolicyDecision,
        source: PolicySource,
    ) -> GuardResult<()> {
        self.auditor
            .log_decision(agent_pid, agent_label, file_path, operation, decision, source)?;
        self.emit(IpcResponse::Event(StreamingEvent::AuditEvent(AuditEventView {
            id: 0,
            agent_pid,
            agent_label: agent_label.as_str().to_string(),
            file_path: file_path.to_string_lossy().to_string(),
            operation: operation.as_str().to_string(),
            decision: decision.as_str().to_string(),
            source: source.as_str().to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        })));
        self.status_event();
        Ok(())
    }
    fn persist_session_start(
        &self,
        pid: u32,
        image_name: &str,
        label: AgentLabel,
        workspace: Option<PathBuf>,
    ) {
        let session = AgentSession {
            id: None,
            pid,
            image_name: image_name.to_string(),
            label,
            workspace,
            started_at: chrono::Utc::now(),
            ended_at: None,
        };
        if let Err(err) = self.store.start_session(&session) {
            eprintln!("[daemon] WARN: failed to persist session start PID={pid}: {err}");
        }
    }
    fn persist_session_end(&self, pid: u32) {
        if let Err(err) = self.store.end_session(pid) {
            eprintln!("[daemon] WARN: failed to persist session end PID={pid}: {err}");
        }
    }

    fn restore_projects(&self) -> GuardResult<()> { for p in self.store.list_projects()? { if p.path.exists() { if let Err(e) = self.register_project(p.path.clone()) { eprintln!("[daemon] WARN: restore project {} failed: {e}", p.path.display()); } } else { eprintln!("[daemon] WARN: project path missing on disk, skipping: {}", p.path.display()); } } Ok(()) }
    fn restore_global_rules(&self) -> GuardResult<()> { rebuild_global(self) }
}

fn rebuild_global(s: &DaemonState) -> GuardResult<()> {
    let rules = s.store.list_global_rules()?;
    if rules.is_empty() { *s.global_manifest.write().unwrap_or_else(|e| e.into_inner()) = None; return Ok(()); }
    let mut m = ProjectManifest::default();
    for r in &rules {
        let pat = expand(r.pattern.as_str()); match r.bucket { Bucket::Deny=>m.deny.files.push(pat), Bucket::Ask=>m.ask.files.push(pat), Bucket::Full=>m.full.files.push(pat), Bucket::Delete=>m.delete.files.push(pat), Bucket::Write=>m.write.files.push(pat), Bucket::Read=>m.read.files.push(pat) }
    }
    *s.global_manifest.write().unwrap_or_else(|e| e.into_inner()) = Some(CompiledManifest::compile(&m, PathBuf::new())?); Ok(())
}
fn rebuild_agent(s: &DaemonState, img: &str) -> GuardResult<()> {
    let rules = s.store.list_agent_rules(Some(img))?;
    let mut m = ProjectManifest::default();
    for r in &rules {
        let bucket = match r.bucket.as_str() {
            "deny" => Bucket::Deny,
            "ask" => Bucket::Ask,
            "full" => Bucket::Full,
            "delete" => Bucket::Delete,
            "write" => Bucket::Write,
            "read" => Bucket::Read,
            _ => { eprintln!("[daemon] WARN: unknown bucket '{}' in agent rule, skipping", r.bucket); continue; }
        };
        let pat = expand(&r.pattern);
        match bucket { Bucket::Deny=>m.deny.files.push(pat), Bucket::Ask=>m.ask.files.push(pat), Bucket::Full=>m.full.files.push(pat), Bucket::Delete=>m.delete.files.push(pat), Bucket::Write=>m.write.files.push(pat), Bucket::Read=>m.read.files.push(pat) }
    }
    let compiled = CompiledManifest::compile(&m, PathBuf::new())?;
    eprintln!("[daemon] Agent manifest rebuilt for '{}': {} deny, {} ask, {} write, {} delete, {} read patterns",
        img, m.deny.files.len(), m.ask.files.len(), m.write.files.len(), m.delete.files.len(), m.read.files.len());
    s.agent_manifests.write().unwrap_or_else(|e| e.into_inner()).insert(img.to_string(), compiled);
    Ok(())
}
fn restore_agent_rules(s: &DaemonState) -> GuardResult<()> {
    let rules = s.store.list_agent_rules(None)?;
    let mut images: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in &rules { images.insert(r.agent_image.clone()); }
    let mut new_manifests: HashMap<String, CompiledManifest> = HashMap::new();
    for img in &images {
        let img_rules: Vec<_> = rules.iter().filter(|r| r.agent_image == *img).collect();
        let mut m = ProjectManifest::default();
        for r in &img_rules {
            let bucket = match r.bucket.as_str() {
                "deny" => Bucket::Deny, "ask" => Bucket::Ask, "full" => Bucket::Full,
                "delete" => Bucket::Delete, "write" => Bucket::Write, "read" => Bucket::Read,
                _ => continue,
            };
            let pat = expand(&r.pattern);
            match bucket { Bucket::Deny=>m.deny.files.push(pat), Bucket::Ask=>m.ask.files.push(pat), Bucket::Full=>m.full.files.push(pat), Bucket::Delete=>m.delete.files.push(pat), Bucket::Write=>m.write.files.push(pat), Bucket::Read=>m.read.files.push(pat) }
        }
        new_manifests.insert(img.clone(), CompiledManifest::compile(&m, PathBuf::new())?);
    }
    *s.agent_manifests.write().unwrap_or_else(|e| e.into_inner()) = new_manifests;
    eprintln!("[daemon] Restored {} agent manifests from DB", images.len());
    Ok(())
}
fn eval_global(s: &DaemonState, p: &Path, op: &FileOp) -> (PolicyDecision, PolicySource) {
    if let Some(ref c) = *s.global_manifest.read().unwrap_or_else(|e| e.into_inner()) { let (d,_)=c.evaluate(p, op); return (d,PolicySource::Global); }
    (PolicyDecision::Allow, PolicySource::Default)
}
fn eval_agent(s: &DaemonState, p: &Path, op: &FileOp, agent_image: &str) -> (PolicyDecision, PolicySource) {
    if let Some(manifest) = s.agent_manifests.read().unwrap_or_else(|e| e.into_inner()).get(agent_image) {
        let (d, _) = manifest.evaluate(p, op);
        if d != PolicyDecision::Allow { return (d, PolicySource::Agent); }
    }
    (PolicyDecision::Allow, PolicySource::Default)
}
fn emit_health(s: &DaemonState, ws: &Path, enforcer: &Arc<RwLock<agentguard_enforce::Enforcer>>, manifest: &CompiledManifest) {
    if let Ok(a) = recover_enforcer_read!(enforcer).audit_project_protections(manifest) {
        let t=a.len(); let h=a.iter().filter(|x|x.health.healthy()).count(); let e=a.iter().filter(|x|x.health.content_deny&&x.health.metadata_deny).count();
        let w: Vec<_> = if t == 0 { vec!["0 deny paths found in workspace — Phylax is not actively blocking any files".into()] } else if e<t { vec![format!("{}/{} deny paths effective", e, t)] } else { vec![] };
        s.emit(IpcResponse::ProtectionReport(agentguard_ipc::ProtectionReportData { schema_version:1, workspace:ws.to_path_buf(), total_deny_paths:t, healthy_paths:h, effective_deny_paths:e,
            unhealthy_paths: a.into_iter().filter(|x|!x.health.healthy()).map(|x| agentguard_ipc::ProtectionPathHealth { path:x.path, exists:x.health.exists, content_deny:x.health.content_deny, metadata_deny:x.health.metadata_deny, effective_deny:x.health.content_deny&&x.health.metadata_deny, healthy:x.health.healthy() }).collect(), warnings: w }));
    }
}

fn hash_file(p: &Path) -> GuardResult<String> {
    let b = std::fs::read(p).map_err(|e| agentguard_core::GuardError::EnforcementFailed{path:p.display().to_string(),reason:e.to_string()})?;
    let mut h:u64=0xcbf29ce484222325; for byte in b { h^=byte as u64; h=h.wrapping_mul(0x100000001b3); } Ok(format!("{h:016x}"))
}
fn normalize(p: PathBuf) -> PathBuf { match std::fs::canonicalize(&p) { Ok(x) => strip(x), Err(_) => if p.is_absolute() {p} else { std::env::current_dir().map(|c|c.join(&p)).unwrap_or(p) } } }
fn strip(p: PathBuf) -> PathBuf { let s=p.to_string_lossy(); if let Some(x)=s.strip_prefix("\\\\?\\") { PathBuf::from(x) } else { p } }
fn is_in_ws(p: &Path, ws: &Path) -> bool { std::fs::canonicalize(p).map(|c| strip(c).starts_with(ws)).unwrap_or(false) }
fn expand(pat: &str) -> String { if pat.contains('\\')||pat.contains('/')||pat.contains("**") { pat.to_string() } else { format!("**/{pat}") } }
fn with_toml<T>(enf: &Arc<RwLock<agentguard_enforce::Enforcer>>, tp: &Path, assume: bool, read: impl FnOnce()->GuardResult<T>) -> GuardResult<T> {
    let had = match agentguard_enforce::ace::verify_ace(tp) { Ok(h) => h.content_deny||h.metadata_deny, Err(_) => assume };
    if had { recover_enforcer_write!(enf).temporarily_allow(tp)?; }
    let r = read();
    if had { if let Err(e)=recover_enforcer_write!(enf).reapply_ask(tp) { if r.is_ok() { return Err(e); } } }
    r
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*; use agentguard_manifest::MANDATORY_DENY_PATTERNS; use tempfile::TempDir;
    fn setup(d: &TempDir) -> (DaemonState, broadcast::Receiver<IpcResponse>) {
        let (stx,_)=mpsc::channel(1); let (etx,erx)=broadcast::channel(1024); (DaemonState::new(&d.path().join("t.db"),stx,etx).unwrap(), erx)
    }
    #[test] fn mandatory_injected() { let mut m=ProjectManifest::default(); enforce_mandatory_denies(&mut m); for p in MANDATORY_DENY_PATTERNS { assert!(m.deny.files.iter().any(|x|x==p)); } }
    #[test] fn mandatory_deduped() { let mut m=ProjectManifest::default(); m.deny.files.push(".env".into()); enforce_mandatory_denies(&mut m); assert_eq!(m.deny.files.iter().filter(|x|x.as_str()==".env").count(),1); }
    #[test] fn global_deny() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_global_rule(Bucket::Deny,"**/*.secret").unwrap(); assert_eq!(s.evaluate_access_dry_run(&PathBuf::from("/x/test.secret"),&FileOp::Read).unwrap(), PolicyDecision::Deny); }
    #[test] fn deny_beats_write() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_global_rule(Bucket::Write,"**/*.s").unwrap(); s.add_global_rule(Bucket::Deny,"**/*.s").unwrap(); assert_eq!(s.evaluate_access_dry_run(&PathBuf::from("/x/t.s"),&FileOp::Write).unwrap(), PolicyDecision::Deny); }
    #[test] fn toggle_rule() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_global_rule(Bucket::Deny,"**/*.s").unwrap(); assert_eq!(s.evaluate_access_dry_run(&PathBuf::from("/x/t.s"),&FileOp::Read).unwrap(), PolicyDecision::Deny); let id=s.store.list_global_rules().unwrap()[0].id.unwrap(); s.remove_global_rule(id).unwrap(); assert_eq!(s.evaluate_access_dry_run(&PathBuf::from("/x/t.s"),&FileOp::Read).unwrap(), PolicyDecision::Allow); }
    #[test] fn empty_allow() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); assert_eq!(s.evaluate_access_dry_run(&PathBuf::from("x"),&FileOp::Read).unwrap(), PolicyDecision::Allow); }
    #[test] fn no_rules_allow() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); assert_eq!(s.evaluate_access_dry_run(&PathBuf::from("/tmp/x.txt"),&FileOp::Read).unwrap(), PolicyDecision::Allow); }
    #[test] fn agent_rule() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("c.exe",Bucket::Deny,"*.env").unwrap(); assert_eq!(s.list_agent_rules(Some("c.exe")).unwrap().len(),1); }
    #[test] fn agent_rule_isolated() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("c.exe",Bucket::Deny,"*.env").unwrap(); assert!(s.list_agent_rules(Some("claude.exe")).unwrap().is_empty()); }
    #[test] fn remove_agent_rule() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("c.exe",Bucket::Deny,"*.env").unwrap(); let id=s.list_agent_rules(Some("c.exe")).unwrap()[0].id; s.remove_agent_rule(id).unwrap(); assert!(s.list_agent_rules(Some("c.exe")).unwrap().is_empty()); }
    #[test] fn agent_eval() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("cursor.exe",Bucket::Deny,"*.env").unwrap(); assert_eq!(s.evaluate_access_for_agent(&PathBuf::from("/x/.env"),&FileOp::Read,Some("cursor.exe")).unwrap(), PolicyDecision::Deny); assert_eq!(s.evaluate_access_for_agent(&PathBuf::from("/x/.env"),&FileOp::Read,Some("claude.exe")).unwrap(), PolicyDecision::Allow); assert_eq!(s.evaluate_access_dry_run(&PathBuf::from("/x/.env"),&FileOp::Read).unwrap(), PolicyDecision::Allow); }
    #[test] fn agent_deny_beats_global_write() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_global_rule(Bucket::Write,"*.env").unwrap(); s.add_agent_rule("cursor.exe",Bucket::Deny,"*.env").unwrap(); assert_eq!(s.evaluate_access_for_agent(&PathBuf::from("/x/.env"),&FileOp::Write,Some("cursor.exe")).unwrap(), PolicyDecision::Deny); assert_eq!(s.evaluate_access_for_agent(&PathBuf::from("/x/.env"),&FileOp::Write,None).unwrap(), PolicyDecision::Allow); }
    #[test] fn agent_rule_all_buckets() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("cursor.exe",Bucket::Ask,"*.ask_file").unwrap(); s.add_agent_rule("cursor.exe",Bucket::Write,"*.write_file").unwrap(); s.add_agent_rule("cursor.exe",Bucket::Delete,"*.delete_file").unwrap(); s.add_agent_rule("cursor.exe",Bucket::Read,"*.read_file").unwrap(); let rules=s.list_agent_rules(Some("cursor.exe")).unwrap(); assert_eq!(rules.len(),4); let buckets:Vec<_>=rules.iter().map(|r|r.bucket.clone()).collect(); assert!(buckets.contains(&"ask".to_string())); assert!(buckets.contains(&"write".to_string())); assert!(buckets.contains(&"delete".to_string())); assert!(buckets.contains(&"read".to_string())); }
    #[test] fn agent_rule_persistence_across_remove() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("cursor.exe",Bucket::Deny,"*.env").unwrap(); s.add_agent_rule("claude.exe",Bucket::Deny,"*.key").unwrap(); assert_eq!(s.list_agent_rules(Some("cursor.exe")).unwrap().len(),1); assert_eq!(s.list_agent_rules(Some("claude.exe")).unwrap().len(),1); let cursor_id=s.list_agent_rules(Some("cursor.exe")).unwrap()[0].id; s.remove_agent_rule(cursor_id).unwrap(); assert!(s.list_agent_rules(Some("cursor.exe")).unwrap().is_empty()); assert_eq!(s.list_agent_rules(Some("claude.exe")).unwrap().len(),1,"claude.exe rules must survive cursor.exe removal"); }
    #[test] fn agent_decision_source_is_agent() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("cursor.exe",Bucket::Deny,"*.env").unwrap(); let d=s.evaluate_access_for_agent(&PathBuf::from("/x/.env"),&FileOp::Read,Some("cursor.exe")).unwrap(); assert_eq!(d,PolicyDecision::Deny); let agents=s.agent_manifests.read().unwrap(); assert!(agents.contains_key("cursor.exe")); assert!(agents["cursor.exe"].deny_count()>0); }
    #[test] fn agent_priority_over_global() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_global_rule(Bucket::Full,"*.shared").unwrap(); s.add_agent_rule("cursor.exe",Bucket::Deny,"*.shared").unwrap(); assert_eq!(s.evaluate_access_for_agent(&PathBuf::from("/x/a.shared"),&FileOp::Read,Some("cursor.exe")).unwrap(), PolicyDecision::Deny); assert_eq!(s.evaluate_access_for_agent(&PathBuf::from("/x/a.shared"),&FileOp::Read,None).unwrap(), PolicyDecision::Allow); }
    #[test] fn agent_unknown_image_falls_through() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_global_rule(Bucket::Deny,"*.secret").unwrap(); assert_eq!(s.evaluate_access_for_agent(&PathBuf::from("/x/t.secret"),&FileOp::Read,Some("unknown.exe")).unwrap(), PolicyDecision::Deny); }
    #[test] fn agent_startup_restore() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); s.add_agent_rule("cursor.exe",Bucket::Deny,"*.env").unwrap(); let (stx,_)=mpsc::channel(1); let (etx,_)=broadcast::channel(1024); let s2=DaemonState::new(&t.path().join("t2.db"),stx,etx).unwrap(); s2.add_agent_rule("cursor.exe",Bucket::Deny,"*.env").unwrap(); assert_eq!(s2.list_agent_rules(Some("cursor.exe")).unwrap().len(),1); assert_eq!(s2.evaluate_access_for_agent(&PathBuf::from("/x/.env"),&FileOp::Read,Some("cursor.exe")).unwrap(), PolicyDecision::Deny); }
    #[test] fn ask_lifecycle() { let t=TempDir::new().unwrap(); let (s,mut rx)=setup(&t); let id=s.emit_ask_prompt(AgentLabel::Definite,200,Path::new("/tmp/x.env"),FileOp::Read); assert!(id>0); rx.try_recv().unwrap(); s.process_ask_response(id,true,false).unwrap(); assert!(s.process_ask_response(id,false,false).is_err()); }
    #[test] fn ask_remember() { let t=TempDir::new().unwrap(); let (s,mut rx)=setup(&t); let id=s.emit_ask_prompt(AgentLabel::Definite,300,Path::new("/tmp/x.pem"),FileOp::Write); rx.try_recv().unwrap(); s.process_ask_response(id,false,true).unwrap(); }
    #[test] fn ask_double() { let t=TempDir::new().unwrap(); let (s,mut rx)=setup(&t); let id=s.emit_ask_prompt(AgentLabel::Definite,400,Path::new("/tmp/x.yaml"),FileOp::Delete); rx.try_recv().unwrap(); s.process_ask_response(id,true,false).unwrap(); assert!(s.process_ask_response(id,false,false).is_err()); }
    #[test] fn status_event() { let t=TempDir::new().unwrap(); let (s,mut rx)=setup(&t); s.status_event(); rx.try_recv().unwrap(); }
    #[test] fn system_msg_event() { let t=TempDir::new().unwrap(); let (s,mut rx)=setup(&t); s.system_msg("warn","test"); rx.try_recv().unwrap(); }
    #[test] fn reload_unregistered() { let t=TempDir::new().unwrap(); let (s,_)=setup(&t); assert!(s.reload_project(&PathBuf::from("/nonexistent")).is_err()); }
    #[test]
    fn ask_response_emits_audit_event_and_persists() {
        let t = TempDir::new().unwrap();
        let (s, mut rx) = setup(&t);
        let id = s.emit_ask_prompt(AgentLabel::Definite, 555, Path::new("/tmp/x.env"), FileOp::Read);
        let _ = rx.try_recv();
        s.process_ask_response(id, false, false).unwrap();

        let mut saw_audit = false;
        while let Ok(msg) = rx.try_recv() {
            if let IpcResponse::Event(StreamingEvent::AuditEvent(view)) = msg {
                saw_audit = true;
                assert_eq!(view.agent_pid, 555);
                assert_eq!(view.decision, "deny");
                break;
            }
        }
        assert!(saw_audit, "expected streamed AuditEvent");
        let recent = s.store.recent_audit_events(1).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].agent_pid, 555);
    }

    #[test]
    fn process_events_persist_sessions_to_store() {
        let t = TempDir::new().unwrap();
        let (s, _) = setup(&t);
        let info = agentguard_probe::ProcessInfo {
            pid: 777,
            image_name: "cursor.exe".into(),
            session_id: 0,
            cmdline: String::new(),
            env_vars: vec![],
            has_window: false,
            parent_pid: None,
        };
        s.on_process_event(&agentguard_probe::ProcessEvent::Started(info));
        assert_eq!(s.store.active_sessions().unwrap().len(), 1);
        s.on_process_event(&agentguard_probe::ProcessEvent::Exited(777));
        assert!(s.store.active_sessions().unwrap().is_empty());
    }
}
