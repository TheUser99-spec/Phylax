//! AgentGuard TUI
//!
//! Dark terminal dashboard for local AI file safety.
//! Tab-based: Home | Activity | Projects

use agentguard_core::AgentLabel;
use agentguard_ipc::{
    ActiveAgent, AuditEventView, DaemonStatus, DashboardStats, GlobalRuleInfo, IpcClient,
    IpcResponse, PolicyData, ProjectInfo, StreamingEvent,
};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::ExecutableCommand;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, Wrap};
use ratatui::Frame;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_RECENT_EVENTS: usize = 200;

// ── Theme ───────────────────────────────────

mod t {
    use ratatui::style::Color;
    pub const BG: Color = Color::Rgb(15, 15, 15);
    pub const CARD: Color = Color::Rgb(22, 23, 22);
    pub const CARD_ALT: Color = Color::Rgb(28, 29, 28);
    pub const HIGHLIGHT: Color = Color::Rgb(36, 38, 37);
    pub const DIVIDER: Color = Color::Rgb(38, 40, 38);
    pub const BORDER: Color = Color::Rgb(50, 54, 52);
    pub const TEXT: Color = Color::Rgb(235, 233, 226);
    pub const SOFT: Color = Color::Rgb(165, 163, 156);
    pub const MUTED: Color = Color::Rgb(92, 91, 86);
    pub const GREEN: Color = Color::Rgb(108, 218, 163);
    pub const GREEN_DIM: Color = Color::Rgb(18, 66, 44);
    pub const YELLOW: Color = Color::Rgb(230, 192, 103);
    pub const YELLOW_DIM: Color = Color::Rgb(70, 55, 20);
    pub const RED: Color = Color::Rgb(239, 108, 108);
    pub const RED_DIM: Color = Color::Rgb(76, 28, 32);
    pub const CYAN: Color = Color::Rgb(110, 195, 220);
    pub const CYAN_DIM: Color = Color::Rgb(22, 58, 68);
    pub const MAGENTA: Color = Color::Rgb(180, 133, 215);
    pub const KEY: Color = Color::Rgb(42, 45, 43);
}

// ── Enums ───────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tone { Good, Warn, Danger, Info, Muted }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionKind { Allow, Ask, Deny, Other }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectionPosture { Protected, NeedsSetup, NeedsDecision, Offline }

// ── Data structs ────────────────────────────

struct AskPromptData {
    request_id: u64,
    agent_label: String,
    file_path: String,
    operation: String,
}

struct Toast {
    message: String,
    level: String,
    created: Instant,
}

struct ActiveAgentGroup {
    image_name: String,
    label: AgentLabel,
    #[allow(dead_code)]
    workspace: Option<PathBuf>,
    pids: Vec<u32>,
    #[allow(dead_code)]
    started_at: i64,
}

// ── App ─────────────────────────────────────

struct App {
    client: IpcClient,
    tabs: Vec<&'static str>,
    active_tab: usize,
    version: String,
    projects: Vec<ProjectInfo>,
    active_agents: Vec<ActiveAgent>,
    recent_events: Vec<AuditEventView>,
    events_today: u64,
    blocks_today: u64,
    active_agent_process_count: usize,
    projects_count: usize,
    running: bool,
    error: Option<String>,
    connected: bool,
    pending_ask: Option<AskPromptData>,
    stats: Option<DashboardStats>,
    toasts: Vec<Toast>,
    project_policy: Option<PolicyData>,
    selected_project: Option<PathBuf>,
    global_rules: Vec<GlobalRuleInfo>,
    search_query: String,
    search_active: bool,
    system_messages: Vec<String>,
    tick: u64,
    sort_desc: bool,
    selected_event_idx: Option<usize>,
    last_stats_fetch: Instant,
    last_policy_fetch: Instant,
    last_rules_fetch: Instant,
    policy_fetching: bool,
    rules_fetching: bool,
}

impl App {
    fn new() -> Self {
        let past = Instant::now() - Duration::from_secs(60);
        Self {
            client: IpcClient::new(),
            tabs: vec!["Home", "Activity", "Projects"],
            active_tab: 0,
            version: String::new(),
            projects: Vec::new(),
            active_agents: Vec::new(),
            recent_events: Vec::new(),
            events_today: 0,
            blocks_today: 0,
            active_agent_process_count: 0,
            projects_count: 0,
            running: true,
            error: None,
            connected: false,
            pending_ask: None,
            stats: None,
            toasts: Vec::new(),
            project_policy: None,
            selected_project: None,
            global_rules: Vec::new(),
            search_query: String::new(),
            search_active: false,
            system_messages: Vec::new(),
            tick: 0,
            sort_desc: true,
            selected_event_idx: None,
            last_stats_fetch: past,
            last_policy_fetch: past,
            last_rules_fetch: past,
            policy_fetching: false,
            rules_fetching: false,
        }
    }

    // ── Event Loop ──────────────────────────

    async fn run(&mut self) -> io::Result<()> {
        let mut terminal =
            ratatui::Terminal::new(ratatui::backend::CrosstermBackend::new(io::stdout()))?;

        match self.client.get_status().await {
            Ok(s) => { self.apply_status(s); self.connected = true; }
            Err(e) => self.error = Some(format!("Daemon: {e}")),
        }

        let mut event_rx: Option<tokio::sync::mpsc::Receiver<IpcResponse>> =
            match self.client.subscribe_events().await {
                Ok(rx) => { self.error = None; Some(rx) }
                Err(e) => { self.error = Some(format!("Stream unavailable: {e}")); None }
            };

        let key_tick = Duration::from_millis(50);
        let mut last_poll = tokio::time::Instant::now();
        let mut last_data = tokio::time::Instant::now();

        while self.running {
            self.tick = self.tick.wrapping_add(1);

            self.toasts.retain(|t| {
                let age = if t.level == "error" || t.level == "warn" { 8 } else { 5 };
                t.created.elapsed() < Duration::from_secs(age)
            });
            if self.toasts.len() > 5 { self.toasts.remove(0); }

            terminal.draw(|f| self.draw(f))?;

            if event::poll(key_tick).unwrap_or(false) {
                if let Ok(Event::Key(key)) = event::read() {
                    if key.kind == KeyEventKind::Press {
                        if self.search_active {
                            self.handle_search_key(key.code);
                        } else {
                            self.handle_key(key.code);
                        }
                    }
                }
            }

            if let Some(ref mut rx) = event_rx {
                while let Ok(event) = rx.try_recv() { self.handle_streaming(event); }
            }

            let refresh = if event_rx.is_some() { Duration::from_secs(5) } else { Duration::from_millis(800) };
            if last_poll.elapsed() >= refresh {
                match self.client.get_status().await {
                    Ok(s) => { self.apply_status(s); self.connected = true; self.error = None; }
                    Err(e) => {
                        if event_rx.is_none() { self.connected = false; }
                        self.error = Some(format!("Daemon: {e}"));
                    }
                }
                last_poll = tokio::time::Instant::now();
            }

            if last_data.elapsed() >= Duration::from_secs(30) {
                if self.active_tab == 0 && (self.stats.is_none() || self.last_stats_fetch.elapsed() >= Duration::from_secs(30)) {
                    if let Ok(r) = self.client.send(agentguard_ipc::IpcRequest::GetStats).await {
                        if let IpcResponse::Stats(s) = r {
                            self.stats = Some(s);
                            self.last_stats_fetch = Instant::now();
                        }
                    }
                }
                if self.active_tab == 2 {
                    self.fetch_project_policy().await;
                    self.fetch_global_rules().await;
                }
                last_data = tokio::time::Instant::now();
            }
        }
        Ok(())
    }

    // ── IPC ────────────────────────────────

    fn apply_status(&mut self, s: DaemonStatus) {
        self.version = s.version;
        self.projects = s.projects;
        self.active_agents = s.active_agents;
        self.active_agent_process_count = self.active_agents.len();
        self.projects_count = self.projects.len();
        self.events_today = s.events_today;
        self.blocks_today = s.blocks_today;
        self.recent_events = s.recent_events;
        let has = self.selected_project.as_ref()
            .is_some_and(|sel| self.projects.iter().any(|p| &p.path == sel));
        if !has {
            self.selected_project = self.projects.first().map(|p| p.path.clone());
            self.project_policy = None;
            self.last_policy_fetch = Instant::now() - Duration::from_secs(60);
        }
    }

    fn handle_streaming(&mut self, resp: IpcResponse) {
        match resp {
            IpcResponse::Event(event) => match event {
                StreamingEvent::AuditEvent(view) => {
                    if view.decision == "deny" {
                        self.add_toast("error", format!("BLOCKED: {} {} {}",
                            friendly_agent_label(&view.agent_label),
                            operation_name(&view.operation),
                            file_leaf(&view.file_path)));
                    }
                    self.recent_events.insert(0, view);
                    self.recent_events.truncate(MAX_RECENT_EVENTS);
                }
                StreamingEvent::AgentDetected(agent) => {
                    self.add_toast("warn", format!("Detected: {} (PID={})", agent.image_name, agent.pid));
                    if !self.active_agents.iter().any(|a| a.pid == agent.pid) {
                        self.active_agents.push(agent);
                    }
                    self.active_agent_process_count = self.active_agents.len();
                }
                StreamingEvent::AgentExited { pid } => {
                    self.active_agents.retain(|a| a.pid != pid);
                    self.active_agent_process_count = self.active_agents.len();
                }
                StreamingEvent::StatusUpdate { events_today, blocks_today, active_agents_count, projects_count } => {
                    self.events_today = events_today;
                    self.blocks_today = blocks_today;
                    self.active_agent_process_count = active_agents_count;
                    self.projects_count = projects_count;
                }
                StreamingEvent::SystemMessage { message, level, timestamp: _ } => {
                    self.add_toast(&level, message.clone());
                    self.system_messages.insert(0, format!("[{}] {}", level.to_uppercase(), message));
                    self.system_messages.truncate(50);
                }
                StreamingEvent::AskPrompt { request_id, agent_label, file_path, operation } => {
                    self.pending_ask = Some(AskPromptData { request_id, agent_label, file_path, operation });
                }
            },
            _ => {}
        }
    }

    fn add_toast(&mut self, level: &str, message: String) {
        self.toasts.push(Toast { message, level: level.to_string(), created: Instant::now() });
    }

    fn send_ask_response(&mut self, allowed: bool, remember: bool) {
        if let Some(a) = self.pending_ask.take() {
            let c = self.client.clone();
            let rid = a.request_id;
            tokio::spawn(async move {
                let _ = c.send(agentguard_ipc::IpcRequest::AskResponse { request_id: rid, allowed, remember }).await;
            });
        }
    }

    async fn fetch_project_policy(&mut self) {
        self.policy_fetching = true;
        if let Some(ref path) = self.selected_project {
            if let Ok(r) = self.client.send(agentguard_ipc::IpcRequest::GetPolicy { path: path.clone() }).await {
                if let IpcResponse::Policy(p) = r { self.project_policy = Some(p); }
            }
        } else { self.project_policy = None; }
        self.last_policy_fetch = Instant::now();
        self.policy_fetching = false;
    }

    async fn fetch_global_rules(&mut self) {
        self.rules_fetching = true;
        if let Ok(r) = self.client.send(agentguard_ipc::IpcRequest::ListGlobalRules).await {
            if let IpcResponse::GlobalRulesList(d) = r { self.global_rules = d.rules; }
        }
        self.last_rules_fetch = Instant::now();
        self.rules_fetching = false;
    }

    // ── Helpers ─────────────────────────────

    fn posture(&self) -> ProtectionPosture {
        if !self.connected { ProtectionPosture::Offline }
        else if self.pending_ask.is_some() { ProtectionPosture::NeedsDecision }
        else if self.projects_count == 0 { ProtectionPosture::NeedsSetup }
        else { ProtectionPosture::Protected }
    }

    fn is_live(&self) -> bool { self.connected && self.error.is_none() }

    fn agent_groups(&self) -> Vec<ActiveAgentGroup> {
        let mut map: HashMap<(String, AgentLabel, Option<PathBuf>), ActiveAgentGroup> = HashMap::new();
        for a in &self.active_agents {
            let k = (a.image_name.to_lowercase(), a.label, a.workspace.clone());
            let e = map.entry(k).or_insert_with(|| ActiveAgentGroup {
                image_name: a.image_name.clone(), label: a.label,
                workspace: a.workspace.clone(), pids: vec![], started_at: a.started_at,
            });
            e.pids.push(a.pid);
            e.started_at = e.started_at.min(a.started_at);
        }
        let mut v: Vec<_> = map.into_values().map(|mut g| { g.pids.sort_unstable(); g }).collect();
        v.sort_by(|a, b| label_rank(a.label).cmp(&label_rank(b.label)).then_with(|| a.image_name.cmp(&b.image_name)));
        v
    }

    #[allow(dead_code)]
    fn agent_count(&self) -> usize { self.agent_groups().len() }

    fn filtered_events(&self) -> Vec<&AuditEventView> {
        let mut v: Vec<&AuditEventView> = self.recent_events.iter().filter(|e| {
            if !self.search_query.is_empty() {
                let q = self.search_query.to_lowercase();
                let hay = format!("{} {} {} {} {} {} {}", e.agent_label,
                    friendly_agent_label(&e.agent_label), e.agent_pid,
                    e.operation, e.decision, e.source, e.file_path).to_lowercase();
                return hay.contains(&q);
            }
            true
        }).collect();
        if self.sort_desc { v.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); }
        else { v.sort_by(|a, b| a.timestamp.cmp(&b.timestamp)); }
        v
    }

    fn event_actor(&self, event: &AuditEventView) -> String {
        self.active_agents.iter().find(|a| a.pid == event.agent_pid)
            .map(|a| a.image_name.clone())
            .unwrap_or_else(|| friendly_agent_label(&event.agent_label).to_string())
    }

    fn next_action(&self) -> (&'static str, &'static str, Tone) {
        if !self.connected { ("connect", "Start the daemon first", Tone::Danger) }
        else if self.pending_ask.is_some() { ("approve", "Answer the pending request", Tone::Warn) }
        else if self.projects_count == 0 { ("setup", "Run `agentguard init` in a project", Tone::Warn) }
        else if self.blocks_today > 0 { ("review", "Check blocked files", Tone::Warn) }
        else { ("ready", "Everything looks good", Tone::Good) }
    }

    // ── Key Handling ────────────────────────

    fn handle_key(&mut self, code: KeyCode) {
        if self.pending_ask.is_some() {
            match code {
                KeyCode::Char('y') => self.send_ask_response(true, false),
                KeyCode::Char('n') | KeyCode::Esc => self.send_ask_response(false, false),
                KeyCode::Char('r') => self.send_ask_response(true, true),
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if self.selected_event_idx.is_some() { self.selected_event_idx = None; }
                else if self.search_active { self.search_active = false; self.search_query.clear(); }
                else { self.running = false; }
            }
            KeyCode::Char('Q') => self.running = false,
            KeyCode::Char('/') => { self.search_active = true; self.search_query.clear(); }
            KeyCode::Char('t') => { self.toasts.pop(); }
            KeyCode::Tab | KeyCode::Right => { self.active_tab = (self.active_tab + 1) % self.tabs.len(); }
            KeyCode::BackTab | KeyCode::Left => {
                if self.active_tab == 0 { self.active_tab = self.tabs.len() - 1; }
                else { self.active_tab -= 1; }
            }
            KeyCode::Char('1') => self.active_tab = 0,
            KeyCode::Char('2') => self.active_tab = 1,
            KeyCode::Char('3') => self.active_tab = 2,
            KeyCode::Char('[') if self.active_tab == 2 => self.prev_project(),
            KeyCode::Char(']') if self.active_tab == 2 => self.next_project(),
            KeyCode::Char('s') => self.sort_desc = !self.sort_desc,
            KeyCode::Enter => {
                let flen = self.filtered_events().len();
                if self.active_tab == 1 && flen > 0 {
                    self.selected_event_idx = match self.selected_event_idx {
                        None => Some(0), Some(i) if i + 1 < flen => Some(i + 1), _ => None,
                    };
                }
            }
            _ => {}
        }
    }

    fn handle_search_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => { self.search_active = false; self.search_query.clear(); }
            KeyCode::Enter => self.search_active = false,
            KeyCode::Backspace => { self.search_query.pop(); }
            KeyCode::Char(c) => { self.search_query.push(c); }
            _ => {}
        }
    }

    fn prev_project(&mut self) {
        if self.projects.is_empty() { self.selected_project = None; self.project_policy = None; return; }
        let idx = self.selected_project.as_ref()
            .and_then(|p| self.projects.iter().position(|x| &x.path == p)).unwrap_or(0);
        let nxt = if idx == 0 { self.projects.len() - 1 } else { idx - 1 };
        self.selected_project = Some(self.projects[nxt].path.clone());
        self.project_policy = None;
        self.last_policy_fetch = Instant::now() - Duration::from_secs(60);
    }

    fn next_project(&mut self) {
        if self.projects.is_empty() { self.selected_project = None; self.project_policy = None; return; }
        let idx = self.selected_project.as_ref()
            .and_then(|p| self.projects.iter().position(|x| &x.path == p)).unwrap_or(0);
        let nxt = (idx + 1) % self.projects.len();
        self.selected_project = Some(self.projects[nxt].path.clone());
        self.project_policy = None;
        self.last_policy_fetch = Instant::now() - Duration::from_secs(60);
    }

    // ── Main Draw ───────────────────────────

    fn draw(&self, f: &mut Frame) {
        f.render_widget(Clear, f.area());
        let bg = Block::default().style(Style::default().bg(t::BG));
        f.render_widget(bg, f.area());

        let area = f.area();
        let outer = Block::default()
            .borders(Borders::ALL)
            .border_set(symbols::border::ROUNDED)
            .border_style(Style::default().fg(t::BORDER));
        let inner = outer.inner(area);
        f.render_widget(outer, area);

        let v = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(4), Constraint::Length(2), Constraint::Min(0), Constraint::Length(1)])
            .split(inner);

        self.draw_header(f, v[0]);
        self.draw_tabs(f, v[1]);
        self.draw_body(f, v[2]);
        self.draw_footer(f, v[3]);

        if self.pending_ask.is_some() { self.draw_ask_modal(f); }
        if !self.toasts.is_empty() { self.draw_toasts(f); }
    }

    // ── Header ──────────────────────────────

    fn draw_header(&self, f: &mut Frame, area: Rect) {
        let posture = self.posture();
        let dot = match posture {
            ProtectionPosture::Protected => Span::styled("●", Style::default().fg(t::GREEN)),
            ProtectionPosture::NeedsSetup | ProtectionPosture::NeedsDecision =>
                Span::styled("●", Style::default().fg(t::YELLOW)),
            ProtectionPosture::Offline => Span::styled("○", Style::default().fg(t::RED)),
        };
        let live = if self.is_live() {
            Span::styled(" LIVE ", Style::default().fg(t::GREEN).add_modifier(Modifier::BOLD))
        } else {
            Span::styled(" OFFLINE ", Style::default().fg(t::RED).add_modifier(Modifier::BOLD))
        };
        let now = chrono::Local::now().format("%H:%M:%S").to_string();

        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        let left = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(" AgentGuard ", Style::default().fg(t::TEXT).add_modifier(Modifier::BOLD)),
                dot, Span::raw("  "), live,
                Span::styled("  WARDEN ZERO ", Style::default().fg(t::MUTED)),
            ]),
            Line::from(vec![Span::styled(" OS-level file safety for AI coding agents", Style::default().fg(t::MUTED))]),
        ]);
        f.render_widget(left, top[0]);

        let right = Paragraph::new(vec![
            Line::from(vec![Span::styled(format!("v{}  {}", self.version, now), Style::default().fg(t::SOFT))])
                .alignment(Alignment::Right),
            Line::from(vec![
                Span::styled("projects ", Style::default().fg(t::MUTED)),
                Span::styled(self.projects_count.to_string(), Style::default().fg(t::CYAN).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled("agents ", Style::default().fg(t::MUTED)),
                Span::styled(self.active_agent_process_count.to_string(), Style::default().fg(t::MAGENTA).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled("blocks ", Style::default().fg(t::MUTED)),
                Span::styled(self.blocks_today.to_string(), Style::default().fg(t::RED).add_modifier(Modifier::BOLD)),
            ]).alignment(Alignment::Right),
        ]);
        f.render_widget(right, top[1]);
    }

    // ── Tabs ────────────────────────────────

    fn draw_tabs(&self, f: &mut Frame, area: Rect) {
        let mut spans = Vec::new();
        for (i, tab) in self.tabs.iter().enumerate() {
            if i > 0 { spans.push(Span::styled("  │  ", Style::default().fg(t::DIVIDER))); }
            if i == self.active_tab {
                spans.push(Span::styled(format!(" {tab} "),
                    Style::default().fg(t::TEXT).bg(t::HIGHLIGHT).add_modifier(Modifier::BOLD)));
            } else {
                spans.push(Span::styled(format!(" {tab} "), Style::default().fg(t::MUTED)));
            }
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    // ── Body dispatcher ─────────────────────

    fn draw_body(&self, f: &mut Frame, area: Rect) {
        match self.active_tab {
            0 => self.draw_home(f, area),
            1 => self.draw_activity(f, area),
            2 => self.draw_projects(f, area),
            _ => {}
        }
    }

    // ── Home Tab ────────────────────────────

    fn draw_home(&self, f: &mut Frame, area: Rect) {
        let sections = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(10), Constraint::Min(0)])
            .split(area);

        let top = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(sections[0]);
        let bottom = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(sections[1]);

        self.draw_home_overview(f, top[0]);
        self.draw_home_agents(f, top[1]);
        self.draw_home_activity(f, bottom[0]);
        self.draw_home_rules(f, bottom[1]);
    }

    fn draw_home_overview(&self, f: &mut Frame, area: Rect) {
        let posture = self.posture();
        let (headline, desc, tone) = match posture {
            ProtectionPosture::Protected => ("Safe to code", "AgentGuard is watching this workspace.", Tone::Good),
            ProtectionPosture::NeedsSetup => ("Add a project", "Run `agentguard init` to protect a workspace.", Tone::Warn),
            ProtectionPosture::NeedsDecision => ("Approval needed", "An agent is waiting for your answer.", Tone::Warn),
            ProtectionPosture::Offline => ("Not connected", "Start the AgentGuard daemon first.", Tone::Danger),
        };
        let (_, next_label, next_tone) = self.next_action();
        let selected = self.selected_project.as_ref()
            .and_then(|p| p.file_name().and_then(std::ffi::OsStr::to_str).map(|s| s.to_string()))
            .unwrap_or_else(|| "none".into());

        let lines = vec![
            Line::from(vec![chip(headline, tone), Span::raw("  "), Span::styled(desc, Style::default().fg(t::SOFT))]),
            Line::from(""),
            Line::from(vec![Span::styled("  project  ", Style::default().fg(t::MUTED)), Span::styled(selected, Style::default().fg(t::TEXT))]),
            Line::from(vec![Span::styled("  today    ", Style::default().fg(t::MUTED)),
                Span::styled(format!("{} events, {} blocked", self.events_today, self.blocks_today), Style::default().fg(t::SOFT))]),
            Line::from(vec![Span::styled("  next     ", Style::default().fg(t::MUTED)),
                Span::styled(next_label, Style::default().fg(tone_fg(next_tone)).add_modifier(Modifier::BOLD))]),
        ];
        f.render_widget(Paragraph::new(Text::from(lines)).block(card(" Status ")), area);
    }

    fn draw_home_agents(&self, f: &mut Frame, area: Rect) {
        let groups = self.agent_groups();
        if groups.is_empty() {
            let txt = vec![
                Line::from(vec![Span::styled("  ◆  No active AI agents", Style::default().fg(t::MUTED))]),
                Line::from(vec![Span::styled("  Start Claude, OpenCode, or Cursor in a watched project", Style::default().fg(t::MUTED))]),
            ];
            f.render_widget(Paragraph::new(Text::from(txt)).block(card(" Agents ")), area);
            return;
        }
        let items: Vec<ListItem> = groups.iter().map(|g| {
            let (_, fg, label) = agent_chip(g.label);
            let pids = g.pids.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(label, Style::default().bg(t::RED_DIM).fg(fg).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(&g.image_name, Style::default().fg(t::TEXT).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("PID:{}", truncate(&pids, 12)), Style::default().fg(t::CYAN)),
            ]))
        }).collect();
        f.render_widget(List::new(items).block(card(&format!(" Agents ({}) ", groups.len()))), area);
    }

    fn draw_home_activity(&self, f: &mut Frame, area: Rect) {
        let events: Vec<&AuditEventView> = self.recent_events.iter()
            .filter(|e| matches!(decision_kind(&e.decision), DecisionKind::Deny | DecisionKind::Ask))
            .take(6).collect();

        if events.is_empty() {
            let txt = vec![Line::from(vec![Span::styled("  ◆  No high-priority events yet", Style::default().fg(t::MUTED))])];
            f.render_widget(Paragraph::new(Text::from(txt)).block(card(" Recent Decisions ")), area);
            return;
        }
        let items: Vec<ListItem> = events.iter().map(|e| {
            let icon = match decision_kind(&e.decision) {
                DecisionKind::Deny => "✗", DecisionKind::Ask => "⚠", _ => "◆"
            };
            ListItem::new(Line::from(vec![
                Span::raw("  "), Span::styled(format!("{} ", format_time(e.timestamp)), Style::default().fg(t::MUTED)),
                Span::styled(icon, Style::default().fg(icon_color(decision_kind(&e.decision)))),
                Span::raw("  "), Span::styled(operation_name(&e.operation), Style::default().fg(t::SOFT)),
                Span::raw("  "), Span::styled(file_leaf(&e.file_path), Style::default().fg(t::CYAN)),
            ]))
        }).collect();
        f.render_widget(List::new(items).block(card(" Recent Decisions ")), area);
    }

    fn draw_home_rules(&self, f: &mut Frame, area: Rect) {
        let Some(proj) = self.selected_project.as_ref()
            .and_then(|p| self.projects.iter().find(|x| &x.path == p))
        else {
            f.render_widget(Paragraph::new(vec![Line::from(vec![Span::styled("  ◆  No project selected", Style::default().fg(t::MUTED))])])
                .block(card(" Project Rules ")), area);
            return;
        };
        let lines = vec![
            Line::from(vec![
                Span::raw("  "),
                badge(" blocked ", t::RED_DIM, t::RED), Span::raw(" "),
                Span::styled(proj.deny_count.to_string(), Style::default().fg(t::RED).add_modifier(Modifier::BOLD)),
                Span::raw("    "),
                badge(" ask first ", t::YELLOW_DIM, t::YELLOW), Span::raw(" "),
                Span::styled(proj.ask_count.to_string(), Style::default().fg(t::YELLOW).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::raw("  "),
                badge(" can edit ", t::GREEN_DIM, t::GREEN), Span::raw(" "),
                Span::styled(proj.write_count.to_string(), Style::default().fg(t::GREEN).add_modifier(Modifier::BOLD)),
                Span::raw("    "),
                badge(" can read ", t::CYAN_DIM, t::CYAN), Span::raw(" "),
                Span::styled(proj.read_count.to_string(), Style::default().fg(t::CYAN).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled("  ▼  Open Projects tab to inspect all rules", Style::default().fg(t::MUTED))]),
        ];
        f.render_widget(Paragraph::new(Text::from(lines)).block(card(" Project Rules ")).wrap(Wrap { trim: true }), area);
    }

    // ── Activity Tab ────────────────────────

    fn draw_activity(&self, f: &mut Frame, area: Rect) {
        let filtered = self.filtered_events();
        let has_detail = self.selected_event_idx.is_some();

        let title = format!(" Activity ({}) - {} / {} ",
            filtered.len(),
            if self.sort_desc { "newest" } else { "oldest" },
            if self.search_query.is_empty() { "all" } else { "filtered" });

        if !self.system_messages.is_empty() {
            let parts = Layout::default().direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0)]).split(area);
            let msgs: Vec<Line> = self.system_messages.iter().take(2).map(|m| {
                Line::from(vec![Span::styled("  ⚠ ", Style::default().fg(t::YELLOW)), Span::styled(m, Style::default().fg(t::SOFT))])
            }).collect();
            f.render_widget(Paragraph::new(Text::from(msgs)).block(card(" System Messages ")), parts[0]);
            self.draw_events_table(f, parts[1], &filtered, &title, has_detail);
        } else {
            self.draw_events_table(f, area, &filtered, &title, has_detail);
        }
    }

    fn draw_events_table(&self, f: &mut Frame, area: Rect, filtered: &[&AuditEventView], title: &str, has_detail: bool) {
        let table_area = if has_detail {
            let parts = Layout::default().direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(9)]).split(area);
            let sel = self.selected_event_idx.unwrap_or(0);
            if let Some(event) = filtered.get(sel) {
                self.draw_event_detail(f, event, parts[1]);
            }
            parts[0]
        } else { area };

        if filtered.is_empty() {
            let txt = vec![
                Line::from(vec![Span::raw("  "), Span::styled(
                    format!("events: {}  |  blocks: {}", self.events_today, self.blocks_today),
                    Style::default().fg(t::MUTED))]),
                Line::from(""),
                Line::from(vec![Span::styled("  ◆  No matching events. Press / to search.", Style::default().fg(t::MUTED))]),
            ];
            f.render_widget(Paragraph::new(Text::from(txt)).block(card(title)), table_area);
            return;
        }

        let header = Row::new(vec!["TIME", "VERDICT", "AGENT", "ACTION", "FILE"])
            .style(Style::default().fg(t::MUTED).add_modifier(Modifier::BOLD));

        let rows = filtered.iter().enumerate().map(|(i, e)| {
            let (fg, bg, label) = verdict_chip(&e.decision);
            let rs = if Some(i) == self.selected_event_idx {
                Style::default().bg(t::HIGHLIGHT)
            } else { Style::default() };
            Row::new(vec![
                Cell::from(format_time(e.timestamp)),
                Cell::from(Span::styled(label, Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD))),
                Cell::from(truncate(&self.event_actor(e), 14)),
                Cell::from(operation_name(&e.operation)),
                Cell::from(file_leaf(&e.file_path)),
            ]).style(rs)
        });

        let widths = [Constraint::Length(9), Constraint::Length(12), Constraint::Length(16), Constraint::Length(8), Constraint::Min(12)];
        f.render_widget(Table::new(rows, widths).header(header).column_spacing(1).block(card(title)), table_area);
    }

    fn draw_event_detail(&self, f: &mut Frame, event: &AuditEventView, area: Rect) {
        let (fg, _, label) = verdict_chip(&event.decision);
        let source = match event.source.as_str() {
            "global" | "global_rule" => "Global rule",
            "project" | "manifest" => "Project rules",
            "default" => "Default policy",
            s => s,
        };
        let dk = decision_kind(&event.decision);
        let what = match dk {
            DecisionKind::Deny => "Access blocked before agent touched the file.",
            DecisionKind::Ask => "Policy paused — waiting for your decision.",
            DecisionKind::Allow => "Policy allowed the operation.",
            DecisionKind::Other => "An event was recorded.",
        };
        let next = match dk {
            DecisionKind::Deny => "Check Projects > blocked rules or global rules to adjust.",
            DecisionKind::Ask => "Respond once, then save as project rule if recurring.",
            DecisionKind::Allow => "No action needed unless path looks wrong.",
            DecisionKind::Other => "Check logs if unexpected.",
        };
        let lines = vec![
            Line::from(vec![Span::raw("  "), Span::styled(label, Style::default().fg(fg).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("{} ▸ {}", operation_name(&event.operation), truncate(&event.file_path, 60)), Style::default().fg(t::TEXT))]),
            Line::from(vec![Span::styled("  what   ", Style::default().fg(t::MUTED)), Span::styled(what, Style::default().fg(t::SOFT))]),
            Line::from(vec![Span::styled("  source ", Style::default().fg(t::MUTED)), Span::styled(source, Style::default().fg(t::SOFT))]),
            Line::from(vec![Span::styled("  agent  ", Style::default().fg(t::MUTED)),
                Span::styled(format!("{}  PID:{}", friendly_agent_label(&event.agent_label), event.agent_pid), Style::default().fg(t::MAGENTA))]),
            Line::from(vec![Span::styled("  next   ", Style::default().fg(t::MUTED)), Span::styled(next, Style::default().fg(t::SOFT))]),
            Line::from(vec![Span::styled("  help   ", Style::default().fg(t::MUTED)),
                Span::styled("enter: next event  esc: close  /: search  s: sort", Style::default().fg(t::MUTED))]),
        ];
        f.render_widget(Paragraph::new(Text::from(lines)).block(card(" Event Detail ")).wrap(Wrap { trim: true }), area);
    }

    // ── Projects Tab ────────────────────────

    fn draw_projects(&self, f: &mut Frame, area: Rect) {
        if self.projects.is_empty() {
            let txt = vec![
                Line::from(""),
                Line::from(vec![Span::styled("    ◆  No registered projects.", Style::default().fg(t::MUTED))]),
                Line::from(vec![Span::styled("    Run `agentguard init` inside a workspace to start protection.", Style::default().fg(t::MUTED))]),
            ];
            f.render_widget(Paragraph::new(Text::from(txt)).block(card(" Projects ")), area);
            return;
        }
        let v = Layout::default().direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(0), Constraint::Length(6)])
            .split(area);
        let h = Layout::default().direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
            .split(v[0]);

        // Project list
        let items: Vec<ListItem> = self.projects.iter().map(|p| {
            let sel = self.selected_project.as_ref().is_some_and(|x| x == &p.path);
            let marker = if sel { "▸" } else { " " };
            let style = if sel { Style::default().fg(t::YELLOW).add_modifier(Modifier::BOLD) } else { Style::default().fg(t::MUTED) };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {marker} "), style),
                Span::styled(p.path.file_name().and_then(|n| n.to_str()).unwrap_or("?"), Style::default().fg(t::TEXT).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format!("blocked:{}", p.deny_count), Style::default().fg(t::RED)),
                Span::raw(" "),
                Span::styled(format!("ask:{}", p.ask_count), Style::default().fg(t::YELLOW)),
                Span::raw(" "),
                Span::styled(format!("edit:{}", p.write_count), Style::default().fg(t::GREEN)),
                Span::raw(" "),
                Span::styled(format!("read:{}", p.read_count), Style::default().fg(t::CYAN)),
            ]))
        }).collect();
        f.render_widget(List::new(items).block(card(&format!(" Projects ({}) [switch with [ ] ", self.projects.len()))), h[0]);

        // Project identity
        if let Some(proj) = self.selected_project.as_ref().and_then(|p| self.projects.iter().find(|x| &x.path == p)) {
            let txt = vec![
                Line::from(vec![Span::raw("  "), chip("selected", Tone::Info), Span::raw("  registered")]),
                Line::from(""),
                Line::from(vec![Span::styled("  folder  ", Style::default().fg(t::MUTED)),
                    Span::styled(truncate(&proj.path.display().to_string(), 60), Style::default().fg(t::TEXT))]),
            ];
            f.render_widget(Paragraph::new(Text::from(txt)).block(card(" Selected ")), h[1]);
        } else {
            f.render_widget(Paragraph::new("  No project selected").block(card(" Selected ")), h[1]);
        }

        self.draw_policy_panel(f, v[1]);
        self.draw_global_rules(f, v[2]);
    }

    fn draw_policy_panel(&self, f: &mut Frame, area: Rect) {
        let Some(policy) = &self.project_policy else {
            let txt = if self.policy_fetching {
                vec![Line::from(vec![Span::styled(format!("  {} Loading rules...", self.spinner()), Style::default().fg(t::MUTED))])]
            } else {
                vec![Line::from(vec![Span::styled("  ◆  Select a project to view its rules", Style::default().fg(t::MUTED))])]
            };
            f.render_widget(Paragraph::new(Text::from(txt)).block(card(" Project Rules ")), area);
            return;
        };
        let header = Row::new(vec!["BUCKET", "COUNT", "MEANING", "PATTERNS"])
            .style(Style::default().fg(t::MUTED).add_modifier(Modifier::BOLD));
        let rows = policy_rows(policy).into_iter().map(|b| {
            let preview = if b.patterns.is_empty() { "—".to_string() }
                else { b.patterns.iter().take(3).cloned().collect::<Vec<_>>().join(", ") };
            Row::new(vec![
                Cell::from(Span::styled(b.label, Style::default().fg(tone_fg(b.tone)).add_modifier(Modifier::BOLD))),
                Cell::from(b.count.to_string()),
                Cell::from(b.meaning),
                Cell::from(preview),
            ])
        });
        f.render_widget(Table::new(rows, [Constraint::Length(12), Constraint::Length(7), Constraint::Length(22), Constraint::Min(16)])
            .header(header).column_spacing(1).block(card(" Project Rules ")), area);
    }

    fn draw_global_rules(&self, f: &mut Frame, area: Rect) {
        if self.global_rules.is_empty() {
            f.render_widget(Paragraph::new("  ◆  No global rules. They apply to every project.").block(card(" Global Rules ")), area);
            return;
        }
        let items: Vec<ListItem> = self.global_rules.iter().map(|r| {
            let (tone, label) = bucket_label(&r.bucket);
            ListItem::new(Line::from(vec![
                Span::raw("  "),
                Span::styled(label, Style::default().fg(tone_fg(tone)).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(&r.pattern, Style::default().fg(t::SOFT)),
            ]))
        }).collect();
        f.render_widget(List::new(items).block(card(&format!(" Global Rules ({}) ", self.global_rules.len()))), area);
    }

    // ── Footer ──────────────────────────────

    fn draw_footer(&self, f: &mut Frame, area: Rect) {
        let (_, next_label, next_tone) = self.next_action();
        let mut spans = vec![
            key(" Q "), Span::styled(" quit  ", Style::default().fg(t::MUTED)),
            key(" 1 "), Span::raw(" home "),
            key(" 2 "), Span::raw(" activity "),
            key(" 3 "), Span::raw(" projects  "),
            Span::styled("│", Style::default().fg(t::DIVIDER)),
            key(" / "), Span::styled(" search  ", Style::default().fg(t::MUTED)),
            key(" Enter "), Span::styled(" inspect  ", Style::default().fg(t::MUTED)),
            Span::styled("│", Style::default().fg(t::DIVIDER)),
            Span::styled(" next: ", Style::default().fg(t::MUTED)),
            Span::styled(next_label, Style::default().fg(tone_fg(next_tone)).add_modifier(Modifier::BOLD)),
        ];
        if self.active_tab == 2 {
            spans.push(Span::raw("  "));
            spans.push(key(" [ ] "));
            spans.push(Span::styled(" switch project", Style::default().fg(t::MUTED)));
        }
        if self.search_active || !self.search_query.is_empty() {
            spans.push(Span::raw("  │  "));
            spans.push(Span::styled(format!("filter: {}", self.search_query), Style::default().fg(t::YELLOW)));
        }
        if let Some(e) = &self.error {
            spans.push(Span::raw("  │  "));
            spans.push(Span::styled(e, Style::default().fg(t::RED)));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    // ── Ask Modal ───────────────────────────

    fn draw_ask_modal(&self, f: &mut Frame) {
        let ask = match &self.pending_ask { Some(a) => a, None => return };
        let area = f.area();
        let w = area.width.min(64).max(48);
        let h = 9u16;
        let x = (area.width - w) / 2;
        let y = (area.height - h) / 2;
        let modal = Rect::new(x, y, w, h);

        let lines = vec![
            Line::from(vec![Span::styled("  ▸  Agent wants to use a protected file  ", Style::default().fg(t::YELLOW).add_modifier(Modifier::BOLD))]),
            Line::from(""),
            Line::from(vec![Span::raw("  "), Span::styled(friendly_agent_label(&ask.agent_label), Style::default().fg(t::MAGENTA)),
                Span::raw(format!(" wants to {}:", operation_name(&ask.operation)))]),
            Line::from(vec![Span::raw("  "), Span::styled(truncate(&ask.file_path, 56), Style::default().fg(t::CYAN).add_modifier(Modifier::BOLD))]),
            Line::from(""),
            Line::from(vec![key(" y "), Span::raw(" allow once   "), key(" n "), Span::raw(" block   "), key(" r "), Span::raw(" remember")]),
            Line::from(vec![Span::styled("  esc ", Style::default().fg(t::TEXT).bg(t::CARD_ALT)),
                Span::styled(" blocks    ", Style::default().fg(t::MUTED)),
                Span::styled(format!("#{}", ask.request_id), Style::default().fg(t::MUTED))]),
        ];
        let p = Paragraph::new(Text::from(lines))
            .block(Block::default().borders(Borders::ALL).border_set(symbols::border::ROUNDED)
                .border_style(Style::default().fg(t::YELLOW)).style(Style::default().bg(t::BG)))
            .style(Style::default().bg(t::BG));
        f.render_widget(p, modal);
    }

    // ── Toasts ──────────────────────────────

    fn draw_toasts(&self, f: &mut Frame) {
        let area = f.area();
        let w = 42u16;
        let h = 3u16;
        for (i, toast) in self.toasts.iter().rev().take(5).enumerate() {
            let y = area.y + 1 + (i as u16 * (h + 1));
            let x = area.width.saturating_sub(w + 2);
            let r = Rect::new(x, y, w, h);
            let (color, icon) = match toast.level.as_str() {
                "error" => (t::RED, "✗"), "warn" => (t::YELLOW, "⚠"), "success" => (t::GREEN, "✓"), _ => (t::CYAN, "◆"),
            };
            let lines = vec![
                Line::from(vec![Span::styled(format!(" {} ", icon), Style::default().fg(color).add_modifier(Modifier::BOLD)), Span::styled(&toast.message, Style::default().fg(t::TEXT))]),
                Line::from(""),
                Line::from(vec![Span::styled("  press t to dismiss  ", Style::default().fg(t::MUTED))]),
            ];
            f.render_widget(Clear, r);
            f.render_widget(Paragraph::new(Text::from(lines))
                .block(Block::default().borders(Borders::ALL).border_set(symbols::border::ROUNDED).border_style(Style::default().fg(color))), r);
        }
    }

    fn spinner(&self) -> &str {
        const CHARS: &[&str] = &["◐", "◓", "◑", "◒"];
        CHARS[(self.tick / 2) as usize % CHARS.len()]
    }
}

// ── Entrypoint ──────────────────────────────

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut app = App::new();
    enable_raw_mode()?;
    io::stdout().execute(crossterm::terminal::EnterAlternateScreen)?;
    let result = app.run().await;
    disable_raw_mode()?;
    io::stdout().execute(crossterm::terminal::LeaveAlternateScreen)?;
    result
}

// ── Helpers: Styling ─────────────────────────

fn card(title: &str) -> Block<'static> {
    Block::default()
        .title(title.to_string())
        .borders(Borders::TOP)
        .border_set(symbols::border::ROUNDED)
        .border_style(Style::default().fg(t::BORDER))
        .style(Style::default().bg(t::CARD))
}

fn tone_fg(tone: Tone) -> Color {
    match tone {
        Tone::Good => t::GREEN, Tone::Warn => t::YELLOW,
        Tone::Danger => t::RED, Tone::Info => t::CYAN, Tone::Muted => t::MUTED,
    }
}

fn tone_bg(tone: Tone) -> Color {
    match tone {
        Tone::Good => t::GREEN_DIM, Tone::Warn => t::YELLOW_DIM,
        Tone::Danger => t::RED_DIM, Tone::Info => t::CYAN_DIM, Tone::Muted => t::CARD_ALT,
    }
}

fn icon_color(kind: DecisionKind) -> Color {
    match kind {
        DecisionKind::Deny => t::RED, DecisionKind::Ask => t::YELLOW,
        DecisionKind::Allow => t::GREEN, DecisionKind::Other => t::CYAN,
    }
}

fn chip(label: &str, tone: Tone) -> Span<'static> {
    Span::styled(format!(" {label} "), Style::default().fg(t::TEXT).bg(tone_bg(tone)).add_modifier(Modifier::BOLD))
}

fn badge(label: &str, bg: Color, fg: Color) -> Span<'static> {
    Span::styled(format!(" {label} "), Style::default().bg(bg).fg(fg).add_modifier(Modifier::BOLD))
}

fn key(label: &'static str) -> Span<'static> {
    Span::styled(label, Style::default().fg(t::TEXT).bg(t::KEY).add_modifier(Modifier::BOLD))
}

// ── Helpers: Data ───────────────────────────

fn format_time(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "--:--:--".into())
}

fn operation_name(op: &str) -> String {
    match op.to_ascii_lowercase().as_str() {
        "read" => "read".into(), "write" => "edit".into(), "delete" => "delete".into(), s => s.to_string(),
    }
}

fn file_leaf(path: &str) -> String {
    let n = path.replace('\\', "/");
    n.rsplit('/').find(|p| !p.is_empty()).unwrap_or(path).to_string()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("...{}", &s[s.len().saturating_sub(max - 3)..]) }
}

fn decision_kind(d: &str) -> DecisionKind {
    match d.to_ascii_lowercase().as_str() {
        "allow" | "allowed" => DecisionKind::Allow,
        "ask" | "asked" => DecisionKind::Ask,
        "deny" | "denied" | "block" | "blocked" => DecisionKind::Deny,
        _ => DecisionKind::Other,
    }
}

fn verdict_chip(decision: &str) -> (Color, Color, &'static str) {
    match decision_kind(decision) {
        DecisionKind::Deny => (t::TEXT, t::RED_DIM, " BLOCKED "),
        DecisionKind::Ask => (t::TEXT, t::YELLOW_DIM, " ASK "),
        DecisionKind::Allow => (t::TEXT, t::GREEN_DIM, " ALLOWED "),
        DecisionKind::Other => (t::TEXT, t::CARD_ALT, " EVENT "),
    }
}

fn friendly_agent_label(label: &str) -> &'static str {
    match label.to_ascii_lowercase().as_str() {
        "definite" => "ai agent", "probable" => "likely ai",
        "inherited" => "child process", "human" => "human", _ => "agent",
    }
}

fn agent_chip(label: AgentLabel) -> (Color, Color, &'static str) {
    match label {
        AgentLabel::Definite => (t::RED, t::TEXT, " ai agent "),
        AgentLabel::Probable => (t::YELLOW, t::TEXT, " likely ai "),
        AgentLabel::Inherited => (t::CYAN, t::TEXT, " child "),
        AgentLabel::Human => (t::CARD_ALT, t::TEXT, " human "),
    }
}

fn label_rank(label: AgentLabel) -> u8 {
    match label {
        AgentLabel::Definite => 0, AgentLabel::Probable => 1,
        AgentLabel::Inherited => 2, AgentLabel::Human => 3,
    }
}

fn bucket_label(bucket: &str) -> (Tone, &'static str) {
    match bucket.to_ascii_lowercase().as_str() {
        "deny" | "block" => (Tone::Danger, "Blocked"),
        "ask" => (Tone::Warn, "Ask first"),
        "write" => (Tone::Good, "Can edit"),
        "read" => (Tone::Info, "Can read"),
        "delete" => (Tone::Warn, "Can delete"),
        "full" => (Tone::Good, "Full access"),
        _ => (Tone::Muted, "Other"),
    }
}

struct PolicyRow {
    label: &'static str,
    tone: Tone,
    meaning: &'static str,
    patterns: Vec<String>,
    count: usize,
}

fn policy_rows(p: &PolicyData) -> Vec<PolicyRow> {
    vec![
        PolicyRow { label: "Blocked", tone: Tone::Danger, meaning: "Never allowed", patterns: p.deny.clone(), count: p.deny.len() },
        PolicyRow { label: "Ask first", tone: Tone::Warn, meaning: "Approval needed", patterns: p.ask.clone(), count: p.ask.len() },
        PolicyRow { label: "Full access", tone: Tone::Good, meaning: "No restrictions", patterns: p.full.clone(), count: p.full.len() },
        PolicyRow { label: "Can delete", tone: Tone::Warn, meaning: "Read & remove", patterns: p.delete.clone(), count: p.delete.len() },
        PolicyRow { label: "Can edit", tone: Tone::Good, meaning: "Read & modify", patterns: p.write.clone(), count: p.write.len() },
        PolicyRow { label: "Can read", tone: Tone::Info, meaning: "Read only", patterns: p.read.clone(), count: p.read.len() },
    ]
}

// ── Tests ───────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn empty_status() -> DaemonStatus {
        DaemonStatus { running: true, version: "0.1.0".into(), projects: vec![], active_agents: vec![],
            events_today: 0, blocks_today: 0, recent_events: vec![] }
    }

    fn sample_project(path: &str) -> ProjectInfo {
        ProjectInfo { path: PathBuf::from(path), toml_hash: "h".into(), added_at: 1,
            deny_count: 1, ask_count: 2, write_count: 3, delete_count: 4, read_count: 5 }
    }

    fn sample_event() -> AuditEventView {
        AuditEventView { id: 1, agent_pid: 10, agent_label: "DEFINITE".into(), file_path: "/tmp/.env".into(),
            operation: "read".into(), decision: "deny".into(), source: "project".into(), timestamp: 1 }
    }

    fn sample_policy() -> PolicyData {
        PolicyData { project_name: "test".into(), default_mode: "conservative".into(),
            deny: vec![".env".into()], ask: vec!["Cargo.lock".into()], full: vec![],
            delete: vec!["target/**".into()], write: vec!["src/**".into()], read: vec!["README.md".into()] }
    }

    fn sample_agent(pid: u32, image_name: &str) -> ActiveAgent {
        ActiveAgent { pid, image_name: image_name.into(), label: AgentLabel::Definite,
            workspace: Some(PathBuf::from("C:/work")), started_at: pid as i64 }
    }

    fn populated_app() -> App {
        let mut app = App::new();
        let mut s = empty_status();
        s.version = "0.1.0".into();
        s.projects = vec![sample_project("C:/work/test")];
        s.active_agents = vec![sample_agent(17612, "opencode.exe"), sample_agent(11688, "OpenCode.exe")];
        s.events_today = 3; s.blocks_today = 1;
        s.recent_events = vec![
            sample_event(),
            AuditEventView { id: 2, agent_pid: 10, agent_label: "DEFINITE".into(),
                file_path: "C:/work/test/src/main.rs".into(), operation: "write".into(), decision: "allow".into(),
                source: "project".into(), timestamp: 2 },
            AuditEventView { id: 3, agent_pid: 10, agent_label: "DEFINITE".into(),
                file_path: "C:/work/test/Cargo.lock".into(), operation: "read".into(), decision: "ask".into(),
                source: "project".into(), timestamp: 3 },
        ];
        app.apply_status(s);
        app.connected = true;
        app.project_policy = Some(sample_policy());
        app.global_rules = vec![GlobalRuleInfo { id: 1, bucket: "deny".into(), pattern: "*.secret".into(),
            created_at: "2026-05-30T00:00:00Z".into() }];
        app
    }

    fn render(app: &mut App, w: u16, h: u16) -> String {
        let backend = TestBackend::new(w, h);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        term.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    // ── Data tests ──────────────────────────

    #[test] fn decision_chips_are_semantic() {
        assert_eq!(decision_kind("deny"), DecisionKind::Deny);
        assert_eq!(decision_kind("ASK"), DecisionKind::Ask);
        assert_eq!(decision_kind("allow"), DecisionKind::Allow);
        assert_eq!(verdict_chip("deny").2.trim(), "BLOCKED");
    }

    #[test] fn labels_are_translated() {
        assert_eq!(friendly_agent_label("DEFINITE"), "ai agent");
        assert_eq!(friendly_agent_label("INHERITED"), "child process");
        assert_eq!(agent_chip(AgentLabel::Definite).2.trim(), "ai agent");
    }

    #[test] fn agent_groups_collapse_pids() {
        let mut app = App::new();
        app.active_agents = vec![sample_agent(17612, "opencode.exe"), sample_agent(11688, "OpenCode.exe"), sample_agent(20000, "cursor.exe")];
        app.active_agent_process_count = 3;
        let groups = app.agent_groups();
        assert_eq!(groups.len(), 2);
        let og = groups.iter().find(|g| g.image_name.eq_ignore_ascii_case("opencode.exe")).unwrap();
        assert_eq!(og.pids, vec![11688, 17612]);
    }

    #[test] fn posture_tracks_state() {
        let mut app = App::new();
        assert_eq!(app.posture(), ProtectionPosture::Offline);
        app.connected = true; assert_eq!(app.posture(), ProtectionPosture::NeedsSetup);
        app.projects_count = 1; assert_eq!(app.posture(), ProtectionPosture::Protected);
        app.pending_ask = Some(AskPromptData { request_id: 1, agent_label: "DEFINITE".into(), file_path: ".env".into(), operation: "read".into() });
        assert_eq!(app.posture(), ProtectionPosture::NeedsDecision);
    }

    #[test] fn filtered_events_respects_query() {
        let mut app = populated_app();
        assert_eq!(app.filtered_events().len(), 3);
        app.search_query = ".env".to_string(); assert_eq!(app.filtered_events().len(), 1);
        app.search_query = "nonexistent".to_string(); assert_eq!(app.filtered_events().len(), 0);
    }

    #[test] fn next_action_prioritizes() {
        let mut app = App::new();
        assert_eq!(app.next_action().0, "connect");
        app.connected = true; assert_eq!(app.next_action().0, "setup");
        app.projects_count = 1; assert_eq!(app.next_action().0, "ready");
        app.blocks_today = 5; assert_eq!(app.next_action().0, "review");
    }

    // ── Key binding tests ───────────────────

    #[test] fn tabs_navigate_by_number() {
        let mut app = App::new();
        app.handle_key(KeyCode::Char('2')); assert_eq!(app.active_tab, 1);
        app.handle_key(KeyCode::Char('3')); assert_eq!(app.active_tab, 2);
    }

    #[test] fn enter_selects_event_in_activity() {
        let mut app = populated_app();
        app.active_tab = 0; app.handle_key(KeyCode::Enter); assert_eq!(app.selected_event_idx, None);
        app.active_tab = 1; app.handle_key(KeyCode::Enter); assert_eq!(app.selected_event_idx, Some(0));
        app.handle_key(KeyCode::Enter); assert_eq!(app.selected_event_idx, Some(1));
    }

    #[test] fn project_navigation_wraps() {
        let mut app = App::new();
        let mut s = empty_status();
        s.projects = vec![sample_project("C:/a"), sample_project("C:/b")];
        app.apply_status(s);
        assert_eq!(app.selected_project, Some(PathBuf::from("C:/a")));
        app.active_tab = 2;
        app.handle_key(KeyCode::Char(']')); assert_eq!(app.selected_project, Some(PathBuf::from("C:/b")));
        app.handle_key(KeyCode::Char('[')); assert_eq!(app.selected_project, Some(PathBuf::from("C:/a")));
    }

    // ── Render tests ────────────────────────

    #[test] fn brand_is_visible_at_top() {
        let mut app = populated_app();
        let content = render(&mut app, 120, 35);
        assert!(content.contains("AgentGuard"));
        assert!(content.contains("WARDEN ZERO"));
    }

    #[test] fn all_tabs_are_present() {
        for tab in 0..3 {
            let mut app = populated_app(); app.active_tab = tab;
            assert!(render(&mut app, 120, 35).contains("AgentGuard"));
        }
    }

    #[test] fn footer_shows_keybindings() {
        let mut app = populated_app();
        let content = render(&mut app, 120, 30);
        assert!(content.contains("quit"));
        assert!(content.contains("home"));
        assert!(content.contains("activity"));
        assert!(content.contains("projects"));
    }

    #[test] fn activity_shows_events() {
        let mut app = populated_app(); app.active_tab = 1;
        assert!(render(&mut app, 120, 35).contains(".env"));
    }

    #[test] fn ask_modal_is_plain_language() {
        let mut app = populated_app();
        app.pending_ask = Some(AskPromptData { request_id: 42, agent_label: "DEFINITE".into(),
            file_path: "C:/work/.env".into(), operation: "read".into() });
        let content = render(&mut app, 120, 35);
        assert!(content.contains("Agent wants to use a protected file"));
        assert!(content.contains("allow once"));
        assert!(content.contains("block"));
        assert!(content.contains("remember"));
        assert!(!content.contains("DEFINITE"));
    }

    #[test] fn theme_contrast_meets_wcag_aa() {
        let pairs = [(t::TEXT, t::BG), (t::TEXT, t::CARD), (t::TEXT, t::GREEN_DIM),
            (t::TEXT, t::YELLOW_DIM), (t::TEXT, t::RED_DIM), (t::GREEN, t::BG), (t::YELLOW, t::BG), (t::RED, t::BG)];
        for (fg, bg) in pairs {
            let l1 = lum(fg); let l2 = lum(bg);
            let (lt, dk) = if l1 >= l2 { (l1, l2) } else { (l2, l1) };
            let r = (lt + 0.05) / (dk + 0.05);
            assert!(r >= 4.5, "contrast {fg:?} on {bg:?} was {r:.2}");
        }
    }

    fn lum(c: Color) -> f64 {
        let (r, g, b) = match c { Color::Rgb(r, g, b) => (r, g, b), _ => panic!("expected RGB") };
        let ch = |v: u8| { let v = v as f64 / 255.0; if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) } };
        0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)
    }
}
