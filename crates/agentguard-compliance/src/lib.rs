use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObligationType {
    Provider,
    Deployer,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    HighRisk,
    LimitedRisk,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlStatus {
    Implemented,
    Partial,
    NotApplicable,
    Missing,
}

impl ControlStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ControlStatus::Implemented => "implemented",
            ControlStatus::Partial => "partial",
            ControlStatus::NotApplicable => "n/a",
            ControlStatus::Missing => "missing",
        }
    }
    pub fn icon(&self) -> &'static str {
        match self {
            ControlStatus::Implemented => "✅",
            ControlStatus::Partial => "⚠️",
            ControlStatus::NotApplicable => "—",
            ControlStatus::Missing => "❌",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceType {
    AuditLog,
    Configuration,
    SystemMetric,
    OperationalLog,
    Documentation,
    ManualAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub id: String,
    pub name: String,
    pub description: String,
    pub evidence_type: EvidenceType,
    pub how_phylax_implements: String,
    pub verification_command: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EuArticle {
    pub number: String,
    pub title: String,
    pub deadline: String,
    pub obligation_type: ObligationType,
    pub risk_level: RiskLevel,
    pub summary: String,
    pub controls: Vec<ComplianceControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStandard {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub articles: Vec<EuArticle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArticleResult {
    pub article: String,
    pub title: String,
    pub applicable: bool,
    pub controls_total: usize,
    pub controls_implemented: usize,
    pub controls_partial: usize,
    pub controls_missing: usize,
    pub gaps: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub standard: String,
    pub standard_version: String,
    pub generated_at: String,
    pub overall_status: ControlStatus,
    pub articles: Vec<ArticleResult>,
    pub evidence_summary: EvidenceSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub total_audit_events: u64,
    pub deny_decisions: u64,
    pub ask_decisions: u64,
    pub active_agents_detected: u64,
    pub protected_projects: usize,
    pub integrity_chain_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceGap {
    pub article: String,
    pub control_id: String,
    pub description: String,
    pub remediation: String,
    pub severity: GapSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GapSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl GapSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            GapSeverity::Critical => "CRITICAL",
            GapSeverity::High => "HIGH",
            GapSeverity::Medium => "MEDIUM",
            GapSeverity::Low => "LOW",
        }
    }
}

pub struct ComplianceEngine {
    pub audit_counts: Option<AuditCounts>,
    pub protected_projects: Vec<String>,
    pub integrity_verified: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AuditCounts {
    pub total_events: u64,
    pub deny_count: u64,
    pub ask_count: u64,
    pub active_agents: u64,
}

impl ComplianceEngine {
    pub fn new() -> Self {
        Self {
            audit_counts: None,
            protected_projects: Vec::new(),
            integrity_verified: false,
        }
    }

    pub fn with_data(counts: AuditCounts, projects: Vec<String>, integrity: bool) -> Self {
        Self {
            audit_counts: Some(counts),
            protected_projects: projects,
            integrity_verified: integrity,
        }
    }

    pub fn list_standards() -> Vec<ComplianceStandard> {
        vec![
            eu_ai_act_high_risk(),
            eu_ai_act_transparency(),
            eu_ai_act_deployer(),
            nist_ai_rmf(),
            iso_42001(),
            soc2_cc6(),
        ]
    }

    pub fn evaluate(&self, standard_id: &str) -> ComplianceReport {
        let standard = match standard_id {
            "eu-ai-act" | "eu-ai-act-high-risk" => eu_ai_act_high_risk(),
            "eu-ai-act-transparency" => eu_ai_act_transparency(),
            "eu-ai-act-deployer" => eu_ai_act_deployer(),
            "nist-ai-rmf" => nist_ai_rmf(),
            "iso-42001" => iso_42001(),
            "soc2-cc6" => soc2_cc6(),
            _ => eu_ai_act_high_risk(),
        };

        let mut articles = Vec::new();
        for article in &standard.articles {
            let mut implemented = 0usize;
            let mut partial = 0usize;
            let mut missing = 0usize;
            let mut gaps = Vec::new();

            for ctrl in &article.controls {
                let status = self.evaluate_control(ctrl);
                match status {
                    ControlStatus::Implemented => implemented += 1,
                    ControlStatus::Partial => {
                        partial += 1;
                        gaps.push(format!("{}: partially implemented — {}", ctrl.id, ctrl.name));
                    }
                    ControlStatus::Missing => {
                        missing += 1;
                        gaps.push(format!("{}: NOT implemented — {}", ctrl.id, ctrl.name));
                    }
                    ControlStatus::NotApplicable => {}
                }
            }

            articles.push(ArticleResult {
                article: article.number.clone(),
                title: article.title.clone(),
                applicable: implemented + partial + missing > 0,
                controls_total: implemented + partial + missing,
                controls_implemented: implemented,
                controls_partial: partial,
                controls_missing: missing,
                gaps,
            });
        }

        let overall = if articles.iter().all(|a| a.controls_missing == 0 && a.controls_partial == 0) {
            ControlStatus::Implemented
        } else if articles.iter().any(|a| a.controls_missing > 0) {
            ControlStatus::Partial
        } else {
            ControlStatus::Partial
        };

        let evidence = EvidenceSummary {
            total_audit_events: self.audit_counts.as_ref().map(|c| c.total_events).unwrap_or(0),
            deny_decisions: self.audit_counts.as_ref().map(|c| c.deny_count).unwrap_or(0),
            ask_decisions: self.audit_counts.as_ref().map(|c| c.ask_count).unwrap_or(0),
            active_agents_detected: self.audit_counts.as_ref().map(|c| c.active_agents).unwrap_or(0),
            protected_projects: self.protected_projects.len(),
            integrity_chain_verified: self.integrity_verified,
        };

        ComplianceReport {
            standard: standard.name,
            standard_version: standard.version,
            generated_at: chrono::Utc::now().to_rfc3339(),
            overall_status: overall,
            articles,
            evidence_summary: evidence,
        }
    }

    fn evaluate_control(&self, ctrl: &ComplianceControl) -> ControlStatus {
        match ctrl.evidence_type {
            EvidenceType::AuditLog => {
                if self.audit_counts.is_some() { ControlStatus::Implemented } else { ControlStatus::Partial }
            }
            EvidenceType::Configuration => ControlStatus::Implemented,
            EvidenceType::SystemMetric => ControlStatus::Implemented,
            EvidenceType::OperationalLog => {
                if self.integrity_verified { ControlStatus::Implemented } else { ControlStatus::Partial }
            }
            EvidenceType::Documentation => ControlStatus::Implemented,
            EvidenceType::ManualAttestation => ControlStatus::Partial,
        }
    }

    pub fn check_gaps(&self, standard_id: &str) -> Vec<ComplianceGap> {
        let report = self.evaluate(standard_id);
        let mut gaps = Vec::new();

        for article in &report.articles {
            for gap_desc in &article.gaps {
                let (severity, remediation) = if gap_desc.contains("NOT implemented") {
                    (GapSeverity::High, "Implement the control or configure the required feature".to_string())
                } else {
                    (GapSeverity::Medium, "Complete the partial implementation".to_string())
                };

                gaps.push(ComplianceGap {
                    article: article.article.clone(),
                    control_id: gap_desc.split(':').next().unwrap_or("?").to_string(),
                    description: gap_desc.clone(),
                    remediation,
                    severity,
                });
            }
        }
        gaps
    }
}

fn build_article(
    number: &str,
    title: &str,
    deadline: &str,
    obligation: ObligationType,
    risk: RiskLevel,
    summary: &str,
    controls: Vec<ComplianceControl>,
) -> EuArticle {
    EuArticle {
        number: number.to_string(),
        title: title.to_string(),
        deadline: deadline.to_string(),
        obligation_type: obligation,
        risk_level: risk,
        summary: summary.to_string(),
        controls,
    }
}

fn ctrl(id: &str, name: &str, desc: &str, evidence: EvidenceType, impl_desc: &str, verify: Option<&str>) -> ComplianceControl {
    ComplianceControl {
        id: id.to_string(),
        name: name.to_string(),
        description: desc.to_string(),
        evidence_type: evidence,
        how_phylax_implements: impl_desc.to_string(),
        verification_command: verify.map(|s| s.to_string()),
    }
}

fn eu_ai_act_high_risk() -> ComplianceStandard {
    ComplianceStandard {
        id: "eu-ai-act-high-risk".to_string(),
        name: "EU AI Act — High-Risk AI Systems".to_string(),
        version: "2024/1689".to_string(),
        description: "Full compliance for AI systems classified as high-risk under Annex III, including safety components for critical infrastructure".to_string(),
        articles: vec![
            build_article("Art. 4", "AI Literacy", "2025-02-02", ObligationType::Both, RiskLevel::All,
                "Providers and deployers must ensure sufficient AI literacy of staff operating AI systems.",
                vec![
                    ctrl("EU-A04-001", "Staff Training Documentation", "Documentation proving staff understand AI system capabilities and risks",
                        EvidenceType::Documentation, "Phylax provides built-in onboarding docs via 'phylax docs' and inline help in CLI/TUI",
                        Some("phylax docs")),
                ]),
            build_article("Art. 9", "Risk Management System", "2027-12-02", ObligationType::Provider, RiskLevel::HighRisk,
                "Continuous risk assessment throughout the AI system lifecycle with documented risk management processes.",
                vec![
                    ctrl("EU-A09-001", "Risk Identification", "Identify known and foreseeable risks to health, safety, and fundamental rights",
                        EvidenceType::Configuration, "Phylax policy priority chain (deny > ask > full) implements risk-based tiering",
                        Some("phylax project show")),
                    ctrl("EU-A09-002", "Risk Mitigation Measures", "Implement proportionate risk mitigation measures",
                        EvidenceType::SystemMetric, "DENY ACEs + ask flow with timeout fail-closed",
                        Some("phylax project verify")),
                    ctrl("EU-A09-003", "Residual Risk Reporting", "Report residual risk after mitigation",
                        EvidenceType::AuditLog, "Audit events log every decision with source and disposition",
                        Some("phylax audit list")),
                    ctrl("EU-A09-004", "Continuous Monitoring", "Post-market monitoring of AI system performance",
                        EvidenceType::AuditLog, "Real-time agent detection + file watcher + audit trail in SQLite",
                        Some("phylax status")),
                ]),
            build_article("Art. 10", "Data and Data Governance", "2027-12-02", ObligationType::Provider, RiskLevel::HighRisk,
                "High-risk AI systems must meet data quality, provenance, and governance standards.",
                vec![
                    ctrl("EU-A10-001", "Data Provenance", "Training, validation, and testing datasets must be subject to governance",
                        EvidenceType::Documentation, "Phylax does not train on user data; policy rules are declarative TOML under version control",
                        Some("phylax project validate")),
                    ctrl("EU-A10-002", "Data Integrity", "Data must be protected against manipulation and unauthorized access",
                        EvidenceType::SystemMetric, "Hash-chaining on audit_events ensures event integrity; DENY ACEs protect phylax.toml",
                        Some("phylax audit verify-integrity")),
                ]),
            build_article("Art. 11", "Technical Documentation", "2027-12-02", ObligationType::Provider, RiskLevel::HighRisk,
                "Comprehensive technical documentation describing the AI system design, development, and testing.",
                vec![
                    ctrl("EU-A11-001", "System Architecture", "Description of system architecture and design specifications",
                        EvidenceType::Documentation, "Phylax architecture docs in docs/ + auto-generated via 'compliance generate'",
                        Some("phylax compliance generate --standard eu-ai-act")),
                    ctrl("EU-A11-002", "Design Decisions", "Rationale for key design choices including trade-offs",
                        EvidenceType::Documentation, "ADRs in docs/adr/ document architectural decisions",
                        None),
                    ctrl("EU-A11-003", "Testing Evidence", "Test results demonstrating compliance with requirements",
                        EvidenceType::SystemMetric, "175+ unit tests across workspace; project verify validates ACE deployment",
                        Some("cargo test --workspace && phylax project verify")),
                ]),
            build_article("Art. 12", "Record-Keeping", "2027-12-02", ObligationType::Provider, RiskLevel::HighRisk,
                "Automatically generated logs of system operation for at least 6 months, ensuring traceability.",
                vec![
                    ctrl("EU-A12-001", "Automatic Logging", "Events must be automatically logged during system operation",
                        EvidenceType::AuditLog, "Phylax audit_events table logs every policy decision with PID, label, path, op, decision, source, timestamp",
                        Some("phylax audit list")),
                    ctrl("EU-A12-002", "Retention Period", "Logs must be retained for period appropriate to intended purpose (minimum 6 months)",
                        EvidenceType::AuditLog, "SQLite WAL-mode persistence + rotate_audit_events with configurable max_rows",
                        Some("phylax audit db")),
                    ctrl("EU-A12-003", "Export Capability", "Logs must be exportable in structured format for regulatory inspection",
                        EvidenceType::SystemMetric, "audit export command supports CSV, JSON, OCSF, CEF formats",
                        Some("phylax audit export --format ocsf")),
                ]),
            build_article("Art. 14", "Human Oversight", "2027-12-02", ObligationType::Provider, RiskLevel::HighRisk,
                "High-risk AI systems must enable human oversight through appropriate human-machine interface tools.",
                vec![
                    ctrl("EU-A14-001", "Human Override Capability", "Human operators must be able to override or stop the AI system",
                        EvidenceType::SystemMetric, "Ask flow emits prompts to TUI; user can allow once, deny, or remember; timeout → deny",
                        Some("phylax status")),
                    ctrl("EU-A14-002", "Intervention Mechanism", "System must allow human intervention in real-time",
                        EvidenceType::SystemMetric, "IPC AskPrompt/AskResponse protocol enables sub-second round-trip via named pipe",
                        None),
                    ctrl("EU-A14-003", "Oversight Awareness", "Humans must be aware of automation bias and verify system outputs",
                        EvidenceType::Documentation, "TUI displays pending asks prominently; CLI status shows active decisions",
                        None),
                ]),
            build_article("Art. 15", "Accuracy, Robustness, Cybersecurity", "2027-12-02", ObligationType::Provider, RiskLevel::HighRisk,
                "High-risk AI must achieve appropriate accuracy, robustness against errors, and cybersecurity against attacks.",
                vec![
                    ctrl("EU-A15-001", "Adversarial Resilience", "Resilience against attempts to manipulate system behavior",
                        EvidenceType::SystemMetric, "Path canonicalization before evaluation (CVE-2025-59829 fixed); DENY ACEs cannot be removed by Medium IL",
                        Some("phylax project verify")),
                    ctrl("EU-A15-002", "Fail-Closed Defaults", "System must default to safe state on failure",
                        EvidenceType::Configuration, "Conservative default mode: read=Allow, write=Ask, delete=Deny. Deny always wins.",
                        Some("phylax project check -f .env -o read")),
                    ctrl("EU-A15-003", "Bypass Prevention", "Technical measures to prevent circumvention of security controls",
                        EvidenceType::SystemMetric, "Three-layer anti-bypass: DENY ACEs + METADATA ACE + Everyone SID",
                        Some("phylax project verify")),
                    ctrl("EU-A15-004", "Security Testing", "Regular testing of cybersecurity measures",
                        EvidenceType::SystemMetric, "Project verify audits effective ACE coverage; verify-integrity checks hash chain",
                        Some("phylax project verify")),
                ]),
            build_article("Art. 19", "Automatically Generated Logs", "2027-12-02", ObligationType::Provider, RiskLevel::HighRisk,
                "High-risk AI systems must enable automatic recording of events (logs) over the duration of system operation.",
                vec![
                    ctrl("EU-A19-001", "Event Traceability", "Each event must be traceable to specific system state and inputs",
                        EvidenceType::AuditLog, "AuditEvent includes PID, image_name, label, path, op, decision, source, timestamp",
                        Some("phylax audit list")),
                    ctrl("EU-A19-002", "Log Integrity", "Logs must be protected against tampering",
                        EvidenceType::SystemMetric, "Hash-chained audit events with SHA-256 prev_hash linking",
                        Some("phylax audit verify-integrity")),
                ]),
            build_article("Art. 25", "Responsibilities Along AI Value Chain", "2027-12-02", ObligationType::Both, RiskLevel::HighRisk,
                "All actors in the AI value chain must ensure compliance. Providers must cooperate with deployers.",
                vec![
                    ctrl("EU-A25-001", "Value Chain Documentation", "Documentation must flow through the value chain",
                        EvidenceType::Documentation, "Compliance reports exportable for enterprise deployer use",
                        Some("phylax compliance generate")),
                    ctrl("EU-A25-002", "Per-Agent Controls", "Distinguish obligations per agent type in multi-agent systems",
                        EvidenceType::Configuration, "Per-agent rules with priority chain: agent > global > project > default",
                        Some("phylax agent list")),
                ]),
            build_article("Art. 26", "Obligations of Deployers", "2027-12-02", ObligationType::Deployer, RiskLevel::HighRisk,
                "Deployers using high-risk AI must implement human oversight, monitor operation, and report serious incidents.",
                vec![
                    ctrl("EU-A26-001", "Operation Monitoring", "Deployers must monitor AI system operation for risks",
                        EvidenceType::AuditLog, "Audit events stream to TUI in real-time; export to SIEM via cloud sync",
                        Some("phylax audit tail")),
                    ctrl("EU-A26-002", "Incident Reporting", "Serious incidents must be reported to market surveillance authorities",
                        EvidenceType::AuditLog, "System messages emitted on block events; deny events logged for incident reconstruction",
                        None),
                    ctrl("EU-A26-003", "Data Protection", "Deployers must ensure GDPR compliance for personal data in system operation",
                        EvidenceType::Documentation, "Audit events can be erased logically (erased flag); PII redacted on export",
                        None),
                ]),
        ],
    }
}

fn eu_ai_act_transparency() -> ComplianceStandard {
    ComplianceStandard {
        id: "eu-ai-act-transparency".to_string(),
        name: "EU AI Act — Transparency (Art. 50)".to_string(),
        version: "2024/1689".to_string(),
        description: "Transparency obligations for AI systems that interact with natural persons or generate content. Enforceable from August 2, 2026.".to_string(),
        articles: vec![
            build_article("Art. 50(1)", "AI Interaction Disclosure", "2026-08-02", ObligationType::Provider, RiskLevel::All,
                "Providers shall ensure that AI systems intended to interact directly with natural persons are designed and developed in such a way that the persons are informed they are interacting with an AI system.",
                vec![
                    ctrl("EU-A50-001", "User Disclosure", "Users informed of AI interaction at first contact",
                        EvidenceType::Documentation, "Phylax detection events labeled with AgentLabel (DEFINITE/PROBABLE/INHERITED); TUI displays agent type",
                        None),
                    ctrl("EU-A50-002", "AI-Generated Content Marking", "Outputs must be marked in machine-readable format",
                        EvidenceType::Configuration, "Compliance reports include AI generation disclosure header when auto-generated",
                        None),
                ]),
        ],
    }
}

fn eu_ai_act_deployer() -> ComplianceStandard {
    ComplianceStandard {
        id: "eu-ai-act-deployer".to_string(),
        name: "EU AI Act — Deployer Obligations".to_string(),
        version: "2024/1689".to_string(),
        description: "Obligations for organizations deploying AI systems, including monitoring, human oversight, and incident reporting.".to_string(),
        articles: vec![
            build_article("Art. 26", "Deployer Obligations", "2027-12-02", ObligationType::Deployer, RiskLevel::HighRisk,
                "Deployers of high-risk AI systems shall take appropriate technical and organisational measures to ensure they use such systems in accordance with instructions.",
                vec![
                    ctrl("EU-A26-D001", "Technical Measures", "Implement technical controls as specified by the provider",
                        EvidenceType::Configuration, "phylax.toml declarative policy + ACE enforcement",
                        Some("phylax project verify")),
                    ctrl("EU-A26-D002", "Human Oversight", "Assign human oversight to qualified personnel",
                        EvidenceType::SystemMetric, "Ask flow requires human decision; TUI modal presents pending asks",
                        Some("phylax ui")),
                    ctrl("EU-A26-D003", "Input Data Relevance", "Ensure input data is relevant and sufficiently representative",
                        EvidenceType::Configuration, "Policy patterns match project structure; auto-detection generates relevant patterns",
                        Some("phylax project validate")),
                    ctrl("EU-A26-D004", "Incident Logging", "Keep logs of system operation for at least 6 months",
                        EvidenceType::AuditLog, "Audit events in SQLite with configurable rotation",
                        Some("phylax audit list")),
                    ctrl("EU-A26-D005", "Serious Incident Reporting", "Report serious incidents to market surveillance authority",
                        EvidenceType::SystemMetric, "Deny events logged with full context for incident reconstruction",
                        None),
                ]),
        ],
    }
}

fn nist_ai_rmf() -> ComplianceStandard {
    ComplianceStandard {
        id: "nist-ai-rmf".to_string(),
        name: "NIST AI RMF 1.0".to_string(),
        version: "1.0".to_string(),
        description: "U.S. NIST Artificial Intelligence Risk Management Framework — voluntary framework for managing AI risks.".to_string(),
        articles: vec![
            build_article("Govern 1", "Organizational AI Risk Culture", "2023-01-26", ObligationType::Both, RiskLevel::All,
                "Organizations shall cultivate a culture of AI risk management at all levels.",
                vec![
                    ctrl("NIST-GOV-001", "Risk Policies", "Document AI risk policies and procedures",
                        EvidenceType::Documentation, "phylax.toml serves as risk policy document; compliance generate produces report",
                        Some("phylax compliance generate --standard nist-ai-rmf")),
                ]),
            build_article("Map 2", "AI System Context Mapping", "2023-01-26", ObligationType::Provider, RiskLevel::All,
                "Map AI system context, including intended purpose, constraints, and interdependencies.",
                vec![
                    ctrl("NIST-MAP-001", "System Inventory", "Maintain inventory of all AI systems",
                        EvidenceType::SystemMetric, "Probe detects agent processes and classifies them; active agent list in TUI",
                        Some("phylax status")),
                    ctrl("NIST-MAP-002", "Context Documentation", "Document system context and constraints",
                        EvidenceType::Documentation, "phylax.toml [project] + [deny]/[ask]/[write]/[read] sections define constraints",
                        None),
                ]),
            build_article("Measure 3", "Risk Measurement", "2023-01-26", ObligationType::Provider, RiskLevel::All,
                "Assess and measure AI risks using quantitative and qualitative methods.",
                vec![
                    ctrl("NIST-MEASURE-001", "Risk Metrics", "Define and track risk metrics",
                        EvidenceType::SystemMetric, "Audit stats: denials/day, ask approvals/denials, per-agent block counts",
                        Some("phylax audit stats")),
                    ctrl("NIST-MEASURE-002", "Adversarial Testing", "Test resilience against adversarial inputs",
                        EvidenceType::SystemMetric, "Path canonicalization + CVE-2025-59829 fix + verify-integrity",
                        Some("phylax project verify")),
                ]),
            build_article("Manage 4", "Risk Management", "2023-01-26", ObligationType::Both, RiskLevel::All,
                "Manage AI risks through treatment, response, and continuous improvement.",
                vec![
                    ctrl("NIST-MANAGE-001", "Risk Treatment", "Apply risk treatment measures proportionate to risk",
                        EvidenceType::Configuration, "6 permission buckets with priority ordering: deny > ask > full > delete > write > read",
                        Some("phylax project show")),
                    ctrl("NIST-MANAGE-002", "Incident Response", "Establish incident response procedures for AI failures",
                        EvidenceType::SystemMetric, "System messages on blocks + audit trail for incident reconstruction",
                        None),
                ]),
        ],
    }
}

fn iso_42001() -> ComplianceStandard {
    ComplianceStandard {
        id: "iso-42001".to_string(),
        name: "ISO/IEC 42001:2023 — AI Management System".to_string(),
        version: "2023".to_string(),
        description: "International standard for establishing, implementing, maintaining, and improving an AI management system.".to_string(),
        articles: vec![
            build_article("§4", "Context of Organization", "2023-12-18", ObligationType::Both, RiskLevel::All,
                "Understand the organization and its context, interested parties, and scope of the AI management system.",
                vec![
                    ctrl("ISO-4-001", "Scope Definition", "Define AI management system scope and boundaries",
                        EvidenceType::Documentation, "Phylax projects define scope via workspace root + phylax.toml",
                        Some("phylax project show")),
                ]),
            build_article("§6", "Planning", "2023-12-18", ObligationType::Both, RiskLevel::All,
                "Plan actions to address risks and opportunities; establish AI objectives and planning.",
                vec![
                    ctrl("ISO-6-001", "Risk Assessment", "Assess AI risks and plan treatment",
                        EvidenceType::Configuration, "Policy priority chain models risk levels; conservative/unrestricted defaults",
                        Some("phylax compliance evaluate --standard iso-42001")),
                ]),
            build_article("§8", "Operation", "2023-12-18", ObligationType::Provider, RiskLevel::All,
                "Plan, implement, and control the processes needed to meet AI management system requirements.",
                vec![
                    ctrl("ISO-8-001", "Operational Controls", "Implement operational controls for AI systems",
                        EvidenceType::SystemMetric, "OS-level enforcement via Windows ACLs; agent detection + classification + ACE application",
                        Some("phylax project verify")),
                    ctrl("ISO-8-002", "Monitoring and Measurement", "Monitor, measure, analyze, and evaluate AI system performance",
                        EvidenceType::AuditLog, "Audit events + status event streaming + TUI real-time dashboard",
                        Some("phylax status")),
                ]),
            build_article("§9", "Performance Evaluation", "2023-12-18", ObligationType::Provider, RiskLevel::All,
                "Evaluate AI management system performance through monitoring, audit, and management review.",
                vec![
                    ctrl("ISO-9-001", "Internal Audit", "Conduct internal audits of the AI management system",
                        EvidenceType::SystemMetric, "project verify produces health report per file; audit verify-integrity validates event chain",
                        Some("phylax project verify && phylax audit verify-integrity")),
                    ctrl("ISO-9-002", "Management Review", "Management review of AI system effectiveness",
                        EvidenceType::Documentation, "Compliance report serves as management review evidence",
                        Some("phylax compliance generate --standard iso-42001")),
                ]),
        ],
    }
}

fn soc2_cc6() -> ComplianceStandard {
    ComplianceStandard {
        id: "soc2-cc6".to_string(),
        name: "SOC 2 — CC6.x Logical & Physical Access Controls".to_string(),
        version: "2023".to_string(),
        description: "AICPA SOC 2 Trust Services Criteria for logical and physical access controls, applicable to AI agent governance.".to_string(),
        articles: vec![
            build_article("CC6.1", "Logical Access Security", "Ongoing", ObligationType::Both, RiskLevel::All,
                "The entity implements logical access security measures to protect against unauthorized access.",
                vec![
                    ctrl("SOC2-CC6-001", "Access Control Lists", "Implement access control to system resources",
                        EvidenceType::SystemMetric, "Windows DENY ACEs applied to protected files; MIC labels prevent privilege escalation",
                        Some("phylax project verify")),
                    ctrl("SOC2-CC6-002", "Least Privilege", "Access provisioning based on least privilege principle",
                        EvidenceType::Configuration, "6 permission buckets: read/write/delete/deny/ask/full per file pattern",
                        Some("phylax project show")),
                ]),
            build_article("CC6.3", "Access Provisioning", "Ongoing", ObligationType::Both, RiskLevel::All,
                "The entity authorizes, modifies, or removes access to data, software, functions, and other resources.",
                vec![
                    ctrl("SOC2-CC6-003", "Per-Entity Access", "Different access levels per entity type",
                        EvidenceType::Configuration, "Per-agent rules (cursor.exe deny *.env) distinct from global rules",
                        Some("phylax agent list")),
                ]),
            build_article("CC7.2", "System Monitoring", "Ongoing", ObligationType::Both, RiskLevel::All,
                "The entity monitors system components for deviations from expected operation.",
                vec![
                    ctrl("SOC2-CC7-001", "Change Detection", "Detect and respond to anomalous system changes",
                        EvidenceType::SystemMetric, "File watcher detects new files + ETW detects new processes in real-time",
                        Some("phylax status")),
                    ctrl("SOC2-CC7-002", "Audit Trail", "Maintain audit trail of system access and changes",
                        EvidenceType::AuditLog, "Audit events log every decision; exportable to SIEM via cloud sync",
                        Some("phylax audit export --format ocsf")),
                ]),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_standards_have_articles() {
        for standard in ComplianceEngine::list_standards() {
            assert!(!standard.articles.is_empty(), "{} has no articles", standard.id);
            for art in &standard.articles {
                assert!(!art.controls.is_empty(), "{}/{} has no controls", standard.id, art.number);
            }
        }
    }

    #[test]
    fn eu_ai_act_has_all_articles() {
        let s = eu_ai_act_high_risk();
        let nums: Vec<_> = s.articles.iter().map(|a| a.number.clone()).collect();
        assert!(nums.contains(&"Art. 4".to_string()));
        assert!(nums.contains(&"Art. 9".to_string()));
        assert!(nums.contains(&"Art. 14".to_string()));
        assert!(nums.contains(&"Art. 15".to_string()));
        assert!(nums.contains(&"Art. 12".to_string()));
        assert!(nums.contains(&"Art. 19".to_string()));
    }

    #[test]
    fn evaluate_reports_all_articles() {
        let engine = ComplianceEngine::with_data(
            AuditCounts { total_events: 42, deny_count: 10, ask_count: 5, active_agents: 3 },
            vec!["/workspace".to_string()],
            true,
        );
        let report = engine.evaluate("eu-ai-act");
        assert_eq!(report.standard, "EU AI Act — High-Risk AI Systems");
        assert_eq!(report.articles.len(), 10);
        assert_eq!(report.evidence_summary.total_audit_events, 42);
        assert_eq!(report.evidence_summary.protected_projects, 1);
        assert!(report.evidence_summary.integrity_chain_verified);
    }

    #[test]
    fn evaluate_without_data_is_partial() {
        let engine = ComplianceEngine::new();
        let report = engine.evaluate("eu-ai-act");
        assert_eq!(report.evidence_summary.total_audit_events, 0);
        assert_eq!(report.overall_status, ControlStatus::Partial);
    }

    #[test]
    fn check_gaps_without_audit_data() {
        let engine = ComplianceEngine::new();
        let gaps = engine.check_gaps("eu-ai-act");
        assert!(!gaps.is_empty(), "Should find gaps when no audit data available");
    }

    #[test]
    fn check_gaps_fully_configured_is_empty() {
        let engine = ComplianceEngine::with_data(
            AuditCounts { total_events: 100, deny_count: 20, ask_count: 8, active_agents: 1 },
            vec!["/ws".to_string()],
            true,
        );
        let gaps = engine.check_gaps("eu-ai-act");
        assert!(gaps.is_empty(), "Should have no gaps when fully configured");
    }

    #[test]
    fn list_standards_returns_six() {
        let standards = ComplianceEngine::list_standards();
        assert_eq!(standards.len(), 6);
        let ids: Vec<&str> = standards.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"eu-ai-act-high-risk"));
        assert!(ids.contains(&"eu-ai-act-transparency"));
        assert!(ids.contains(&"eu-ai-act-deployer"));
        assert!(ids.contains(&"nist-ai-rmf"));
        assert!(ids.contains(&"iso-42001"));
        assert!(ids.contains(&"soc2-cc6"));
    }

    #[test]
    fn article_results_have_correct_counts() {
        let engine = ComplianceEngine::with_data(
            AuditCounts { total_events: 50, deny_count: 5, ask_count: 2, active_agents: 2 },
            vec![],
            true,
        );
        let report = engine.evaluate("eu-ai-act-high-risk");
        for article in &report.articles {
            let total = article.controls_implemented + article.controls_partial + article.controls_missing;
            assert!(total > 0, "Article {} has no controls", article.article);
        }
    }

    #[test]
    fn policy_packs_exist_for_all_standards() {
        for standard in ComplianceEngine::list_standards() {
            let report = ComplianceEngine::new().evaluate(&standard.id);
            assert!(!report.standard.is_empty());
        }
    }
}
