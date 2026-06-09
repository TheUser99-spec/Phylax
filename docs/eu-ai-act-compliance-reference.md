# EU AI Act (Regulation 2024/1689) — Complete Compliance Reference for AI Agent Security Platforms

**Version:** 1.0 | **Date:** 2026-06-06 | **Status:** Research Reference
**Regulation:** Regulation (EU) 2024/1689 (Official Journal, 13 June 2024)
**Applied to:** Tools like Phylax — AI agent control/security platforms

---

## Executive Summary

The EU AI Act introduces a risk-based regulatory framework. For an **AI agent security platform** (e.g., Phylax — a tool that constrains what AI agents can read, write, or delete at the OS level), the threshold questions are:

1. **Is the platform itself an "AI system"** under Article 3(1)? If it uses rule-based policy engines (not machine learning), it likely falls outside the definition.
2. **If it is an AI system, is it "high-risk"** under Article 6 / Annex III? The platform does not fit cleanly into any Annex III category. However, if it is marketed as a **safety component** for high-risk AI systems (e.g., AI in critical infrastructure, medical devices), it could be captured through the "safety component" doctrine.
3. **Even if not high-risk**, the platform is subject to **Article 50 transparency obligations** (Chapter IV) if it interacts with natural persons or generates content, and to **Article 4 AI literacy** requirements.
4. **If the platform integrates a GPAI model** (e.g., an LLM for policy suggestions), Chapter V obligations apply to the GPAI provider, not necessarily to Phylax as the deployer.

**Most likely classification:** Limited-risk (transparency tier) for AI agent interaction disclosure. Not automatically high-risk. However, **enterprise customers deploying it as a safety guard for high-risk AI systems** should treat it as part of their high-risk compliance chain under Article 25 (responsibilities along the AI value chain).

---

## Threshold Analysis: Is This an "AI System"?

**Article 3(1)** defines an "AI system" as:

> A machine-based system that is designed to operate with varying levels of autonomy and that may exhibit adaptiveness after deployment, and that, for explicit or implicit objectives, infers, from the input it receives, how to generate outputs such as predictions, content, recommendations, or decisions that can influence physical or virtual environments.

**Analysis for Phylax:**
- Phylax's core decision engine (`agentguard-policy`) uses a deterministic policy engine (deny > ask > full > delete > write > read) with GlobSet matching.
- This is a **rule-based system**, not an ML-inferred system.
- **Likely conclusion:** Phylax's core policy engine is **not an AI system** under Article 3(1). It does not "infer" — it matches rules deterministically.
- **Caveat:** If future versions add ML-based anomaly detection, behavioral classification, or LLM-based policy suggestions, those components **would** be AI systems.

---

## Detailed Article-by-Article Analysis

### ARTICLE 4 — AI Literacy (Effective: 2 February 2025)

**Text:** Providers and deployers shall take measures to ensure sufficient AI literacy of their staff and other persons dealing with the operation and use of AI systems on their behalf.

**Obligations:**
- Staff operating Phylax must have adequate understanding of AI systems, their risks, and the platform's capabilities.
- Training documentation must exist.
- This applies **regardless of risk classification**.

**Evidence Phylax would need:**
- Training materials or onboarding documentation for enterprise admins.
- AI literacy statement in product documentation.

---

### ARTICLE 5 — Prohibited AI Practices (Effective: 2 February 2025)

**Eight prohibited practices:**
1. Harmful manipulative/deceptive AI
2. Exploitation of vulnerabilities (age, disability)
3. Social scoring (by public authorities)
4. Individual criminal risk prediction
5. Untargeted scraping for facial recognition DBs
6. Emotion recognition in workplaces/education
7. Biometric categorization for protected characteristics
8. Real-time remote biometric ID in public spaces (w/ exceptions)

**Omnibus Amendment (May 2026 agreement):** Adds prohibition of AI systems generating non-consensual sexually explicit/intimate content or CSAM (e.g., "nudification" apps).

**Analysis for Phylax:** None of the prohibited practices are relevant to an agent security platform. **No compliance burden under Article 5.**

---

### ARTICLE 6 — Classification Rules for High-Risk AI Systems

**Two paths to high-risk classification:**

1. **Article 6(1):** AI system is a **safety component** of a product covered by Annex I Union harmonization legislation, OR is itself such a product, and requires third-party conformity assessment under that legislation.
2. **Article 6(2):** AI system is listed in **Annex III**.

**Annex III categories (relevant to security platforms):**

| Annex III Point | Area | Relevance to Phylax |
|---|---|---|
| 1 | Biometrics (remote, categorization, emotion) | None |
| 2 | Critical infrastructure (safety components) | **Possible**: If deployed to protect AI in transport, energy, water, digital infrastructure |
| 3 | Education/vocational training | Low |
| 4 | Employment, worker management | Low |
| 5 | Access to essential services (credit, insurance, emergency) | Low |
| 6 | Law enforcement | Possible for government deployments |
| 7 | Migration, asylum, border control | Low |
| 8 | Administration of justice | Low |

**Key question:** Is Phylax a "safety component" under Annex III point 2?

A "safety component" is defined (Article 3(14)) as a component that performs a safety function for an AI system or product, the failure of which endangers health, safety, or fundamental rights. If Phylax is marketed as a **safety guard** for high-risk AI systems in critical infrastructure, this could be argued.

**Evidence needed if classified as high-risk:**
- Documentation showing which Annex III category applies.
- If Article 6(3) exemption is claimed (accessory role, no material impact on decision), detailed justification in technical documentation.

---

### ARTICLE 9 — Risk Management System (Effective: 2 August 2026, for high-risk only)

**Complete requirements (10 paragraphs):**

**9(1):** A risk management system shall be **established, implemented, documented and maintained**.

**9(2):** Must be a **continuous iterative process** throughout the entire lifecycle, with regular systematic review. Comprises:
- (a) **Identification and analysis** of known and reasonably foreseeable risks to health, safety, or fundamental rights from intended use.
- (b) **Estimation and evaluation** of risks from intended use AND reasonably foreseeable misuse.
- (c) **Evaluation of risks** from post-market monitoring data (Article 72).
- (d) **Adoption of targeted risk management measures** to address identified risks.

**9(3):** Risks limited to those that can be **reasonably mitigated or eliminated through design** or provision of adequate technical information.

**9(4):** Risk management measures must consider **combined application effects** of all Section 2 requirements to minimize risks effectively.

**9(5):** **Residual risk** must be **judged acceptable**. Measures must include:
- (a) Elimination/reduction through design.
- (b) Mitigation/control measures for residual risks.
- (c) Provision of Article 13 information and **training to deployers**, considering their technical knowledge and context.

**9(6):** **Testing** required to identify appropriate risk management measures — must ensure consistent performance for intended purpose.

**9(7):** Testing may include **real-world conditions** under Article 60.

**9(8):** Testing at any time during development AND **before placing on market/putting into service**. Testing against **pre-defined metrics and probabilistic thresholds**.

**9(9):** **Vulnerable group impact** assessment: consider impact on persons under 18 and other vulnerable groups.

**9(10):** If other Union law already requires internal risk management, may be combined.

**Evidence Phylax would need to produce (if high-risk):**

| Requirement | Evidence Artifact |
|---|---|
| Risk management system established & documented | Risk Management Policy document |
| Continuous iterative process | Risk review schedule, meeting minutes, version history |
| Known & foreseeable risk identification | Risk register with at least: privilege escalation, policy bypass, denial-of-service, path traversal, symlink attacks, API abuse, token theft |
| Foreseeable misuse analysis | Threat model covering: attacker modifies phylax.toml, attacker kills daemon, attacker spoofs PID, attacker floods named pipe |
| Post-market monitoring risk evaluation | Integration of audit logs (agentguard-audit) with risk review process |
| Targeted risk management measures | Design decisions traceable to risks: fail-closed default, canonicalization requirement, pipe ACL constraints |
| Combined effects assessment | Cross-impact analysis of how policy + enforce + probe interact under failure conditions |
| Residual risk judgment | Signed residual risk acceptance document |
| Deployer training provision | Administrator documentation covering risk-relevant configuration |
| Pre-market testing with defined metrics | Test reports with predefined pass/fail thresholds for each security property |
| Vulnerable group assessment | Statement on whether system poses specific risks to under-18 or vulnerable groups |
| Lifecycle integration | Evidence that risk management continues after deployment (post-market monitoring plan) |

**Phylax-specific risks to document:**
- Agent bypass via direct filesystem access (kernel driver gap until Phase 2)
- Named pipe spoofing (mitigated by ACL)
- phylax.toml injection/manipulation
- Race conditions in policy reload
- Denial of service via rule explosion
- False positive file blocking disrupting legitimate agent operations
- False negative permitting unauthorized access

---

### ARTICLE 10 — Data and Data Governance (High-risk only)

**10(1):** High-risk AI systems using ML training must use training, validation, and testing datasets meeting quality criteria.

**10(2):** Data governance practices must cover:
- (a) Design choices
- (b) Data collection processes and origin (for personal data: original purpose)
- (c) Data preparation: annotation, labelling, cleaning, updating, enrichment, aggregation
- (d) Formulation of assumptions about what data measures/represents
- (e) Assessment of data availability, quantity, suitability
- (f) **Bias examination** — especially where outputs influence future inputs (feedback loops)
- (g) Measures to **detect, prevent, mitigate biases**
- (h) Identification of data gaps or shortcomings

**10(3):** Datasets must be **relevant, sufficiently representative, free of errors, and complete**. Must have appropriate statistical properties for the target population.

**10(4):** Datasets must account for **geographical, contextual, behavioural, or functional setting** of intended use.

**10(5):** Exceptional processing of special category personal data for bias detection/correction, under strict safeguards (pseudonymisation, access controls, no onward transfer, deletion after correction).

**10(6):** For non-training AI systems (rule-based), paragraphs 2-5 apply **only to testing datasets**.

**Relevance to Phylax:**
- If Phylax's policy engine is rule-based (no ML training), **only testing datasets are in scope** (Article 10(6)).
- If future ML components are added (anomaly detection, behavioral classification), full data governance applies.
- For rule-based testing: test datasets (e.g., curated file path corpora, sample phylax.toml manifests) must meet quality criteria.

**Evidence needed:**
- Data governance policy (if ML components exist).
- Test dataset documentation: provenance, coverage, edge cases.
- Bias assessment for test datasets.

---

### ARTICLE 11 — Technical Documentation (High-risk only)

**11(1):** Technical documentation must be drawn up **before** placing on market, kept **up-to-date**, and must:
- Demonstrate compliance with Section 2 requirements.
- Provide clear, comprehensive information for competent authorities and notified bodies.
- Contain **at minimum the elements in Annex IV**.
- SMEs may use simplified form (Commission to provide template).

**11(2):** If related to a product under Annex I legislation, single documentation set covering both.

**11(3):** Commission empowered to amend Annex IV via delegated acts.

**Annex IV — Minimum Technical Documentation Contents:**

1. **General description** of the AI system:
   - Intended purpose, entity developing it, date/version
   - How it interacts with hardware/software not part of the system
   - Versions of relevant software/firmware and versioning requirements
   - Forms of placing on market/putting into service
   - Hardware on which it runs
   - If component of products: product description and integration
   - Instructions for use (Article 13) and basic description of user interface

2. **Detailed description of elements** of the AI system and development process:
   - (a) Methods and steps performed for development, including use of pre-trained systems/tools
   - (b) Design specifications: logic, key design choices, assumptions (including regarding persons/groups); main classification choices; what the system optimizes for; relevance of parameters; description of expected output and output quality
   - (c) System architecture: how components build on each other, computational resources
   - (d) If data-driven: training methodologies, techniques, training/validation/testing datasets, provenance, scope, main characteristics; how data was obtained and selected; labelling procedures; data cleaning methodologies
   - (e) Human oversight measures (Article 14): technical measures for interpretation of outputs
   - (f) Where applicable: predetermined changes to system/performance
   - (g) Validation and testing procedures, including performance metrics, accuracy, robustness, cybersecurity metrics; test logs and test reports

3. **Detailed information about monitoring, functioning and control:**
   - Capabilities, limitations, foreseeable unintended outcomes; accuracy metrics for specific persons/groups; foreseeable unintended outcomes and risk sources; measures for human oversight
   - Specifications for input data
   - Changes since last assessment (if applicable)
   - Logging capabilities (Article 12)

4. **Description of metrics** appropriateness for the specific high-risk AI system

5. **Detailed description of risk management system** (Article 9)

6. **Description of relevant changes** made by the provider to the system through its lifecycle

7. **List of harmonised standards** applied (or common specifications used)

8. **Copy of EU declaration of conformity** (Article 47/Annex V)

9. **Description of system in place to evaluate AI system performance** in the post-market phase (Article 72 post-market monitoring plan)

**Evidence Phylax would need:**

| Annex IV Element | Phylax Artifact |
|---|---|
| General description | Product overview: Phylax is a Windows security layer constraining AI agent filesystem operations |
| System architecture | Crate dependency graph, component diagram (probe → classifier → policy → enforce → audit) |
| Design logic | Policy engine design: deny > ask > full > delete > write > read priority chain |
| Key design choices | Fail-closed default, canonicalization requirement, named-pipe IPC |
| Development process | Rust workspace structure, version control history, CI/CD pipeline |
| Training data (if ML) | N/A for rule-based core; test datasets documented |
| Validation/testing | Test suite results: 48 manifest tests, 27 probe tests, 11 enforce tests, etc. |
| Monitoring capabilities | Audit logging (agentguard-audit), post-market monitoring (agentguard-daemon) |
| Logging (Article 12) | SQLite audit logs, automatically generated event logs |
| Risk management description | Risk register + mitigation traceability matrix |
| Standards applied | List of harmonised standards (once published) |
| EU DoC | Draft Declaration of Conformity (Annex V template) |
| Post-market plan | Monitoring plan template per Article 72(3) |

---

### ARTICLE 12 — Record-Keeping / Logging (High-risk only)

**12(1):** High-risk AI systems must **technically allow automatic recording of events (logs) over the lifetime of the system**.

**12(2):** Logging must enable recording of events relevant for:
- (a) Identifying situations that may result in risk (Article 79(1)) or substantial modification
- (b) Facilitating post-market monitoring (Article 72)
- (c) Monitoring operation (Article 26(5))

**12(3):** For Annex III point 1(a) biometric systems specifically: must log period of each use, reference database, matching input data, human verifier identification.

**Relevance to Phylax:**
- Phylax already has `agentguard-audit` for audit logging.
- `agentguard-store` (SQLite) provides persistent storage.
- Requirements: logs must be **automatic** (not user-initiated), cover the **lifetime** of the system.

**What must be logged:**

| Event Category | Specific Events |
|---|---|
| Access decisions | Every file/operation check: timestamp, PID, agent label, path, operation, decision (allow/deny/ask), rule matched |
| Policy changes | Every modification to global rules, per-agent rules, or project manifests; who made the change, when |
| System state changes | Daemon start/stop, policy reload, protection toggle, errors |
| Security-relevant events | Failed pipe authentication, ACL application failures, daemon crashes |
| Deployer actions | Ask responses (allow/deny/timeout), manual overrides |
| Configuration | phylax.toml changes, workspace registration/deregistration |

**Retention period:** Per Article 26(6), deployers must keep logs for **at least 6 months** (unless other law specifies longer). As a provider, logs should be kept for the system lifetime + a reasonable period after last deployment.

**Evidence needed:**
- Log schema documentation.
- Evidence that logging is automatic and tamper-resistant.
- Log retention policy.

---

### ARTICLE 13 — Transparency and Provision of Information to Deployers (High-risk only)

**13(1):** System must be **sufficiently transparent** to enable deployers to interpret output and use it appropriately.

**13(2):** Accompanied by **instructions for use** in digital format — concise, complete, correct, clear, relevant, accessible, comprehensible.

**13(3):** Instructions for use must contain at minimum:

| (a) | Provider identity and contact details |
|---|---|
| (b)(i) | Intended purpose |
| (b)(ii) | Accuracy level, metrics, robustness, cybersecurity — tested/validated thresholds and foreseeable circumstances affecting them |
| (b)(iii) | Known/foreseeable circumstances leading to health/safety/fundamental rights risks |
| (b)(iv) | Technical capabilities to explain output |
| (b)(v) | Performance on specific persons/groups |
| (b)(vi) | Input data specifications, training/validation/testing dataset information |
| (b)(vii) | Information to interpret and use output appropriately |
| (c) | Predetermined changes to system/performance |
| (d) | Human oversight measures (Article 14), including technical measures to facilitate output interpretation |
| (e) | Computational/hardware resources needed, expected lifetime, maintenance/care measures (including frequency), software updates |
| (f) | Mechanisms for deployers to collect, store, and interpret logs (Article 12) |

**Phylax-specific instructions for use:**
- Policy priority chain explanation (deny > ask > full > delete > write > read).
- Canonicalization requirement for paths.
- Named pipe protocol and ACL configuration.
- How to configure phylax.toml.
- How to interpret audit logs.
- Known limitations (e.g., Phase 1 Windows-only, kernel driver pending).
- Security model: what the tool can and cannot protect against.

---

### ARTICLE 14 — Human Oversight (High-risk only)

**14(1):** Systems must be designed so natural persons can **effectively oversee** them during use, including through human-machine interface tools.

**14(2):** Oversight must **prevent or minimize** risks to health, safety, or fundamental rights, especially when risks persist despite other requirements.

**14(3):** Oversight measures must be **commensurate with risks, autonomy level, and context**. Can be:
- (a) Built into the system by provider (when technically feasible)
- (b) Identified by provider for implementation by deployer

**14(4):** Deployer human overseers must be enabled to:
- (a) Understand capacities/limitations and monitor/detect anomalies, dysfunctions, unexpected performance
- (b) Remain aware of **automation bias** (over-reliance)
- (c) Correctly interpret output using available tools/methods
- (d) **Decide not to use the system, or disregard, override, or reverse** its output
- (e) **Intervene/interrupt** the system through a "stop" button or similar procedure to a safe state

**14(5):** For Annex III point 1(a) biometric systems: **two-person verification requirement** (not applicable to law enforcement/migration/asylum where disproportionate).

**Phylax-specific oversight measures:**

| Requirement | Phylax Implementation |
|---|---|
| Oversight interface | TUI dashboard (agentguard-tui) and CLI (agentguard-cli) |
| Monitor for anomalies | Event log tab in TUI showing denied operations, policy violations |
| Override capability | Ask flow: user can approve/deny per-operation via TUI/CLI (Article 26(5)) |
| Stop capability | CLI shutdown command, daemon service stop |
| Automation bias prevention | TUI explicitly labels automated vs. human decisions; default policies visible |
| Understand limitations | Documentation of what kernel driver gap means (Phase 2) |

**The "Ask" flow in Phylax directly implements Article 14(4)(d):**
- When policy returns `ask`, the daemon pauses the I/O decision (via named pipe to minifilter in Phase 2).
- User receives notification via TUI/CLI.
- User can allow, deny, or timeout (timeout → deny = fail-closed).

---

### ARTICLE 15 — Accuracy, Robustness, and Cybersecurity (High-risk only)

**15(1):** Systems must achieve **appropriate level of accuracy, robustness, and cybersecurity**, performing consistently throughout lifecycle.

**15(2):** Commission to encourage development of benchmarks and measurement methodologies with metrology/benchmarking authorities.

**15(3):** Accuracy levels and metrics must be **declared in instructions for use**.

**15(4):** **Resilience** against errors, faults, inconsistencies (including interaction with natural persons or other systems). Technical/organizational measures required. Technical redundancy, backup/fail-safe plans. For systems that **continue to learn** after deployment: must eliminate/reduce biased output feedback loops with mitigation measures.

**15(5):** **Cybersecurity** — resilience against unauthorized third parties attempting to alter use, outputs, or performance by exploiting vulnerabilities. Technical solutions must be **appropriate to circumstances and risks**. AI-specific vulnerability measures must include, where appropriate, prevention/detection/response for:
- **Data poisoning** (manipulating training data)
- **Model poisoning** (manipulating pre-trained components)
- **Adversarial examples / model evasion** (inputs designed to cause mistakes)
- **Confidentiality attacks** or model flaws

**Phylax-specific cybersecurity requirements:**

| Area | Implementation |
|---|---|
| Policy integrity | phylax.toml files must be integrity-protected (checksums, signed manifests) |
| Named pipe security | Strict ACL on `\\.\pipe\agentguard` — only authorized processes |
| Daemon hardening | Run as protected service; least privilege |
| Adversarial resilience | Path canonicalization prevents symlink/TOCTOU bypass |
| Adversarial manifest injection | Manifest parser hardening against malformed TOML |
| Fail-closed design | Default deny when policy engine encounters errors |
| Feedback loop prevention | No ML retraining from observations in current architecture |
| Redundancy | Phase 1 (user-mode ACL) + Phase 2 (kernel minifilter) as defense-in-depth |
| Secure updates | Signed daemon updates, verified policy reloads |

**Attack vectors to defend against:**
- Rule-set poisoning via compromised phylax.toml
- Named pipe hijacking
- Process impersonation
- Policy bypass via alternate filesystem paths
- Daemon termination/DoS
- Audit log tampering
- Timestamp manipulation

**Testing requirements:**
- Pre-defined security test plan with pass/fail thresholds.
- Fuzzing of manifest parser.
- Penetration testing results.
- Adversarial test cases for policy engine.

---

### ARTICLE 16 — Obligations of Providers of High-Risk AI Systems

**Providers must:**

| Point | Obligation | Phylax Status |
|---|---|---|
| (a) | Ensure compliance with Section 2 requirements | Would need conformity assessment if classified high-risk |
| (b) | Indicate name, trade name, trademark, address on system/packaging/documentation | Standard product labeling |
| (c) | Have QMS complying with Article 17 | See Article 17 analysis |
| (d) | Keep documentation per Article 18 | Phylax already has documentation, would need Annex IV format |
| (e) | Keep automatically generated logs (Article 19) | agentguard-audit + agentguard-store |
| (f) | Undergo conformity assessment before placing on market (Article 43) | Internal control (Annex VI) or QMS-based (Annex VII) |
| (g) | Draw up EU Declaration of Conformity (Article 47, Annex V) | Would need to draft |
| (h) | Affix CE marking (Article 48) | Would need to affix |
| (i) | Register in EU database (Article 49) | Would need registration |
| (j) | Take corrective actions (Article 20) | Bug fixes, security patches, recall if needed |
| (k) | Demonstrate conformity to national competent authority on request | Provide documentation package |
| (l) | Comply with accessibility Directives (EU) 2016/2102 and 2019/882 | TUI accessibility |

---

### ARTICLE 17 — Quality Management System (High-risk only)

Must be **documented** in systematic, orderly manner as written policies, procedures, instructions. Must include:

| Element | Description |
|---|---|
| (a) Regulatory compliance strategy | Including conformity assessment procedures and modification management |
| (b) Design, design control, design verification | Techniques, procedures, systematic actions |
| (c) Development, quality control, quality assurance | Techniques, procedures, systematic actions |
| (d) Examination, test, validation procedures | Before, during, after development — with frequency |
| (e) Technical specifications and standards | Applied standards; where not fully applied, means to ensure compliance |
| (f) Data management | Acquisition, collection, analysis, labelling, storage, filtration, mining, aggregation, retention |
| (g) Risk management system | Per Article 9 |
| (h) Post-market monitoring system | Per Article 72 |
| (i) Serious incident reporting procedures | Per Article 73 |
| (j) Communication handling | With authorities, notified bodies, operators, customers |
| (k) Record-keeping systems | All relevant documentation and information |
| (l) Resource management | Including security of supply |
| (m) Accountability framework | Management and staff responsibilities |

**17(2):** Implementation must be **proportionate to provider organisation size** but must respect rigour and protection level required.

**17(3):** May be integrated with existing sectoral QMS obligations.

**17(4):** Financial institutions: QMS (except g, h, i) deemed fulfilled by compliance with financial services internal governance rules.

**Evidence Phylax would need:**
- Written QMS manual covering all 13 elements.
- Documented design control procedures (code review, testing gates).
- Documented validation procedures.
- Documented data management procedures (for test datasets and audit logs).
- Accountability matrix: who is responsible for what.

---

### ARTICLE 18 — Documentation Keeping (High-risk only)

Providers must keep for **10 years after placing on market or putting into service** (for national competent authorities):

- Technical documentation (Article 11/Annex IV)
- QMS documentation (Article 17)
- Conformity assessment documentation
- EU Declaration of Conformity
- Changes approved by notified bodies (if applicable)
- Logs automatically generated (Article 19)

---

### ARTICLE 19 — Automatically Generated Logs (High-risk only)

**19(1):** Providers must keep automatically generated logs of high-risk AI systems **to the extent such logs are under their control** by virtue of contractual arrangement with deployer or by law.

**19(2):** Logs must be kept for a period **appropriate to intended purpose, at least 6 months** (unless other Union/national law requires longer), particularly in Union data protection law.

**Phylax:**
- Audit logs stored in SQLite via agentguard-store.
- Retention: at least 6 months (conforms to Article 19(2)).
- Access controls on audit database.

---

### ARTICLE 20 — Corrective Actions and Duty of Information (High-risk only)

**20(1):** Providers who consider or have reason to consider that a high-risk AI system is not in conformity must immediately take **corrective actions** to bring it into conformity, withdraw it, or recall it. Must inform distributors, importers, deployers, and (where applicable) authorized representatives.

**20(2):** If system presents a **risk** (Article 79(1)), provider must immediately:
- Investigate the non-compliance
- Inform competent authorities of Member States where system was made available
- Inform notified body that issued certificate
- Describe corrective actions taken

**Phylax incident response:**
- Security vulnerability → patch, notify users.
- Policy engine bypass discovered → fix, notify, document.
- Integration with Article 73 serious incident reporting.

---

### ARTICLE 26 — Obligations of Deployers of High-Risk AI Systems (Effective: 2 August 2026)

**This is critical for Phylax's enterprise customers.**

**26(1):** Deployers must take **appropriate technical and organisational measures** to use systems in accordance with instructions for use.

**26(2):** Deployers must **assign human oversight** to natural persons with necessary competence, training, authority, and support.

**26(3):** Obligations without prejudice to deployer's freedom to organize resources for human oversight implementation.

**26(4):** If deployer controls input data, must ensure it is **relevant and sufficiently representative** for intended purpose.

**26(5):** Deployers must **monitor operation** based on instructions for use and inform providers per Article 72. If use may result in risk under Article 79(1): **inform provider/distributor and market surveillance authority without undue delay, and suspend use**. If serious incident: immediately inform provider first, then importer/distributor and market surveillance authorities. Does NOT cover sensitive operational data of law enforcement.

**26(6):** Deployers must **keep automatically generated logs** for at least **6 months** (unless other law requires longer).

**26(7):** **Workplace notice**: employers must inform workers' representatives and affected workers before deploying high-risk AI at the workplace.

**26(8):** Public authority deployers must register in EU database and not use unregistered high-risk AI systems.

**26(9):** Use Article 13 information to comply with GDPR data protection impact assessments.

**26(11):** Deployers of Annex III systems making/assisting decisions about natural persons must **inform those persons** they are subject to high-risk AI.

**26(12):** Deployers must **cooperate** with competent authorities.

**What this means for Phylax enterprise customers:**
- They must have trained personnel overseeing the platform.
- They must monitor operations and report risks.
- They must keep logs for 6+ months.
- If the tool is used in workplace context, they must inform workers/representatives.
- They must cooperate with market surveillance authorities.

---

### ARTICLE 27 — Fundamental Rights Impact Assessment (High-risk only)

**27(1):** Before deploying high-risk AI systems, deployers that are **bodies governed by public law, private entities providing public services**, or deployers of Annex III point 5(b)(c) (credit scoring/insurance/emergency services) must perform a FRIA.

Assessment must include:

| (a) | Description of deployer's processes using the AI system |
|---|---|
| (b) | Period and frequency of use |
| (c) | Categories of natural persons and groups likely affected |
| (d) | Specific risks of harm to identified categories |
| (e) | Description of human oversight measures implemented |
| (f) | Measures to be taken if risks materialize (internal governance, complaint mechanisms) |

**27(2):** Applies to **first use**. May rely on previously conducted FRIAs for similar cases. Must update if elements change or become outdated.

**27(3):** Deployer must notify market surveillance authority of results (AI Office to provide template questionnaire).

**27(4):** Complements (does not replace) GDPR data protection impact assessments.

**Relevance to Phylax:** For enterprise customers who are public bodies or provide public services and deploy Phylax as part of a high-risk AI system deployment, they may need to conduct a FRIA covering this tool.

---

### ARTICLE 43 — Conformity Assessment (High-risk only)

Two available procedures:

1. **Annex VI — Internal control:** Provider self-assesses and declares conformity. Applicable to most Annex III systems.
2. **Annex VII — QMS + technical documentation assessment:** Involves notified body. Applicable when no harmonised standard is applied in full.

**For Phylax:** If classified as high-risk and harmonised standards exist, internal control (Annex VI) likely applies.

**Article 43(3):** For high-risk AI systems that are safety components of products under Annex I legislation: follows the conformity assessment of the sectoral legislation.

---

### ARTICLE 49 — Registration (High-risk only)

**49(1):** Before placing on market or putting into service, providers (and authorized representatives) must register themselves and their system in the **EU database** (Article 71).

**Information to submit (Annex VIII):**
- Provider details (name, address, contact)
- Authorized representative details (if applicable)
- AI system trade name and additional unambiguous reference
- Description of intended purpose
- System status (on market / in service / no longer)
- Member States where placed on market/put into service
- Notified body certificate (if applicable)
- Electronic copy of instructions for use
- URL for additional information (optional)

---

### ARTICLE 50 — Transparency Obligations for Providers and Deployers of Certain AI Systems (Effective: 2 August 2026)

**This applies REGARDLESS of high-risk classification. This is the most directly applicable article for Phylax.**

**50(1):** AI systems intended to **interact directly with natural persons** must inform persons they are interacting with an AI system, **unless obvious** to a reasonably well-informed, observant person. Exception for law enforcement.

**50(2):** AI systems generating **synthetic audio, image, video, or text content** must mark outputs in **machine-readable format** and detectable as artificially generated/manipulated. Must be effective, interoperable, robust, reliable. Exception for assistive standard editing or law enforcement.

**50(3):** Deployers of **emotion recognition or biometric categorization systems** must inform exposed natural persons.

**50(4):** Deployers of AI systems generating **deep fakes** must disclose artificial generation/manipulation. Exception for artistic/satirical works (limited disclosure) and law enforcement. Deployers publishing **AI-generated text of public interest** must disclose.

**50(5):** Information must be provided in **clear and distinguishable manner at latest at time of first interaction**. Must conform to accessibility requirements.

**50(7):** AI Office to facilitate codes of practice for detection and labelling of AI-generated content.

**Analysis for Phylax:**

1. **If Phylax has a TUI/CLI that interacts with human admins:** Does not need to disclose it's AI (Phylax is not an AI chatbot — it's a security tool). The TUI is a monitoring dashboard.
2. **If Phylax generates reports, alerts, or policy recommendations using AI:** Any AI-generated output must be labeled. If the tool suggests policy rules using an LLM, those suggestions must be marked as AI-generated.
3. **If Phylax's "Ask" prompts are AI-generated:** Labels required.
4. **Article 50(1) does not apply** unless Phylax itself presents as an interactive AI agent.

**Most likely Article 50 obligations for Phylax:**
- Minimal. If no AI-generated content, no labeling required.
- If LLM-based policy suggestions are added: those must be marked as AI-generated (Article 50(2)).
- The TUI "Ask" flow notifications should clearly indicate when a recommendation is from the rule engine vs. any AI component.

---

### ARTICLE 53 — Obligations for Providers of GPAI Models (Effective: 2 August 2025)

**Applies to the GPAI model provider, not Phylax directly.** BUT if Phylax integrates an LLM (e.g., for policy suggestions), the downstream obligations matter.

**53(1)(a):** GPAI providers must draw up and keep up-to-date **technical documentation** including training/testing process and evaluation results (Annex XI minimum).

**53(1)(b):** Must make available to downstream AI system providers:
- Information enabling understanding of capabilities and limitations
- Minimum elements per Annex XII

**53(1)(c):** Must have **copyright compliance policy**, including respect for rightsholder opt-outs under Article 4(3) of Directive (EU) 2019/790.

**53(1)(d):** Must publish **sufficiently detailed summary of training content** using AI Office template.

**53(2):** Open-source exception: obligations 53(1)(a) and (b) **do not apply** to free and open-source models where parameters, weights, architecture, and usage information are publicly available. Exception does NOT apply to systemic risk models.

**53(3):** Must cooperate with Commission and national authorities.

**53(4):** May rely on Codes of Practice (Article 56) until harmonised standard published.

**53(5):** Commission may adopt delegated acts for measurement/calculation methodologies.

**Annex XI — GPAI Technical Documentation (minimum):**
- General description (intended tasks, architecture, parameters)
- Development process (design choices, training methodologies, data used, computational resources)
- Known or estimated energy consumption
- Results of internal/external testing and evaluation
- Where applicable, testing and optimisation for foreseeable systemic risks (Article 55)

**Annex XII — Transparency Info to Downstream Providers (minimum):**
- General description of model and development process
- Description of components and architecture
- Modalities and format of inputs and outputs
- Information on data used for training/testing
- Known limitations, biases, risks
- Harmonised standards applied

---

### ARTICLE 55 — Obligations for GPAI Models with Systemic Risk (Effective: 2 August 2025)

In addition to Article 53, systemic risk GPAI providers must:
- (a) Perform **model evaluation** (adversarial testing, standardised protocols)
- (b) Assess and **mitigate systemic risks** at Union level
- (c) Track, document, and report **serious incidents** to AI Office and national authorities
- (d) Ensure **adequate level of cybersecurity protection**

**Relevance to Phylax:** If Phylax integrates an LLM classified as systemic risk GPAI, that LLM provider must comply.

---

### ARTICLE 56 — Codes of Practice (GPAI)

**56(1):** AI Office shall encourage and facilitate drawing up of Codes of Practice at Union level to contribute to proper application of Chapter V.

**56(2):** Codes shall cover obligations under Articles 53 and 55. For Article 55: at minimum:
- Means to ensure compliance with technical documentation and downstream information obligations
- Identification of type/nature of systemic risks and challenges
- Risk assessment, mitigation measures
- AI governance mechanisms (accountability, roles, responsibilities)
- Adequate cybersecurity

**56(3):** AI Office may invite GPAI providers and national authorities to participate.

**56(6):** Commission may adopt implementing acts to approve codes. If inadequate, may adopt common rules.

**Current status (as of July 2025):** The GPAI Code of Practice has been published by the Commission (submitted by independent experts). It provides practical guidance on transparency, copyright, and safety/security obligations.

---

### ARTICLE 72 — Post-Market Monitoring (High-risk only)

**72(1):** Providers must establish and document a **post-market monitoring system** proportionate to AI technology nature and risks.

**72(2):** System must **actively and systematically collect, document, and analyse** relevant data on performance throughout lifetime, allowing continuous compliance evaluation. May include analysis of interaction with other AI systems. Does not cover sensitive operational data of law enforcement.

**72(3):** Based on a **post-market monitoring plan** — part of technical documentation (Annex IV). Commission to adopt **implementing act** with template by **2 February 2026**.

**72(4):** May integrate with existing post-market monitoring under Annex I legislation or financial services law.

**Phylax post-market monitoring system:**
- `agentguard-audit` collects operational data.
- `agentguard-daemon` can report metrics.
- Need: formal post-market monitoring plan.
- Need: data collection from deployers (through IPC, telemetry, or support channels).
- Need: periodic compliance evaluation reports.

---

### ARTICLE 73 — Reporting of Serious Incidents (High-risk only)

**73(1):** Providers must report **serious incidents** to market surveillance authorities of the Member State where the incident occurred.

**73(2):** Report must be made **immediately** after establishing causal link or reasonable likelihood, and **not later than 15 days** after becoming aware of the serious incident.

**73(3):** For **widespread infringement** or serious incident under Article 3(49)(b): **immediately, not later than 2 days**.

**73(4):** If **death of a person**: immediately, not later than **10 days**.

**73(5):** May submit **incomplete initial report** followed by complete report.

**73(6):** After reporting: investigate without delay — risk assessment, corrective action. Cooperate with authorities. Do not alter system in way that affects evaluation prior to informing authorities.

**73(7):** For Article 3(49)(c) incidents (fundamental rights breaches): market surveillance authority must inform national public authorities. Commission to issue guidance by **2 August 2025**.

**73(8):** Market surveillance authority must take appropriate measures within **7 days**.

**"Serious incident" defined (Article 3(49)):**
- (a) Death or serious damage to health, property, or environment
- (b) Serious and irreversible disruption of critical infrastructure
- (c) Breach of obligations under Union law intended to protect fundamental rights

**Phylax serious incident scenarios:**
- Policy engine failure permits unauthorized deletion of critical files → potential property damage
- Agent bypass causes disruption to critical infrastructure AI systems
- ACL misapplication leads to fundamental rights breaches (e.g., improper data access)

**Incident reporting procedure needed:**
1. Detection (audit monitoring, deployer reports)
2. Triage (severity, causal link assessment)
3. Notification to relevant Member State market surveillance authority (within 15/2/10 days)
4. Investigation (root cause analysis)
5. Corrective action (patch, recall, advisory)
6. Closure documentation

---

### ARTICLE 85 — Right to Lodge a Complaint

Any natural or legal person with grounds to consider there has been an infringement of the Regulation may lodge a complaint with the relevant market surveillance authority.

---

### ARTICLE 86 — Right to Explanation of Individual Decision-Making

**86(1):** Any affected person subject to a decision based on output from a high-risk AI system that produces legal effects or similarly significantly affects them shall have the right to obtain from the deployer **clear and meaningful explanations** of the role of the AI system in the decision-making procedure and the main elements of the decision taken.

**86(2):** Paragraph 1 shall apply only to the extent the right is not already provided for under other Union law.

**Relevance to Phylax:** If Phylax is deployed as high-risk and its decisions affect individuals (e.g., blocking a user's file access), affected persons could request explanation.

---

### ARTICLE 99 — Penalties (Effective: 2 August 2025)

**Three-tier fine structure:**

| Tier | Infringement | Maximum Fine (higher of) |
|---|---|---|
| 1 | Article 5 (prohibited practices) | **EUR 35,000,000 or 7%** of global annual turnover |
| 2 | Provider/deployer obligations (Art. 16, 22-24, 26, 31, 33, 34, 50), notified body obligations | **EUR 15,000,000 or 3%** of global annual turnover |
| 3 | Supply of incorrect, incomplete, or misleading information | **EUR 7,500,000 or 1%** of global annual turnover |

**99(6):** For **SMEs/startups**: fines up to the **lower** of the percentage or amount.

**99(7):** Factors considered when determining fines:
- (a) Nature, gravity, duration of infringement; affected persons; damage level
- (b) Whether other market surveillance authorities have already fined for same infringement
- (c) Whether other authorities have fined for same activity under other law
- (d) Size, annual turnover, market share of operator
- (e) Financial benefits gained or losses avoided
- (f) Degree of cooperation with national authorities
- (g) Degree of responsibility (considering technical/organisational measures)
- (h) How infringement became known (self-reported?)
- (i) Intentional or negligent
- (j) Actions taken to mitigate harm

**99(8):** Member States lay down rules on imposing fines on public authorities.

**99(11):** Member States must annually report to Commission on fines issued and related litigation.

---

### ARTICLE 101 — Fines for GPAI Model Providers

Commission may impose fines on GPAI model providers:
- Up to 3% of total worldwide annual turnover or EUR 15,000,000
- For intentional/negligent non-compliance, failure to comply with requested measures, or failure to provide information

---

### ARTICLE 111 — AI Systems Already on the Market

Systems already placed on market/put into service before application dates:
- High-risk systems: operators must take necessary steps to comply **only if significant design changes occur** after application date
- GPAI models placed on market before 2 August 2025: providers must comply by **2 August 2027**

---

### ARTICLE 112 — Evaluation and Review

**112(1):** Commission shall assess need for amendment of Annex III (high-risk list) and Article 5 (prohibitions):
- Annually until end of 2028
- Every four years thereafter
- First report due by **2 August 2027**, subsequent reports by end of each year

**112(3):** By 2 August 2028 and every 4 years: evaluate and report on overall functioning, including GPAI rules, enforcement, codes of practice, and standards.

---

### ARTICLE 113 — Entry into Force and Application Timeline

| Date | What Applies |
|---|---|
| **1 August 2024** | AI Act enters into force (20 days after OJ publication — was 12 July 2024) |
| **2 February 2025** | Chapter I (General Provisions), Chapter II (Prohibited Practices) — **6 months** |
| **2 August 2025** | Chapter III Section 4 (Notifying authorities/bodies), Chapter V (GPAI models), Chapter VII (Governance), Chapter XII (Penalties, except Article 101 GPAI fines), Article 78 (Confidentiality) — **12 months** |
| **2 August 2026** | All remaining provisions — **24 months**. Includes: Chapter III Sections 1-3 and 5 (High-risk requirements, provider/deployer obligations, conformity assessment), Chapter IV (Article 50 transparency), Chapter VI (Innovation), Chapters VIII-IX (Database, post-market, serious incidents), Chapter XI (Delegated acts) |
| **2 August 2027** | Article 6(1) obligations for Annex I products (extended by Omnibus) |
| **2 December 2027** | Rules for high-risk AI systems in certain areas (biometrics, critical infrastructure, education, employment, migration, asylum, border control) — under Omnibus amendment |
| **2 August 2028** | Rules for high-risk AI systems embedded in products (lifts, toys, machinery) — under Omnibus amendment |
| **2 August 2030** | Article 111: GPAI models placed on market before 2 August 2025 must be compliant |

---

## GPAI (General Purpose AI) Requirements — Summary

Do not confuse "GPAI model" (Chapter V) with "high-risk AI system" (Chapter III). They are separate regulatory tracks:

| Aspect | High-Risk AI System (Ch. III) | GPAI Model (Ch. V) |
|---|---|---|
| What | An AI system + its deployment context | A model that can serve multiple purposes |
| Who is responsible | Provider of the AI system | Provider of the model |
| Obligations | Articles 8-27 (full set) | Articles 53-55 (documentation, transparency, copyright, risk mitigation for systemic) |
| Conformity assessment | Yes (Article 43) | No (compliance shown via codes of practice or alternative means) |
| CE marking | Yes | No |
| Effective date | 2 August 2026 | 2 August 2025 |
| Omnibus changes | Extended to Dec 2027/Aug 2028 for some | No change |

**For Phylax:** If Phylax **integrates** an LLM (e.g., for AI-powered policy suggestions), Phylax is a **downstream deployer** of the GPAI model. The LLM provider (e.g., Anthropic, OpenAI, Meta) has the Chapter V obligations. Phylax's obligations are limited to transparent disclosure under Article 50 and due diligence under Article 25.

---

## Provider Obligations vs Deployer Obligations

| Obligation | Provider | Deployer |
|---|---|---|
| Risk management system (Art. 9) | ✓ Establish and maintain | — |
| Data governance (Art. 10) | ✓ Ensure training data quality | ✓ Ensure input data is representative (Art. 26(4)) |
| Technical documentation (Art. 11) | ✓ Draw up, keep updated, retain 10 years | — |
| Record-keeping/logging (Art. 12) | ✓ Technical capability for automatic logs | ✓ Keep logs under their control (6+ months) (Art. 26(6)) |
| Transparency to deployers (Art. 13) | ✓ Provide instructions for use to deployer | — |
| Human oversight (Art. 14) | ✓ Design for oversight; identify measures | ✓ Assign trained human overseers (Art. 26(2)) |
| Accuracy/robustness/cybersecurity (Art. 15) | ✓ Ensure throughout lifecycle | ✓ Monitor operation (Art. 26(5)) |
| Conformity assessment (Art. 16(f)/43) | ✓ Before placing on market | — |
| CE marking + DoC (Art. 16(g)-(h)/47-48) | ✓ | — |
| Registration (Art. 16(i)/49) | ✓ | ✓ Public authorities must register (Art. 26(8)) |
| Corrective actions (Art. 20) | ✓ Take action and notify | ✓ Inform provider and authorities if risk detected (Art. 26(5)) |
| QMS (Art. 17) | ✓ | — |
| Post-market monitoring (Art. 72) | ✓ Establish system and plan | ✓ Contribute data; inform provider |
| Serious incident reporting (Art. 73) | ✓ Report to authorities within 15d/2d/10d | ✓ Inform provider and authorities |
| Fundamental rights impact assessment (Art. 27) | — | ✓ Public bodies and essential service deployers |
| Article 50 transparency | ✓ Design for disclosure (Art. 50(1)-(2)) | ✓ Disclose deep fakes, emotion recognition (Art. 50(3)-(4)) |
| Cooperation (Art. 26(12)) | ✓ (Art. 21) | ✓ |
| Workplace notification (Art. 26(7)) | — | ✓ Employers must inform workers |

**For an AI agent security platform:**

- **Phylax (the vendor)** is the **provider**. If classified as high-risk, all provider obligations apply.
- **Enterprise customer deploying Phylax** is the **deployer**. Deployer obligations under Article 26 apply.
- **Enterprise customer's end-users** (developers, operators) have no direct obligations but benefit from transparency requirements.

---

## Harmonised Standards (CEN/CENELEC)

**Article 40:** Harmonised standards published in the Official Journal provide **presumption of conformity** with covered requirements.

**Standardisation request:** In May 2023 (before the Act was final), the Commission issued a standardisation request to CEN/CENELEC (M/593) covering 10 deliverables:

| Deliverable | Topic | Status |
|---|---|---|
| 1 | Risk management system | Under development |
| 2 | Data governance and data quality | Under development |
| 3 | Record-keeping (logging) | Under development |
| 4 | Transparency and information for deployers | Under development |
| 5 | Human oversight | Under development |
| 6 | Accuracy requirements | Under development |
| 7 | Robustness requirements | Under development |
| 8 | Cybersecurity requirements | Under development |
| 9 | Quality management system | Under development |
| 10 | Conformity assessment | Under development |

**Relevant security standards (likely to inform harmonised standards):**
- ISO/IEC 27001 (ISMS)
- ISO/IEC 42001 (AI Management System)
- ISO/IEC 22989 (AI concepts and terminology)
- ISO/IEC 23894 (AI risk management)
- ISO/IEC 5338 (AI system lifecycle processes)
- ISO/IEC 24029 (AI robustness assessment)
- ENISA guidelines on AI cybersecurity

**CEN/CENELEC JTC 21** is the joint technical committee developing these standards. Standards are expected to be available for citation in the OJ by mid-2026.

**For Phylax:** Once standards are published, map each Article requirement to applicable standard. If standards exist, apply them to gain presumption of conformity. If not, use Article 41 common specifications.

---

## Omnibus Amendment (AI Omnibus) — Political Agreement 7 May 2026

Key changes:

1. **Extended transition periods for high-risk AI:**
   - Systems in biometrics, critical infrastructure, education, employment, migration, asylum, border control: **2 December 2027**
   - Systems embedded in products (lifts, toys, machinery): **2 August 2028**

2. **New prohibition:** AI systems generating non-consensual sexually explicit/intimate content or CSAM (e.g., nudification apps)

3. **Reinforced AI Office powers:** Centralised oversight of AI systems built on GPAI models

4. **SME/SMC benefits extended:** Simplified requirements extended to small mid-cap companies

5. **More access to regulatory sandboxes:** Including EU-level sandbox

6. **Clarification of interplay with product safety laws** (particularly Machinery Regulation)

**Draft guidelines under consultation (as of May 2026):**
- Guidelines for classification of high-risk AI systems (consultation opened 19 May 2026)
- Guidelines for AI transparency obligations (consultation opened 8 May 2026)

---

## ENISA and National Regulator Guidance

**ENISA (European Union Agency for Cybersecurity):**
- Published guidance on AI cybersecurity under the AI Act
- Focuses on Article 15 technical cybersecurity measures
- Recommends: threat modeling, adversarial testing, secure development lifecycle, vulnerability management

**EU AI Office:**
- Established under Article 64
- Responsible for: GPAI enforcement, codes of practice, standardisation coordination, guidelines
- Published: GPAI Guidelines (July 2025), GPAI Code of Practice (July 2025), Training data summary template (July 2025)
- Forthcoming: Guidelines on high-risk classification (May 2026 consultation), Guidelines on transparency (May 2026 consultation), Code of Practice on marking/labelling AI-generated content (Q2 2026)

**National Competent Authorities (Article 70):**
- Each Member State must designate at least one notifying authority and at least one market surveillance authority by **2 August 2025**
- These are the bodies that will enforce the Act at national level
- See https://artificialintelligenceact.eu/national-implementation-plans/ for per-country status

---

## Compliance Evidence Map for Phylax

The following table maps what Phylax would need to produce as **evidence of compliance** if classified as high-risk. Even if not high-risk, many of these artifacts represent good security practice.

| Article | Evidence Required | Status in Phylax | Gap |
|---|---|---|---|
| **Art. 4** | AI literacy training materials | Not yet formalized | Create admin training guide |
| **Art. 9** | Risk management system (documented, maintained) | Partial: AGENTS.md covers security model | Formal risk register, review schedule, residual risk acceptance |
| **Art. 9(6)** | Testing with predefined metrics | Test suites exist (48+ manifest tests) | Add security-specific test metrics and thresholds |
| **Art. 9(9)** | Vulnerable group impact assessment | Not done | Document if applicable |
| **Art. 10** | Data governance for test datasets | Not formalized | Document test data provenance, quality |
| **Art. 11/Annex IV** | Complete technical documentation package | Partial: AGENTS.md, crate docs | Full Annex IV documentation set |
| **Art. 12** | Automatic event logging | Yes: agentguard-audit | Audit log schema documentation, retention policy |
| **Art. 13** | Instructions for use | Partial: CLI/TUI documentation | Comprehensive admin manual covering all 13(3) elements |
| **Art. 14** | Human oversight measures | Yes: Ask flow, TUI monitoring, CLI override | Document in instructions for use |
| **Art. 15(4)** | Resilience to errors/faults | Yes: fail-closed design, canonicalization | Resilience testing documentation |
| **Art. 15(5)** | Cybersecurity measures | Yes: pipe ACL, path canonicalization | Threat model, pen test results, vulnerability management |
| **Art. 17** | Quality Management System | Not formalized | Full QMS manual |
| **Art. 18** | Documentation keeping (10 years) | Git history | Formal archive procedure |
| **Art. 19** | Log retention (6+ months) | SQLite store | Formal retention policy |
| **Art. 20** | Corrective action procedure | Not formalized | Incident response plan, vulnerability disclosure |
| **Art. 26** | Deployer obligations documentation | Not done (deployer-side) | Provide deployer with compliance guide |
| **Art. 43** | Conformity assessment | Not done | Internal control or QMS assessment |
| **Art. 47/Annex V** | EU Declaration of Conformity | Not done | Draft using Annex V template |
| **Art. 48** | CE marking | Not applicable (yet) | Affix when required |
| **Art. 49/Annex VIII** | EU database registration | Not done | Register when required |
| **Art. 50** | Transparency labeling (if AI-generated outputs) | Not applicable (rule-based) | Add labels if LLM features added |
| **Art. 53 (if integrating GPAI)** | GPAI documentation from model provider | Not applicable (no LLM yet) | Request from model provider if integrated |
| **Art. 72** | Post-market monitoring system and plan | Partial: audit infrastructure | Formal PMM plan, data collection, periodic review |
| **Art. 73** | Serious incident reporting procedure | Not formalized | Create incident reporting SOP |
| **Art. 99** | Penalty exposure awareness | Not assessed | Document maximum exposure scenarios |

---

## Key Compliance Deadlines for Phylax

| Deadline | Action |
|---|---|
| **Already effective (2 Feb 2025)** | AI literacy (Article 4) — ensure documentation covers this |
| **Already effective (2 Aug 2025)** | GPAI obligations (Article 53) — if integrating an LLM, verify model provider compliance |
| **2 Feb 2026** | Commission to provide post-market monitoring plan template (Article 72(3)) |
| **Q2 2026** | Code of Practice on marking/labelling AI-generated content expected |
| **2 Aug 2026** | Full application of high-risk requirements (Chapter III), Article 50 transparency (Chapter IV), post-market monitoring (Article 72), serious incident reporting (Article 73) |
| **Mid-2026** | Harmonised standards (CEN/CENELEC) expected for citation in OJ |
| **2 Dec 2027** | Omnibus-extended deadline for certain Annex III high-risk categories |
| **2 Aug 2028** | Omnibus-extended deadline for product-embedded high-risk AI systems |

---

## Recommended Compliance Strategy for Phylax

1. **Classify correctly:** Argue that the rule-based core is not an AI system under Article 3(1). If future ML components are added, classify those separately.

2. **Even if not high-risk**, implement compliance artifacts as security best practices:
   - Formal risk assessment and threat model
   - Comprehensive technical documentation (Annex IV format as template)
   - Incident response and reporting procedures
   - Post-market monitoring (telemetry, audit analysis)
   - Admin training materials (AI literacy)

3. **Prepare for Article 50**: If LLM features are added for policy suggestions, ensure AI-generated outputs are labeled.

4. **Monitor standards development**: Subscribe to CEN/CENELEC JTC 21 outputs and ENISA guidance.

5. **Enterprise customer compliance guide**: Prepare a document explaining what your enterprise customers need to do under Article 26 if they deploy Phylax as part of a high-risk AI system infrastructure.

6. **Track Omnibus implementation**: The extended deadlines provide breathing room but the obligations remain.

7. **Pre-audit readiness**: If a national competent authority requests documentation under Article 16(k), the provider must demonstrate conformity. Having documentation ready avoids penalty exposure under Article 99(5) (incorrect/incomplete information: up to EUR 7.5M / 1%).

---

## References

- Regulation (EU) 2024/1689: https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- AI Act Explorer (Future of Life Institute): https://artificialintelligenceact.eu/ai-act-explorer/
- European Commission AI Act page: https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
- GPAI Code of Practice (July 2025): https://digital-strategy.ec.europa.eu/en/library/general-purpose-ai-code-practice
- GPAI Guidelines (July 2025): https://digital-strategy.ec.europa.eu/en/library/guidelines-general-purpose-ai-models
- CEN/CENELEC JTC 21: https://www.cencenelec.eu/areas-of-work/cen-cenelec-topics/artificial-intelligence/
- AI Act Implementation Timeline: https://artificialintelligenceact.eu/implementation-timeline/
- National Implementation Plans: https://artificialintelligenceact.eu/national-implementation-plans/
- Standardisation request M/593: https://ec.europa.eu/growth/tools-databases/mandates/
- Omnibus Amendment (political agreement 7 May 2026): https://digital-strategy.ec.europa.eu/en/news/eu-agrees-simplify-ai-rules-boost-innovation-and-ban-nudification-apps-protect-citizens
