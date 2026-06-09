# ADR 009: Audit Logging Architecture -- Local-First + Cloud Sync

**Status:** Draft (research complete, implementation pending)
**Author:** Architecture research
**Date:** 2026-06-06

---

## Context

Phylax currently writes audit events to a local SQLite database (`%APPDATA%\phylax\phylax.db`)
via `agentguard-audit` to `agentguard-store`. There is no cloud export, streaming, or remote
storage. For enterprise deployment, customers require:

- Centralized visibility across fleets (SIEM ingestion)
- Regulatory compliance evidence (GDPR, EU AI Act, SOC 2)
- Tamper-evident, immutable audit trails
- Data residency controls

This ADR surveys industry best practices and proposes a phased architecture.

---

## 1. Dual Storage Architectures

### Industry patterns (by priority for Phylax)

| Pattern | Who uses it | Strengths | Weaknesses |
|---------|-------------|-----------|------------|
| **Local-first, cloud-sync** | CrowdStrike Falcon, SentinelOne, Microsoft Defender | Works offline; agent always records; sync is eventual | Conflict resolution complexity; local storage limits |
| **Cloud-first, local cache** | Datadog Agent, New Relic, Splunk UF | Centralized querying; infinite retention | Ingestion cost; requires connectivity |
| **Write-ahead log + dual-sink** | Apache Kafka + S3, Vector | Decoupled sinks; replay support | Operational overhead |

### Recommended for Phylax: **Local-first with batch cloud sync**

Rationale:
1. The enforcement loop (policy decision to audit write) must be <1ms; network I/O would
   introduce unacceptable latency.
2. Windows agents may be offline (laptops, air-gapped environments).
3. SQLite WAL mode already provides crash-safe local persistence.

### Architecture sketch

```
+---------------------------------+
|  Enforcement Loop (hot path)    |
|  PolicyDecision to Auditor      |
|  to INSERT INTO audit_events    |
|  <1ms, synchronous              |
+---------------+-----------------+
                |
                v
+---------------------------------+
|  Local SQLite (WAL mode)        |
|  audit_events                   |
|  + seq_no (monotonic)           |
|  + hash_chain (SHA-256)         |
|  + sync_state column            |
+---------------+-----------------+
                |
                v (async, batched, compressed)
+---------------------------------+
|  Cloud Sync Worker              |
|  - Reads un-synced events       |
|  - Batches (1000 events/batch)  |
|  - Compresses (zstd)            |
|  - Uploads to cloud sink        |
|  - Marks as synced              |
+---------------+-----------------+
                |
                v
+---------------------------------+
|  Cloud Sink (configurable)      |
|  to S3 + Parquet/Iceberg        |
|  to GCS Blob Storage            |
|  to Azure Blob                  |
|  to SIEM via HTTPS (Splunk HEC) |
+---------------------------------+
```

### Conflict resolution strategy

Since enforcement is **local-first and authoritative**, the cloud is a replica, not a source of
truth. Conflicts do not arise because:
- Events are append-only
- `seq_no` is monotonically increasing per-installation
- Cloud events are never modified -- only appended or logically deleted (GDPR right-to-erasure)

For multi-machine correlation, each event carries a `host_id` (UUID generated at install time)
and the cloud query layer uses `(host_id, seq_no)` as a composite key.

### Eventual consistency

- Sync interval: configurable, default 60 seconds
- Max local buffer: configurable, default 50,000 events (~50 MB)
- If cloud sync fails: exponential backoff, never drop events
- If local rotation evicts unsynced events: log a warning, continue; cloud gap is detectable
  by `seq_no` gaps

---

## 2. Audit Log Formats and Standards

### Comparison matrix

| Standard | Scope | Strengths | Weaknesses | Best for |
|----------|-------|-----------|------------|----------|
| **OCSF** (Open Cybersecurity Schema Framework) | Full security event taxonomy | Vendor-neutral; AWS + Splunk backing; 1000+ event classes; JSON Schema | Newer; tooling still maturing | **Primary choice for Phylax** |
| **CEF** (Common Event Format) | SIEM ingestion | Universal support; ArcSight legacy | Key=value string only; no nested objects; rigid prefix | Legacy SIEM compatibility |
| **LEEF** (Log Event Extended Format) | QRadar | QRadar native | IBM-specific; declining relevance | QRadar customers |
| **ECS** (Elastic Common Schema) | Elastic stack | Rich field taxonomy; Elastic-native | Centered on Elasticsearch; less SIEM-portable than OCSF | Elastic/OpenSearch deployments |
| **OpenTelemetry Logs** | Observability | Span correlation; vendor-neutral | Not audit-specific; lacks security event taxonomy | Infrastructure observability |
| **CloudTrail-format JSON** | AWS audit | Proven at scale; well-documented | AWS-specific field names | AWS deployments |

### Recommendation: **OCSF primary, CEF/CloudTrail-format as export options**

OCSF is the right primary format because:
1. Splunk, AWS Security Lake, and Microsoft Sentinel have announced or shipped OCSF ingestion.
2. OCSF's `Security Finding` and `IAM Activity` event classes map cleanly to Phylax's
   enforcement decisions.
3. OCSF has a formal JSON Schema -- type-safe serialization from Rust is straightforward.

### OCSF event class mapping for Phylax

| Phylax event | OCSF class ID | OCSF class name | Key fields |
|-------------|---------------|-----------------|------------|
| File access decision (allow/deny) | 4005 | `File System Activity` | `activity_id` (1=Read/2=Write/3=Delete), `disposition_id` (1=Allowed/2=Blocked/3=Queried), `file.name`, `file.path` |
| Ask prompt decision | 4006 | `Proactive Policy Activity` | `policy.name`, `policy.decision`, `policy.response` |
| Agent session start/end | 3004 | `Process Activity` | `process.pid`, `process.file.name`, `process.uid` |
| Policy change (global rule CRUD) | 2002 | `Policy Modify Activity` | `policy.name`, `policy_rules[].action`, `change_type` |
| Protection enable/disable | 2002 | `Policy Modify Activity` | `policy.name`, `status_id` (1=Active/2=Suspended) |

### OCSF envelope skeleton (every Phylax event)

```json
{
  "metadata": {
    "version": "1.4.0",
    "product": {
      "name": "Phylax",
      "vendor_name": "AgentGuard",
      "version": "0.7.0"
    },
    "profiles": ["host", "linux", "windows"],
    "event_code": "File System Activity: Blocked"
  },
  "severity_id": 0,
  "category_name": "System Activity",
  "category_uid": 1,
  "class_name": "File System Activity",
  "class_uid": 4005,
  "activity_name": "Delete",
  "activity_id": 3,
  "time": 1717718400000,
  "device": {
    "hostname": "ENG-LAPTOP-01",
    "uid": "550e8400-e29b-41d4-a716-446655440000",
    "os": { "type": "Windows", "type_id": 100 }
  },
  "actor": {
    "process": {
      "pid": 12345,
      "file": { "name": "claude.exe", "path": "C:/Users/omkde/AppData/Local/..." }
    },
    "session": { "uid": "550e8400-...", "issuer": "Phylax Subject Classifier" }
  },
  "file": {
    "name": ".env",
    "path": "C:/workspace/.env",
    "type": "Regular",
    "type_id": 1
  },
  "disposition": "Blocked",
  "disposition_id": 2,
  "policy": {
    "name": "Project .env deny rule",
    "uid": "deny:*.env",
    "desc": "Matched deny bucket rule from project manifest"
  },
  "unmapped": {
    "phylax_source": "project",
    "phylax_seq_no": 104729,
    "phylax_hash_chain": "sha256:abc123...",
    "phylax_agent_label": "DEFINITE"
  }
}
```

### CEF fallback (for legacy SIEM)

For CEF-compatible export, flatten the structured event into a CEF header:

```
CEF:0|AgentGuard|Phylax|0.7.0|4005|File System Activity: Blocked|3|
  msg=Blocked agent file access
  src=127.0.0.1
  suser=claude.exe
  filePath=C:/workspace/.env
  filePermission=0
  act=Delete
  outcome=Failure
  reason=deny bucket
  cs1=project
  cs1Label=phylax_source
  cs2=DEFINITE
  cs2Label=phylax_agent_label
```

### CloudTrail-format (for AWS-native customers)

Follow the CloudTrail `Records[]` structure with an invented `eventSource`:

```json
{"Records": [{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "PID:12345:claude.exe",
        "arn": "arn:agentguard:subject:DEFINITE:claude.exe",
        "sessionContext": {
            "attributes": {
                "creationDate": "2026-06-06T10:00:00Z",
                "mfaAuthenticated": "false"
            }
        }
    },
    "eventTime": "2026-06-06T10:15:30Z",
    "eventSource": "phylax.agentguard.io",
    "eventName": "FileAccessDecision",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "127.0.0.1",
    "userAgent": "Phylax Enforcer/0.7.0",
    "requestParameters": {
        "filePath": "C:/workspace/.env",
        "operation": "delete"
    },
    "responseElements": {
        "decision": "deny",
        "source": "project",
        "rule": "deny:*.env"
    },
    "errorCode": "AccessDenied",
    "errorMessage": "Phylax deny bucket matched *.env",
    "requestID": "0021d104-98d1-4ca9-b4e4-EXAMPLE01",
    "eventID": "4a0b44d9-1e8b-4f4e-8b5e-EXAMPLE02",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "eventCategory": "Management"
}]}
```

---

## 3. Cloud Storage Options

### Option ranking for Phylax

| Solution | Best for | Cost model | SIEM compatibility | Recommendation |
|----------|----------|------------|-------------------|----------------|
| **S3 + Parquet/Iceberg** | Multi-cloud, queryable archive | Storage only (~$0.023/GB) | Athena, Redshift Spectrum, Spark | **Primary cloud sink** |
| **Splunk HEC endpoint** | Splunk customers | Per GB ingested | Native | **Primary SIEM integration** |
| **OpenSearch / Elasticsearch** | Self-hosted search | Infrastructure cost | Native (via ECS) | **Secondary SIEM** |
| **Azure Monitor / Log Analytics** | Azure shops | Per GB + query cost | Sentinel native | Azure customers |
| **GCP Cloud Audit Logs** | GCP shops | Per GB ingested | Chronicle native | GCP customers |
| **AWS CloudTrail Lake** | AWS shops | $2.50/GB ingested | CloudTrail console | AWS customers |
| **Kafka topic** | Streaming/federation | Infrastructure cost | Any via connect | Advanced deployments |

### Recommended phased approach

**Phase 1: File-based export** (immediate)
- Extend `agentguard-cli audit export` to support `json` (OCSF), `cef`, and `cloudtrail` formats
- Users manage upload to their SIEM/storage

**Phase 2: Direct SIEM push** (short-term)
- HTTP event collector (Splunk HEC, Elasticsearch `_bulk`)
- Configured via `phylax.toml` or environment variables
- Async batch worker in daemon

**Phase 3: Object storage with table format** (medium-term)
- S3/GCS/Azure Blob with Parquet files partitioned by `year/month/day/hour`
- Apache Iceberg table format for time-travel, schema evolution, partition pruning
- Catalog: AWS Glue or Nessie (for multi-engine access)

**Phase 4: Streaming/federation** (long-term)
- Kafka topic per fleet
- OpenTelemetry Collector integration

### SIEM integration matrix

| SIEM | Ingestion method | Format | Rate limits | Notes |
|------|-----------------|--------|-------------|-------|
| Splunk Enterprise/Cloud | HEC (HTTP Event Collector) | JSON, CEF | ~6 MB/s per HEC token | Most common enterprise SIEM |
| Elastic/OpenSearch | `_bulk` API / Beats | JSON (ECS or custom) | Per-node queue limits | Use data streams for time-series |
| Azure Sentinel | Log Analytics API / AMA agent | JSON (custom log schema) | 30 MB/min per DCR | Data Collection Rules define schema |
| GCP Chronicle | Ingestion API / Feed | UDM structured JSON | 1 MB/s per feed | GCP-specific UDM mapping |
| Datadog | Logs API | JSON | 5 MB/s per API key | Good for cloud-native shops |
| AWS Security Lake | S3 put to managed bucket | OCSF Parquet | S3 write limits | Native OCSF support |

### Parquet schema for cloud storage

```rust
// Conceptual Parquet schema for audit event storage
// Partition structure: year=2026/month=06/day=06/hour=14/
message AuditEvent {
    required int64  seq_no;
    required binary host_id        (UTF8);    // UUID
    required int64  timestamp_ms;             // epoch millis
    required int32  agent_pid;
    required binary agent_label    (UTF8);    // DEFINITE|PROBABLE|INHERITED|HUMAN
    required binary agent_image    (UTF8);    // e.g. claude.exe
    required binary file_path      (UTF8);
    required binary operation      (UTF8);    // read|write|delete
    required binary decision       (UTF8);    // allow|deny|ask
    required binary source         (UTF8);    // agent|global|project|default
    optional binary matched_rule   (UTF8);    // e.g. deny:**/.env
    optional binary project_name   (UTF8);
    required binary hash_chain     (UTF8);    // SHA-256 hex
    optional binary prev_hash      (UTF8);    // previous event hash
    optional binary signature      (BYTE_ARRAY); // Ed25519 signature
    optional binary ocsf_json      (UTF8);    // full OCSF-encoded event
}
```

---

## 4. Integrity and Non-Repudiation

### Hash chaining design (Certificate Transparency style)

Each audit event includes:
- `seq_no`: monotonic counter (SQLite `AUTOINCREMENT`)
- `prev_hash`: SHA-256 of the *previous* event's full JSON
- `hash_chain`: SHA-256 of `(prev_hash || event_json)`

This creates an append-only Merkle-DAG where modifying any event invalidates all subsequent
hashes. The daemon verifies the chain on startup and alerts on breaks.

```rust
// Pseudocode for hash-chain insertion
fn compute_hash(event: &AuditEvent, prev_hash: &str) -> String {
    let event_json = serde_json::to_string(&to_ocsf(event)).unwrap();
    let data = format!("{}||{}", prev_hash, event_json);
    let digest = ring::digest::digest(&ring::digest::SHA256, data.as_bytes());
    hex::encode(digest.as_ref())
}

fn verify_chain(events: &[AuditEventRow]) -> ChainVerification {
    let mut prev = "0000000000000000000000000000000000000000000000000000000000000000";
    for (i, e) in events.iter().enumerate() {
        let expected = compute_hash(e, prev);
        if e.hash_chain != expected {
            return ChainVerification::Break {
                at_index: i,
                expected,
                found: e.hash_chain.clone(),
            };
        }
        prev = &e.hash_chain;
    }
    ChainVerification::Valid { count: events.len() }
}
```

### Ed25519 signing

For non-repudiation in compliance scenarios:
- Each installation generates an Ed25519 keypair at first run
- Public key is registered with a central attestation service (optional)
- Each event is signed with the private key
- A verifier can check `(event_json, signature, public_key)` without the private key
- Signing happens in the sync worker, not the hot path (signing is ~50us, acceptable for batch)

### WORM storage

For cloud-resident audit data:
- **AWS S3 Object Lock** in Compliance mode: prevents deletion/overwrite for a retention period
- **Azure Immutable Blob Storage**: same, with legal hold support
- **GCP Bucket Lock**: retention policy on bucket
- **Local**: SQLite `PERSIST` journal mode + filesystem ACLs preventing direct `.db` modification
  (read-only for non-SYSTEM accounts except the daemon's service account)

### Integrity verification API

A REST endpoint `/api/v1/audit/integrity` returns:
```json
{
  "status": "valid",
  "total_events": 104729,
  "chain_start": "2026-06-01T00:00:00Z",
  "chain_end": "2026-06-06T14:30:00Z",
  "last_hash": "sha256:def456...",
  "signed": true,
  "signer_public_key": "MCowBQYDK2VwAyEA..."
}
```

---

## 5. REST API Design for Audit Endpoints

### Endpoint inventory

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/api/v1/audit/events` | Query events | API key |
| `GET` | `/api/v1/audit/events/{id}` | Single event | API key |
| `GET` | `/api/v1/audit/export` | Batch export (streaming) | API key |
| `GET` | `/api/v1/audit/stats` | Summary statistics | API key |
| `GET` | `/api/v1/audit/integrity` | Chain/signing verification | API key |
| `POST` | `/api/v1/audit/erasure` | GDPR right-to-erasure | Admin token |
| `GET` | `/api/v1/audit/config` | Audit config (format, sinks) | API key |
| `PUT` | `/api/v1/audit/config` | Update audit config | Admin token |

### Query parameters for `GET /api/v1/audit/events`

```
?from=2026-06-01T00:00:00Z          # ISO 8601 range start
&to=2026-06-06T23:59:59Z            # ISO 8601 range end
&agent_label=DEFINITE               # filter by agent label
&agent_image=claude.exe             # filter by process image name
&project=my-app                     # filter by registered project
&decision=deny                      # filter by decision (allow|deny|ask)
&operation=write                    # filter by file operation
&source=project                     # filter by policy source
&limit=100                          # page size (max 1000)
&cursor=eyJsYXN0X2lkIjogMTA0NzI5fQ # opaque pagination cursor
&order=asc                          # asc|desc (default desc)
```

### Streaming export (`GET /api/v1/audit/export`)

Returns `Transfer-Encoding: chunked` with NDJSON (newline-delimited JSON):

```http
GET /api/v1/audit/export?from=2026-06-01&to=2026-06-06&format=ocsf HTTP/1.1
Authorization: Bearer phylax_sk_abc123

HTTP/1.1 200 OK
Content-Type: application/x-ndjson
Transfer-Encoding: chunked

{"metadata":{...},"time":1717718400000,...}
{"metadata":{...},"time":1717718401000,...}
```

Supports optional compression via `Accept-Encoding: gzip`.

### Pagination strategy: **Cursor-based**

```rust
struct PaginationCursor {
    last_seq_no: i64,   // monotonically increasing ID
    last_ts: i64,       // fallback timestamp for tie-breaking
}

// Encoded as base64url JSON, decoded by server
// Cursor is opaque to the client

fn next_page(store: &Store, cursor: Option<String>, limit: usize) -> PageResult {
    let decoded = cursor
        .map(|c| base64_decode(cursor))
        .unwrap_or(PaginationCursor { last_seq_no: 0, last_ts: 0 });

    let events = store.query_after(decoded.last_seq_no, limit)?;
    let next = if events.len() == limit {
        Some(base64_encode(PaginationCursor {
            last_seq_no: events.last().seq_no,
            last_ts: events.last().ts,
        }))
    } else {
        None
    };

    PageResult { events, next_cursor: next }
}
```

### Rate limiting

- Token bucket per API key: 1000 requests per minute burstable to 2000
- Export endpoint: 1 concurrent export per API key
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- HTTP 429 with `Retry-After` header on exhaustion

### Authentication

Two-tier auth model:
1. **Read-only API key** (prefix `phylax_sk_`): 64-char hex, generated by admin, for SIEM/SOAR
   ingestion
2. **Admin token** (JWT or static token): for config changes, erasure requests, key rotation

API keys stored hashed (SHA-256) in SQLite `api_keys` table.

---

## 6. GDPR / EU AI Act Specific Requirements

### EU AI Act (effective August 2026)

Phylax is classified as a **high-risk AI system** under the EU AI Act because it:
1. Makes automated decisions affecting fundamental rights (access to compute resources)
2. Operates as a security component of AI systems

**Obligations:**

| Requirement | How Phylax addresses it |
|-------------|-------------------------|
| **Record-keeping** (Art. 12) | Audit events automatically logged; configurable retention |
| **Transparency** (Art. 13) | TUI dashboard shows active decisions; CLI `audit list` shows history |
| **Human oversight** (Art. 14) | `Ask` bucket requires human approval; TUI Ask modal |
| **Accuracy** (Art. 15) | Hash-chain integrity verification; subject classifier accuracy metrics |
| **Robustness** (Art. 16) | Fail-closed design: DB unavailable = deny default |
| **Post-market monitoring** (Art. 61) | Cloud-synced audit data for fleet-wide monitoring |

### GDPR specifics

**Right to access (Art. 15):**
- `GET /api/v1/audit/events?agent_pid={my_pid}` returns all events related to a subject's
  processes
- Can filter by any dimension the data subject can identify with

**Right to erasure (Art. 17) - interaction with immutable logs:**
- Immutable hash chain cannot have events *removed* without breaking verification
- Solution: **logical deletion** -- set `erased = true` on matching events, keep the event
  structure intact but redact PII in `file_path` and `user_identity` fields
- Hash chain uses pre-redaction values; verification still works
- Redacted fields store `[REDACTED]` placeholder
- A separate `erasure_requests` table records when/who/why for compliance auditors
- Erasure endpoint requires admin auth + justification

```sql
-- Migrations to support GDPR erasure
ALTER TABLE audit_events ADD COLUMN erased INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_events ADD COLUMN file_path_original TEXT;  -- stores original before redaction

CREATE TABLE erasure_requests (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    requested_by TEXT NOT NULL,     -- admin user
    reason       TEXT NOT NULL,     -- e.g. "Art. 17 GDPR request ticket #12345"
    filter_json  TEXT NOT NULL,     -- JSON describing which events to erase
    events_affected INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
    completed_at INTEGER
);
```

**Data residency:**
- Local SQLite stays on the host machine (data sovereignty by default)
- Cloud sync is **opt-in**, configurable per region
- Cloud sink region can be specified (e.g. `s3://my-bucket?region=eu-west-1`)
- For EU customers: all cloud data must stay in EU regions (AWS eu-*, Azure West/North Europe,
  GCP europe-*)

**Retention policies:**
- Default local retention: 7 days (rotated by `rotate_audit_events`)
- Cloud retention: configurable, default 90 days for hot storage, 7 years for cold archive
- Configurable via `phylax.toml`:
  ```toml
  [audit]
  local_retention_days = 7
  cloud_retention_days = 90
  cold_archive_years = 7
  ```
- Automatic archival: S3 Lifecycle to Glacier Deep Archive after 90 days

**Encryption at rest:**
- Local: SQLite can use SQLCipher or filesystem-level BitLocker
- Cloud: S3/KMS SSE, Azure Storage Service Encryption, GCP default encryption
- Encryption in transit: TLS 1.3 for all cloud sync and HIPAA-compliant API endpoints

**Data Processing Agreement (DPA):**
- Phylax acts as a **data processor** under GDPR when deployed in organizations
- Processing purpose: security enforcement and compliance auditing
- Data categories: process metadata (PID, image name), file paths, policy decisions
- No personal data is collected by design (no usernames, emails, IPs of human users)

---

## 7. Reference Architectures from Industry Tools

### CrowdStrike Falcon (local sensor + cloud)

**Architecture:**
- Lightweight sensor (Windows kernel driver + user-mode agent) on endpoint
- All detection/prevention happens locally (<1ms latency)
- Telemetry streamed to Threat Graph cloud via HTTPS/TLS
- Cloud provides: correlation, threat hunting, managed detection, fleet management

**Lessons for Phylax:**
1. Sensor is self-sufficient -- local decisions never wait for cloud
2. Telemetry is compressed and batched (Falcon uses protobuf, not JSON for efficiency)
3. Cloud connection is outbound-only (no inbound ports on endpoint)
4. Sensor health monitoring includes "telemetry gap" detection

### Wiz (cloud-only, API-based)

**Architecture:**
- Agentless: reads cloud provider APIs (AWS/GCP/Azure)
- All analysis in Wiz cloud; no on-prem persistence
- REST API for querying findings, policy violations, asset inventory
- OCSF support for Security Lake integration

**Lessons for Phylax:**
1. API-first design from day one
2. OCSF adoption signals industry direction
3. Graph-based asset model (not applicable to endpoint, but the idea of linking
   agent-to-project-to-file as a graph is powerful)

### Datadog / Splunk (ingestion APIs)

**Datadog Logs API:**
- `POST /api/v2/logs` with JSON array of log events
- Rate limit: 5 MB/s per API key
- Automatic compression (gzip) accepted
- Structured JSON preferred over plaintext

**Splunk HTTP Event Collector (HEC):**
- `POST /services/collector/event` or `/services/collector/raw`
- HEC token in `Authorization: Splunk <token>` header
- Single event or JSON array of events
- Optional: index, source, sourcetype, host metadata per event

**Key design pattern:** Both support "firehose" ingestion (send events as fast as you can,
let the backend handle indexing). Phylax's sync worker should follow the same pattern --
batch, compress, POST, retry on 429/503, exponential backoff.

### Vanta / Drata (compliance evidence APIs)

**Vanta architecture:**
- Connects to cloud APIs, SaaS tools, and on-prem agents
- Pulls evidence automatically (no manual upload)
- Maps evidence to SOC 2, ISO 27001, HIPAA controls
- Evidence stored as time-series with snapshot capability

**Lessons for Phylax:**
1. Audit events should be queryable by compliance framework control ID
2. Snapshot export: "give me all audit events for Q2 2026" should produce a zip of signed,
   verifiable events
3. Evidence chain of custody: who accessed audit data, when, from which IP

### Snowflake Access History (column-level audit)

**Architecture:**
- Every query that reads/writes data records source columns, target columns, user, timestamp
- Column lineage tracks how data flows through transformations
- Queryable via SQL views in `ACCOUNT_USAGE.ACCESS_HISTORY`
- Org-level view for multi-account environments

**Lessons for Phylax:**
1. The `ACCESS_HISTORY` view's separation of `direct_objects_accessed` (what the query named)
   and `base_objects_accessed` (underlying source) maps well to Phylax's concept of
   canonicalized paths vs raw paths
2. Column-level granularity is valuable for sensitive data tracking (Phylax could extend from
   file-level to column-level when the minifilter supports it)
3. The "lineage as a graph" query pattern (recursive CTE tracing data from stage to table to
   view) is a powerful model for asking "where did this file go?"

---

## Implementation Roadmap for Phylax

### Phase 1: Schema & Format (changes to `agentguard-core` and `agentguard-store`)

1. Add fields to `AuditEvent`:
   - `seq_no: Option<i64>` -- monotonic counter
   - `prev_hash: Option<String>` -- SHA-256 of previous event
   - `hash_chain: Option<String>` -- chain hash
   - `signature: Option<Vec<u8>>` -- Ed25519 signature
   - `erased: bool` -- GDPR logical deletion flag
   - `host_id: Option<String>` -- installation UUID
   - `agent_image: Option<String>` -- process image name
   - `project_name: Option<String>` -- matched project

2. Migration v4: Add columns to `audit_events`, add `erasure_requests` table, add `api_keys`
   table

3. Build OCSF serializer in `agentguard-audit` (or a new `agentguard-audit-format` crate)

### Phase 2: Enhanced Export (changes to `agentguard-cli`)

4. Extend `audit export` to support `ocsf`, `cef`, `cloudtrail` formats
5. Add `audit verify` command to check hash chain integrity
6. Add `audit erase` command for GDPR right-to-erasure (admin only)

### Phase 3: Cloud Sync (new `agentguard-cloud` crate, daemon changes)

7. Cloud sync worker in daemon (async Tokio task)
8. Splunk HEC + Elasticsearch `_bulk` sinks
9. S3/GCS/Azure Blob sinks with Parquet output
10. ERP/retry with exponential backoff
11. Configuration via `phylax.toml` `[cloud]` section

### Phase 4: REST API (new `agentguard-api` crate or extend daemon)

12. HTTP server (axum or actix-web) in daemon on `localhost:8735`
13. Audit query/search/export endpoints
14. API key management
15. Rate limiting middleware
16. OpenAPI/Swagger documentation

---

## Summary of Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Storage architecture | Local-first, cloud-sync | Enforcement latency <1ms; offline support |
| Primary format | OCSF 1.4.0 | Vendor-neutral; industry momentum |
| Export formats | OCSF, CEF, CloudTrail | SIEM compatibility |
| Cloud sink | S3 + Parquet/Iceberg | Cost-effective; queryable; multi-cloud |
| Integrity model | Hash-chaining + Ed25519 signing | Non-repudiation; CT-style verifiability |
| GDPR erasure | Logical deletion + redaction | Preserves chain integrity |
| Pagination | Cursor-based | Stable under concurrent writes |
| Auth model | API key (read) + admin token (write) | Standard enterprise pattern |
| Local retention | 7 days (rolling) | Configurable; keeps DB small |
| Cloud retention | 90 days hot, 7 years cold archive | Enterprise compliance norms |
| Phase 1 target | OCSF export from CLI | Low-risk, high-value, no infra changes |
