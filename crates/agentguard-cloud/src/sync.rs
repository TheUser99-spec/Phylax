use crate::config::{CloudSinkConfig, SinkType};
use crate::sinks::{ElasticsearchSink, HttpSink, SplunkHecSink};
use agentguard_store::Store;
use chrono::Utc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct CloudSyncEngine {
    config: CloudSinkConfig,
    store: Store,
}

impl CloudSyncEngine {
    pub fn new(store: Store, config: CloudSinkConfig) -> Self {
        Self { config, store }
    }

    pub async fn run(&self, stopped: Arc<AtomicBool>) {
        eprintln!("[cloud] Sync engine started (batch={}, interval={}s)",
            self.config.batch_size, self.config.flush_interval_secs);

        while !stopped.load(Ordering::SeqCst) {
            match self.sync_batch().await {
                Ok(n) if n > 0 => {
                    eprintln!("[cloud] Synced {} events", n);
                }
                Err(e) => {
                    eprintln!("[cloud] Sync error: {e}");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    continue;
                }
                _ => {}
            }
            tokio::time::sleep(Duration::from_secs(self.config.flush_interval_secs)).await;
        }
        eprintln!("[cloud] Sync engine stopped");
    }

    async fn sync_batch(&self) -> Result<usize, String> {
        let events = self.store.recent_audit_events(self.config.batch_size)
            .map_err(|e| format!("DB error: {e}"))?;

        if events.is_empty() {
            return Ok(0);
        }

        let host = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let format = self.config.format.as_deref().unwrap_or("ocsf");
        let payload = match format {
            "ocsf" => agentguard_audit::formats::events_to_ocsf(&events, &host).into_bytes(),
            "cef" => agentguard_audit::formats::events_to_cef(&events).into_bytes(),
            _ => serde_json::to_vec(&events).map_err(|e| format!("JSON error: {e}"))?,
        };

        let final_payload = if self.config.compression {
            zstd::encode_all(&payload[..], 3).map_err(|e| format!("zstd: {e}"))?
        } else {
            payload
        };

        let content_type = if self.config.compression { "application/zstd" } else { "application/json" };

        match self.config.sink_type {
            SinkType::Http => {
                let sink = HttpSink::new(
                    self.config.endpoint.clone(),
                    self.config.api_key.clone(),
                    self.config.verify_tls,
                );
                sink.send_batch(&final_payload, content_type).await?;
            }
            SinkType::SplunkHec => {
                let token = self.config.api_key.clone().unwrap_or_default();
                let sink = SplunkHecSink::new(
                    self.config.endpoint.clone(),
                    token,
                    self.config.verify_tls,
                );
                let hec_payload = build_splunk_hec(&events, &host);
                let bytes = if self.config.compression {
                    zstd::encode_all(hec_payload.as_bytes(), 3).map_err(|e| format!("zstd: {e}"))?
                } else {
                    hec_payload.into_bytes()
                };
                sink.send_batch(&bytes).await?;
            }
            SinkType::Elasticsearch => {
                let sink = ElasticsearchSink::new(
                    self.config.endpoint.clone(),
                    self.config.api_key.clone(),
                    self.config.verify_tls,
                );
                let es_payload = build_elasticsearch_bulk(&events, &host);
                let bytes = if self.config.compression {
                    zstd::encode_all(es_payload.as_bytes(), 3).map_err(|e| format!("zstd: {e}"))?
                } else {
                    es_payload.into_bytes()
                };
                sink.send_batch(&bytes).await?;
            }
            SinkType::S3 => {
                return Err("S3 sink not yet implemented".to_string());
            }
        }

        Ok(events.len())
    }
}

fn build_splunk_hec(events: &[agentguard_core::AuditEvent], host: &str) -> String {
    let mut out = String::new();
    let ts = Utc::now().timestamp();
    for event in events {
        let json = agentguard_audit::formats::to_ocsf(event, host);
        out.push_str(&serde_json::json!({
            "time": ts,
            "host": host,
            "source": "phylax",
            "sourcetype": "phylax:audit",
            "event": json,
        }).to_string());
        out.push('\n');
    }
    out
}

fn build_elasticsearch_bulk(events: &[agentguard_core::AuditEvent], host: &str) -> String {
    let index = format!("phylax-audit-{}", Utc::now().format("%Y.%m.%d"));
    let mut out = String::new();
    for event in events {
        let json = agentguard_audit::formats::to_ocsf(event, host);
        out.push_str(&serde_json::json!({
            "index": { "_index": index }
        }).to_string());
        out.push('\n');
        out.push_str(&json.to_string());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentguard_core::{AgentLabel, AuditEvent, FileOp, PolicyDecision, PolicySource};
    use std::path::PathBuf;
    use chrono::Utc;

    fn event(pid: u32) -> AuditEvent {
        AuditEvent {
            id: Some(1), agent_pid: pid,
            agent_label: AgentLabel::Definite,
            file_path: PathBuf::from("/test/.env"),
            operation: FileOp::Read,
            decision: PolicyDecision::Deny,
            source: PolicySource::Project,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn build_splunk_hec_format() {
        let result = build_splunk_hec(&[event(1)], "test-host");
        assert!(result.contains("phylax:audit"));
    }

    #[test]
    fn build_elasticsearch_bulk_format() {
        let result = build_elasticsearch_bulk(&[event(1), event(2)], "test-host");
        assert_eq!(result.lines().count(), 4);
    }

    #[test]
    fn engine_creation() {
        let store = agentguard_store::Store::open_in_memory().unwrap();
        let config = CloudSinkConfig::default();
        let _engine = CloudSyncEngine::new(store, config);
    }

    #[test]
    fn config_from_toml() {
        let toml = r#"
[audit.cloud]
enabled = true
type = "http"
endpoint = "https://audit.example.com/api/events"
api_key = "test-key"
batch_size = 500
format = "ocsf"
"#;
        let config = CloudSinkConfig::from_phylax_toml(toml);
        assert!(config.is_some());
        assert!(config.unwrap().enabled);
    }
}
