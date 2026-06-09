use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkType {
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "s3")]
    S3,
    #[serde(rename = "splunk_hec")]
    SplunkHec,
    #[serde(rename = "elasticsearch")]
    Elasticsearch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudSinkConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "type", default = "default_sink_type")]
    pub sink_type: SinkType,
    pub endpoint: String,
    pub api_key: Option<String>,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_flush_interval_secs")]
    pub flush_interval_secs: u64,
    #[serde(default = "default_retry_max")]
    pub retry_max: u32,
    pub format: Option<String>,
    #[serde(default)]
    pub compression: bool,
    #[serde(default)]
    pub verify_tls: bool,
}

fn default_sink_type() -> SinkType { SinkType::Http }
fn default_batch_size() -> usize { 1000 }
fn default_flush_interval_secs() -> u64 { 30 }
fn default_retry_max() -> u32 { 5 }

impl Default for CloudSinkConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sink_type: SinkType::Http,
            endpoint: String::new(),
            api_key: None,
            batch_size: 1000,
            flush_interval_secs: 30,
            retry_max: 5,
            format: Some("ocsf".to_string()),
            compression: true,
            verify_tls: true,
        }
    }
}

impl CloudSinkConfig {
    pub fn from_phylax_toml(toml_str: &str) -> Option<Self> {
        let parsed: toml::Value = toml::from_str(toml_str).ok()?;
        let cloud = parsed.get("audit")?.get("cloud")?;
        serde_json::from_value(serde_json::to_value(cloud).ok()?).ok()
    }
}
