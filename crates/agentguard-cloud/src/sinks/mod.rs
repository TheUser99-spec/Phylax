pub struct HttpSink {
    client: reqwest::Client,
    endpoint: String,
    api_key: Option<String>,
}

impl HttpSink {
    pub fn new(endpoint: String, api_key: Option<String>, verify_tls: bool) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!verify_tls)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self { client, endpoint, api_key }
    }

    pub async fn send_batch(&self, batch: &[u8], content_type: &str) -> Result<(), String> {
        let mut req = self.client
            .post(&self.endpoint)
            .header("Content-Type", content_type)
            .body(batch.to_vec());

        if let Some(ref key) = self.api_key {
            req = req.header("Authorization", format!("Bearer {key}"));
        }

        let resp = req.send().await.map_err(|e| format!("HTTP error: {e}"))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(format!("HTTP {status}: {body}"))
        }
    }
}

pub struct SplunkHecSink {
    http: HttpSink,
}

impl SplunkHecSink {
    pub fn new(endpoint: String, token: String, verify_tls: bool) -> Self {
        let http = HttpSink {
            client: reqwest::Client::builder()
                .danger_accept_invalid_certs(!verify_tls)
                .build()
                .unwrap_or_default(),
            endpoint,
            api_key: Some(token),
        };
        Self { http }
    }

    pub async fn send_batch(&self, batch: &[u8]) -> Result<(), String> {
        self.http.send_batch(batch, "application/json").await
    }
}

pub struct ElasticsearchSink {
    http: HttpSink,
}

impl ElasticsearchSink {
    pub fn new(endpoint: String, api_key: Option<String>, verify_tls: bool) -> Self {
        let http = HttpSink::new(endpoint, api_key, verify_tls);
        Self { http }
    }

    pub async fn send_batch(&self, batch: &[u8]) -> Result<(), String> {
        let endpoint = format!("{}/_bulk", self.http.endpoint);
        let http = HttpSink::new(endpoint, self.http.api_key.clone(), true);
        http.send_batch(batch, "application/x-ndjson").await
    }
}
