use super::{IntelligenceSource, RawAdvisory};
use std::error::Error;

pub struct OsvSource;

#[derive(serde::Deserialize)]
struct OsvResponse {
    vulns: Option<Vec<OsvVuln>>,
}

#[derive(serde::Deserialize)]
struct OsvVuln {
    id: String,
    summary: Option<String>,
    details: Option<String>,
    references: Option<Vec<OsvRef>>,
    severity: Option<OsvSeverity>,
    modified: String,
    published: Option<String>,
    withdrawn: Option<String>,
    database_specific: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct OsvRef {
    url: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct OsvSeverity {
    score: Option<String>,
    #[serde(rename = "type")]
    typ: Option<String>,
}

impl OsvSource {
    pub fn new() -> Self {
        OsvSource
    }
}

impl Default for OsvSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl IntelligenceSource for OsvSource {
    fn name(&self) -> &str {
        "osv"
    }

    async fn fetch(&self, package: &str, ecosystem: &str) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        let osv_ecosystem = match ecosystem {
            "npm" | "pnpm" | "yarn" | "bun" => "npm",
            "pip" => "PyPI",
            "cargo" => "crates.io",
            "go" => "Go",
            "docker" => "Docker",
            _ => ecosystem,
        };

        let query = serde_json::json!({
            "package": package,
            "ecosystem": osv_ecosystem
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resp = client
            .post("https://api.osv.dev/v1/query")
            .json(&query)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        let osv_resp: OsvResponse = resp.json().await.unwrap_or(OsvResponse { vulns: None });
        let vulns = osv_resp.vulns.unwrap_or_default();

        let advisories: Vec<RawAdvisory> = vulns
            .into_iter()
            .map(|v| RawAdvisory {
                source: "osv".to_string(),
                id: v.id,
                package: package.to_string(),
                ecosystem: ecosystem.to_string(),
                severity: v.severity.and_then(|s| s.score),
                summary: v.summary.unwrap_or_default(),
                details: v.details,
                references: v.references
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|r| r.url)
                    .collect(),
                modified: v.modified,
                published: v.published,
                withdrawn: v.withdrawn,
                vulnerable_versions: v.database_specific
                    .as_ref()
                    .and_then(|d| d.get("database_specific"))
                    .and_then(|ds| ds.get("ranges"))
                    .and_then(|r| serde_json::to_string(r).ok()),
            })
            .collect();

        Ok(advisories)
    }

    async fn fetch_all(&self) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        Ok(vec![])
    }
}
