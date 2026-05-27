use super::{IntelligenceSource, RawAdvisory};
use std::error::Error;

pub struct NpmRegistrySource;

impl NpmRegistrySource {
    pub fn new() -> Self {
        NpmRegistrySource
    }
}

impl Default for NpmRegistrySource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl IntelligenceSource for NpmRegistrySource {
    fn name(&self) -> &str {
        "npm_registry"
    }

    async fn fetch(&self, package: &str, _ecosystem: &str) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        let url = format!("https://registry.npmjs.org/{}", package.replace('/', "%2F"));

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        let json: serde_json::Value = resp.json().await?;

        let latest = json.get("dist-tags")
            .and_then(|t| t.get("latest"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let version_data = json.get("versions")
            .and_then(|v| v.get(latest));

        let mut advisories = vec![];

        let time = json.get("time")
            .and_then(|t| t.get("latest"))
            .and_then(|t| t.as_str());

        if let Some(ts) = time {
            if let Ok(published) = chrono::DateTime::parse_from_rfc3339(ts) {
                let age_hours = (chrono::Utc::now() - published.with_timezone(&chrono::Utc)).num_hours();
                if age_hours < 24 {
                    advisories.push(RawAdvisory {
                        source: "npm_registry".to_string(),
                        id: format!("npm-fresh-{}", package),
                        package: package.to_string(),
                        ecosystem: "npm".to_string(),
                        severity: Some("unknown".to_string()),
                        summary: format!(
                            "Package '{}' was published {} hours ago and may not have been audited yet.",
                            package, age_hours
                        ),
                        details: Some(
                            "This is a very recently published package. Exercise caution.".to_string(),
                        ),
                        references: vec![],
                        modified: chrono::Utc::now().to_rfc3339(),
                        published: Some(ts.to_string()),
                        withdrawn: None,
                        vulnerable_versions: None,
                    });
                }
            }
        }

        let has_postinstall = version_data
            .and_then(|v| v.get("scripts"))
            .and_then(|s| s.get("postinstall"))
            .and_then(|s| s.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        let has_prepare = version_data
            .and_then(|v| v.get("scripts"))
            .and_then(|s| s.get("prepare"))
            .and_then(|s| s.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false);

        if has_postinstall || has_prepare {
            advisories.push(RawAdvisory {
                source: "npm_registry".to_string(),
                id: format!("npm-lifecycle-{}-{}", package, latest),
                package: package.to_string(),
                ecosystem: "npm".to_string(),
                severity: Some("medium".to_string()),
                summary: format!(
                    "Package '{}@{}' has lifecycle scripts (postinstall/prepare) that execute during installation.",
                    package, latest
                ),
                details: Some(
                    "Lifecycle scripts run automatically during package installation. \
                    This is common but can be a vector for malicious code.".to_string()
                ),
                references: vec![],
                modified: chrono::Utc::now().to_rfc3339(),
                published: None,
                withdrawn: None,
                vulnerable_versions: None,
            });
        }

        Ok(advisories)
    }

    async fn fetch_all(&self) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        Ok(vec![])
    }
}
