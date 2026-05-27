use super::{IntelligenceSource, RawAdvisory};
use std::error::Error;

pub struct DepsDevSource;

impl DepsDevSource {
    pub fn new() -> Self {
        DepsDevSource
    }
}

impl Default for DepsDevSource {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(serde::Deserialize, Clone)]
struct DepsDevVulns {
    vulnerabilities: Option<Vec<DepsDevVuln>>,
}

#[derive(serde::Deserialize, Clone)]
struct DepsDevVuln {
    id: Option<String>,
    severity: Option<String>,
    advisory: Option<DepsDevAdvisory>,
    affected: Option<Vec<DepsDevAffected>>,
}

#[derive(serde::Deserialize, Clone)]
struct DepsDevAdvisory {
    details: Option<String>,
}

#[derive(serde::Deserialize, Clone)]
struct DepsDevAffected {
    package: Option<DepsDevPackage>,
    ranges: Option<Vec<DepsDevRange>>,
}

#[derive(serde::Deserialize, Clone)]
#[allow(dead_code)]
struct DepsDevPackage {
    name: Option<String>,
    ecosystem: Option<String>,
}

#[derive(serde::Deserialize, Clone)]
#[allow(dead_code)]
struct DepsDevRange {
    #[serde(rename = "type")]
    typ: Option<String>,
    events: Option<Vec<DepsDevEvent>>,
}

#[derive(serde::Deserialize, Clone)]
struct DepsDevEvent {
    introduced: Option<String>,
    fixed: Option<String>,
}

#[async_trait::async_trait]
impl IntelligenceSource for DepsDevSource {
    fn name(&self) -> &str {
        "deps_dev"
    }

    async fn fetch(&self, package: &str, ecosystem: &str) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        let deps_ecosystem = match ecosystem {
            "npm" | "pnpm" | "yarn" | "bun" => "npm",
            "pip" => "pypi",
            "cargo" => "cratesio",
            "go" => "go",
            _ => ecosystem,
        };

        let url = format!(
            "https://api.deps.dev/v3alpha/vulnerabilities/{}/{}",
            deps_ecosystem, package
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let resp = client.get(&url).send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        let vulns: DepsDevVulns = resp.json().await.unwrap_or(DepsDevVulns { vulnerabilities: None });

        let advisories: Vec<RawAdvisory> = vulns
            .vulnerabilities
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| {
                let affected = v.affected.clone();
                let pkg = affected.as_ref()?.first()?.package.as_ref()?;
                let vulnerable_versions = affected.as_ref().and_then(|a| a.first()).and_then(|a| {
                    a.ranges.as_ref()?.first().and_then(|r| {
                        r.events.as_ref()?.first().map(|e| {
                            format!(
                                "introduced: {}, fixed: {}",
                                e.introduced.as_deref().unwrap_or("?"),
                                e.fixed.as_deref().unwrap_or("unfixed")
                            )
                        })
                    })
                });
                Some(RawAdvisory {
                    source: "deps_dev".to_string(),
                    id: v.id?,
                    package: pkg.name.clone()?,
                    ecosystem: ecosystem.to_string(),
                    severity: v.severity,
                    summary: v.advisory.as_ref()?.details.clone().unwrap_or_default(),
                    details: None,
                    references: vec![],
                    modified: chrono::Utc::now().to_rfc3339(),
                    published: None,
                    withdrawn: None,
                    vulnerable_versions,
                })
            })
            .collect();

        Ok(advisories)
    }

    async fn fetch_all(&self) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        Ok(vec![])
    }
}
