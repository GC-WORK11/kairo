use super::{IntelligenceSource, RawAdvisory};
use std::error::Error;

pub struct GithubAdvisoriesSource {
    gh_token: Option<String>,
}

impl GithubAdvisoriesSource {
    pub fn new(gh_token: Option<String>) -> Self {
        GithubAdvisoriesSource { gh_token }
    }
}

impl Default for GithubAdvisoriesSource {
    fn default() -> Self {
        Self::new(None)
    }
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct GhAdvisoryResponse {
    advisory: GhAdvisory,
    #[serde(rename = "ghsaId")]
    ghsa_id: String,
}

#[derive(serde::Deserialize)]
struct GhAdvisory {
    description: Option<String>,
    severity: Option<String>,
    published_at: Option<String>,
    updated_at: Option<String>,
    withdrawn_at: Option<String>,
    references: Option<Vec<GhReference>>,
    vulnerabilities: Option<Vec<GhVuln>>,
}

#[derive(serde::Deserialize)]
struct GhReference {
    url: Option<String>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct GhVuln {
    package: Option<GhPackage>,
    vulnerable_version_range: Option<String>,
    first_patched_version: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
#[allow(dead_code)]
struct GhPackage {
    ecosystem: Option<String>,
    name: Option<String>,
}

#[async_trait::async_trait]
impl IntelligenceSource for GithubAdvisoriesSource {
    fn name(&self) -> &str {
        "github_advisories"
    }

    async fn fetch(&self, package: &str, ecosystem: &str) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        let gh_ecosystem = match ecosystem {
            "npm" | "pnpm" | "yarn" | "bun" => "NPM",
            "pip" => "PIP",
            "cargo" => "CARGO",
            "go" => "GO",
            "docker" => "CONTAINER",
            _ => "NPM",
        };

        let url = format!(
            "https://api.github.com/advisories?affects={}%2F{}",
            gh_ecosystem.to_lowercase(),
            package
        );

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        let mut req = client.get(&url);
        if let Some(token) = &self.gh_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }
        req = req.header("Accept", "application/vnd.github+json");

        let resp = req.send().await?;
        if !resp.status().is_success() {
            return Ok(vec![]);
        }

        #[derive(serde::Deserialize)]
        struct GhAdvisoryList {
            #[serde(rename = "ghsa_advisory_id")]
            ghsa_id: Option<String>,
            advisory: GhAdvisory,
        }

        let advisories: Vec<GhAdvisoryList> = resp.json().await.unwrap_or_default();

        let results: Vec<RawAdvisory> = advisories
            .into_iter()
            .filter_map(|a| {
                let vuln = a.advisory.vulnerabilities?.into_iter().next()?;
                let pkg = vuln.package?;
                Some(RawAdvisory {
                    source: "github_advisories".to_string(),
                    id: a.ghsa_id?,
                    package: pkg.name?,
                    ecosystem: ecosystem.to_string(),
                    severity: a.advisory.severity.clone(),
                    summary: a.advisory.description?,
                    details: None,
                    references: a.advisory.references
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|r| r.url)
                        .collect(),
                    modified: a.advisory.updated_at?,
                    published: a.advisory.published_at,
                    withdrawn: a.advisory.withdrawn_at,
                    vulnerable_versions: vuln.vulnerable_version_range,
                })
            })
            .collect();

        Ok(results)
    }

    async fn fetch_all(&self) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>> {
        Ok(vec![])
    }
}
