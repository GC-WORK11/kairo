pub mod osv;
pub mod npm_registry;
pub mod github_advisories;
pub mod deps_dev;

pub use osv::OsvSource;
pub use npm_registry::NpmRegistrySource;
pub use github_advisories::GithubAdvisoriesSource;
pub use deps_dev::DepsDevSource;

use serde::{Deserialize, Serialize};
use std::error::Error;

#[async_trait::async_trait]
pub trait IntelligenceSource: Send + Sync {
    fn name(&self) -> &str;
    async fn fetch(&self, package: &str, ecosystem: &str) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>>;
    async fn fetch_all(&self) -> Result<Vec<RawAdvisory>, Box<dyn Error + Send + Sync>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawAdvisory {
    pub source: String,
    pub id: String,
    pub package: String,
    pub ecosystem: String,
    pub severity: Option<String>,
    pub summary: String,
    pub details: Option<String>,
    pub references: Vec<String>,
    pub modified: String,
    pub published: Option<String>,
    pub withdrawn: Option<String>,
    pub vulnerable_versions: Option<String>,
}
