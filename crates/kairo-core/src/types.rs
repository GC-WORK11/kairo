#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Action {
    pub action_type: ActionType,
    pub ecosystem: Ecosystem,
    pub command: String,
    pub package: Option<String>,
    pub version: Option<String>,
    pub repo_context: RepoContext,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoContext {
    pub framework: Option<String>,
    pub has_database: bool,
    pub has_ci: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ActionType {
    PackageInstall,
    CommandExec,
    CiChange,
    Migration,
    InfraEdit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(non_camel_case_types)]
pub enum Ecosystem {
    npm,
    pnpm,
    yarn,
    bun,
    pip,
    cargo,
    go,
    docker,
}

impl Ecosystem {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Ecosystem> {
        match s.to_lowercase().as_str() {
            "npm" => Some(Ecosystem::npm),
            "pnpm" => Some(Ecosystem::pnpm),
            "yarn" => Some(Ecosystem::yarn),
            "bun" => Some(Ecosystem::bun),
            "pip" => Some(Ecosystem::pip),
            "cargo" => Some(Ecosystem::cargo),
            "go" => Some(Ecosystem::go),
            "docker" => Some(Ecosystem::docker),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Verdict {
    pub verdict: VerdictType,
    pub risk_score: u8,
    pub title: String,
    pub summary: String,
    pub recommended_action: Option<String>,
    pub safe_command: Option<String>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerdictType {
    Allow,
    Warn,
    Block,
}

impl std::fmt::Display for VerdictType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerdictType::Allow => write!(f, "ALLOW"),
            VerdictType::Warn => write!(f, "WARN"),
            VerdictType::Block => write!(f, "BLOCK"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageIntelligence {
    pub package: String,
    pub version: Option<String>,
    pub ecosystem: Ecosystem,
    pub publish_age_seconds: Option<u64>,
    pub has_postinstall_script: bool,
    pub has_prepare_script: bool,
    pub has_install_script: bool,
    pub osv_advisories: Vec<OsvAdvisory>,
    pub has_provenance: bool,
    pub license: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OsvAdvisory {
    pub id: String,
    pub severity: String,
    pub summary: String,
    pub modified: String,
}

impl Action {
    pub fn test_package(ecosystem: Ecosystem, package: &str, version: &str) -> Self {
        Action {
            action_type: ActionType::PackageInstall,
            ecosystem,
            command: format!("{} add {}@{}", match ecosystem {
                Ecosystem::npm => "npm",
                Ecosystem::pnpm => "pnpm",
                Ecosystem::yarn => "yarn",
                Ecosystem::bun => "bun",
                Ecosystem::pip => "pip",
                Ecosystem::cargo => "cargo",
                Ecosystem::go => "go",
                Ecosystem::docker => "docker",
            }, package, version),
            package: Some(package.to_string()),
            version: Some(version.to_string()),
            repo_context: RepoContext {
                framework: None,
                has_database: false,
                has_ci: false,
            },
        }
    }
}

impl PackageIntelligence {
    pub fn test_package(package: &str) -> Self {
        PackageIntelligence {
            package: package.to_string(),
            version: None,
            ecosystem: Ecosystem::npm,
            publish_age_seconds: None,
            has_postinstall_script: false,
            has_prepare_script: false,
            has_install_script: false,
            osv_advisories: vec![],
            has_provenance: false,
            license: None,
        }
    }

    pub fn with_age(mut self, seconds: u64) -> Self {
        self.publish_age_seconds = Some(seconds);
        self
    }

    pub fn with_advisory(mut self, id: &str, severity: &str) -> Self {
        self.osv_advisories.push(OsvAdvisory {
            id: id.to_string(),
            severity: severity.to_string(),
            summary: format!("Test advisory {}", id),
            modified: "2024-01-01T00:00:00Z".to_string(),
        });
        self
    }

    pub fn with_license(mut self, license: &str) -> Self {
        self.license = Some(license.to_string());
        self
    }
}
