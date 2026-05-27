use async_trait::async_trait;
use kairo_core::{Action, PackageIntelligence, Verdict, VerdictType, Evidence};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

#[async_trait]
pub trait Plugin: Send + Sync {
    fn name(&self) -> &str;
    fn clone_box(&self) -> Box<dyn Plugin>;
    async fn check(&self, action: Action, intelligence: PackageIntelligence) -> Option<Verdict>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    pub enabled: Option<bool>,
    #[serde(flatten)]
    pub settings: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginResponse {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginInfo {
    pub id: String,
    pub name: String,
}

type PluginMap = HashMap<String, (String, Box<dyn Plugin>)>;

pub struct PluginRegistry {
    plugins: RwLock<PluginMap>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, plugin: Box<dyn Plugin>) -> String {
        let id = Uuid::new_v4().to_string();
        let name = plugin.name().to_string();
        let mut plugins = self.plugins.write().unwrap();
        plugins.insert(id.clone(), (name, plugin));
        id
    }

    pub fn unregister(&self, id: &str) -> bool {
        let mut plugins = self.plugins.write().unwrap();
        plugins.remove(id).is_some()
    }

    pub fn get_plugins(&self) -> Vec<Box<dyn Plugin>> {
        let plugins = self.plugins.read().unwrap();
        plugins.values().map(|(_, p)| p.clone_box()).collect()
    }

    pub fn list(&self) -> Vec<PluginInfo> {
        let plugins = self.plugins.read().unwrap();
        plugins.iter().map(|(id, (name, _))| PluginInfo {
            id: id.clone(),
            name: name.clone(),
        }).collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Built-in plugin implementation for V1
pub struct BuiltInPlugin {
    config: PluginConfig,
}

impl BuiltInPlugin {
    pub fn new(config: PluginConfig) -> Self {
        Self { config }
    }

    async fn check_internal(&self, _action: Action, intelligence: PackageIntelligence) -> Option<Verdict> {
        // Example: block packages with postinstall scripts if configured
        if self.config.settings.get("block_postinstall").and_then(|v| v.as_bool()).unwrap_or(false)
            && intelligence.has_postinstall_script
        {
            return Some(Verdict {
                verdict: VerdictType::Block,
                risk_score: 100,
                title: "Blocked by plugin".to_string(),
                summary: "Package has postinstall script".to_string(),
                recommended_action: Some("Review the postinstall script before proceeding".to_string()),
                safe_command: None,
                evidence: vec![Evidence {
                    evidence_type: "postinstall".to_string(),
                    source: "plugin".to_string(),
                    detail: "postinstall script detected".to_string(),
                }],
            });
        }

        // Example: block packages older than configured threshold
        if let Some(max_age_days) = self.config.settings.get("max_age_days").and_then(|v| v.as_i64()) {
            if let Some(age_seconds) = intelligence.publish_age_seconds {
                let age_days = age_seconds as i64 / 86400;
                if age_days > max_age_days {
                    return Some(Verdict {
                        verdict: VerdictType::Block,
                        risk_score: 80,
                        title: "Blocked by plugin".to_string(),
                        summary: format!("Package is older than {} days", max_age_days),
                        recommended_action: Some("Consider using a newer version".to_string()),
                        safe_command: None,
                        evidence: vec![Evidence {
                            evidence_type: "age".to_string(),
                            source: "plugin".to_string(),
                            detail: format!("package age: {} days", age_days),
                        }],
                    });
                }
            }
        }

        // Example: warn on packages without provenance
        if self.config.settings.get("warn_no_provenance").and_then(|v| v.as_bool()).unwrap_or(false)
            && !intelligence.has_provenance
        {
            return Some(Verdict {
                verdict: VerdictType::Warn,
                risk_score: 50,
                title: "Warned by plugin".to_string(),
                summary: "Package has no provenance".to_string(),
                recommended_action: Some("Verify package integrity manually".to_string()),
                safe_command: None,
                evidence: vec![Evidence {
                    evidence_type: "provenance".to_string(),
                    source: "plugin".to_string(),
                    detail: "no provenance information available".to_string(),
                }],
            });
        }

        None
    }
}

#[async_trait]
impl Plugin for BuiltInPlugin {
    fn name(&self) -> &str {
        &self.config.name
    }

    fn clone_box(&self) -> Box<dyn Plugin> {
        Box::new(BuiltInPlugin {
            config: self.config.clone(),
        })
    }

    async fn check(&self, action: Action, intelligence: PackageIntelligence) -> Option<Verdict> {
        self.check_internal(action, intelligence).await
    }
}
