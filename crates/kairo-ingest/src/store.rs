use crate::sources::{IntelligenceSource, RawAdvisory};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct IntelligenceStore {
    #[allow(dead_code)]
    advisories: Arc<RwLock<HashMap<String, Vec<RawAdvisory>>>>,
    package_cache: Arc<RwLock<HashMap<String, PackageCacheEntry>>>,
    #[allow(dead_code)]
    last_refresh: Arc<RwLock<std::time::Instant>>,
    max_entries: usize,
    default_ttl_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct PackageCacheEntry {
    pub package: String,
    pub ecosystem: String,
    pub advisories: Vec<RawAdvisory>,
    pub fetched_at: std::time::Instant,
    pub ttl_seconds: u64,
}

impl IntelligenceStore {
    pub fn new(max_entries: usize, default_ttl_seconds: u64) -> Self {
        IntelligenceStore {
            advisories: Arc::new(RwLock::new(HashMap::new())),
            package_cache: Arc::new(RwLock::new(HashMap::new())),
            last_refresh: Arc::new(RwLock::new(std::time::Instant::now())),
            max_entries,
            default_ttl_seconds,
        }
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    pub fn default_ttl_seconds(&self) -> u64 {
        self.default_ttl_seconds
    }

    pub async fn get_advisories(&self, package: &str, ecosystem: &str) -> Vec<RawAdvisory> {
        let cache = self.package_cache.read().await;
        let key = format!("{}:{}", ecosystem, package);

        if let Some(entry) = cache.get(&key) {
            let age = entry.fetched_at.elapsed().as_secs();
            if age < entry.ttl_seconds {
                return entry.advisories.clone();
            }
        }

        vec![]
    }

    pub async fn set_advisories(
        &self,
        package: &str,
        ecosystem: &str,
        advisories: Vec<RawAdvisory>,
        ttl_seconds: u64,
    ) {
        let mut cache = self.package_cache.write().await;
        let key = format!("{}:{}", ecosystem, package);

        // Evict oldest entries if at capacity
        if cache.len() >= self.max_entries && !cache.contains_key(&key) {
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, e)| e.fetched_at)
                .map(|(k, _)| k.clone());
            if let Some(key_to_evict) = oldest_key {
                cache.remove(&key_to_evict);
            }
        }

        cache.insert(
            key,
            PackageCacheEntry {
                package: package.to_string(),
                ecosystem: ecosystem.to_string(),
                advisories: advisories.clone(),
                fetched_at: std::time::Instant::now(),
                ttl_seconds,
            },
        );
    }

    pub async fn set_advisories_default_ttl(
        &self,
        package: &str,
        ecosystem: &str,
        advisories: Vec<RawAdvisory>,
    ) {
        self.set_advisories(package, ecosystem, advisories, self.default_ttl_seconds).await;
    }

    pub async fn is_cached(&self, package: &str, ecosystem: &str) -> bool {
        let cache = self.package_cache.read().await;
        let key = format!("{}:{}", ecosystem, package);

        if let Some(entry) = cache.get(&key) {
            entry.fetched_at.elapsed().as_secs() < entry.ttl_seconds
        } else {
            false
        }
    }

    pub async fn refresh_package<S: IntelligenceSource>(
        &self,
        source: &S,
        package: &str,
        ecosystem: &str,
    ) -> Result<Vec<RawAdvisory>, Box<dyn std::error::Error + Send + Sync>> {
        let advisories = source.fetch(package, ecosystem).await?;

        self.set_advisories_default_ttl(package, ecosystem, advisories.clone()).await;

        Ok(advisories)
    }

    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.package_cache.read().await;
        let total = cache.len();
        let mut stale = 0;

        for entry in cache.values() {
            let age = entry.fetched_at.elapsed().as_secs();
            if age >= entry.ttl_seconds {
                stale += 1;
            }
        }

        CacheStats {
            total_entries: total,
            stale_entries: stale,
            fresh_entries: total - stale,
        }
    }
}

impl Default for IntelligenceStore {
    fn default() -> Self {
        Self::new(10000, 3600)
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub stale_entries: usize,
    pub fresh_entries: usize,
}
