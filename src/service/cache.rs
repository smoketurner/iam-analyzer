//! Local cache for AWS service definitions.

use super::types::ServiceDefinition;
use crate::error::{Error, Result};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

/// Cache for service definitions stored on disk.
pub struct ServiceCache {
    cache_dir: PathBuf,
}

impl ServiceCache {
    /// Create a new cache instance.
    ///
    /// Returns None if the cache directory cannot be determined.
    pub fn new() -> Option<Self> {
        let project_dirs = ProjectDirs::from("com", "iam-analyzer", "iam-analyzer")?;
        let cache_dir = project_dirs.cache_dir().join("services");
        Some(Self { cache_dir })
    }

    /// Get the cache directory path.
    pub fn cache_dir(&self) -> &PathBuf {
        &self.cache_dir
    }

    /// Ensure the cache directory exists.
    fn ensure_cache_dir(&self) -> Result<()> {
        if !self.cache_dir.exists() {
            fs::create_dir_all(&self.cache_dir).map_err(|e| Error::FileRead {
                path: self.cache_dir.display().to_string(),
                source: e,
            })?;
        }
        Ok(())
    }

    /// Get the cache file path for a service.
    fn service_path(&self, service_name: &str) -> PathBuf {
        self.cache_dir
            .join(format!("{}.json", service_name.to_lowercase()))
    }

    /// Check if a service is cached.
    pub fn has(&self, service_name: &str) -> bool {
        self.service_path(service_name).exists()
    }

    /// Load a service definition from cache.
    pub fn load(&self, service_name: &str) -> Result<Option<ServiceDefinition>> {
        let path = self.service_path(service_name);
        if !path.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(&path).map_err(|e| Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;

        let service: ServiceDefinition = serde_json::from_str(&content)?;
        Ok(Some(service))
    }

    /// Save a service definition to cache.
    pub fn save(&self, service: &ServiceDefinition) -> Result<()> {
        self.ensure_cache_dir()?;

        let path = self.service_path(&service.name);
        let content = serde_json::to_string_pretty(service)?;

        fs::write(&path, content).map_err(|e| Error::FileRead {
            path: path.display().to_string(),
            source: e,
        })?;

        Ok(())
    }

    /// List all cached service names.
    pub fn list_cached(&self) -> Result<Vec<String>> {
        if !self.cache_dir.exists() {
            return Ok(Vec::new());
        }

        let mut services = Vec::new();
        let entries = fs::read_dir(&self.cache_dir).map_err(|e| Error::FileRead {
            path: self.cache_dir.display().to_string(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| Error::FileRead {
                path: self.cache_dir.display().to_string(),
                source: e,
            })?;

            if let Some(name) = entry.path().file_stem()
                && let Some(name_str) = name.to_str()
            {
                services.push(name_str.to_string());
            }
        }

        Ok(services)
    }

    /// Clear all cached service definitions.
    pub fn clear(&self) -> Result<()> {
        if self.cache_dir.exists() {
            fs::remove_dir_all(&self.cache_dir).map_err(|e| Error::FileRead {
                path: self.cache_dir.display().to_string(),
                source: e,
            })?;
        }
        Ok(())
    }
}

impl Default for ServiceCache {
    fn default() -> Self {
        Self::new().expect("Failed to determine cache directory")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static TEST_COUNTER: AtomicU32 = AtomicU32::new(0);

    /// Create a unique cache directory per test to avoid race conditions
    /// when tests run in parallel.
    fn test_cache() -> ServiceCache {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_dir = std::env::temp_dir().join(format!(
            "iam-analyzer-test-cache-{}-{}",
            std::process::id(),
            id
        ));
        ServiceCache {
            cache_dir: temp_dir,
        }
    }

    #[test]
    fn test_cache_save_and_load() {
        let cache = test_cache();
        let _ = cache.clear();

        let service = ServiceDefinition {
            name: "testservice".to_string(),
            actions: vec![],
            resources: vec![],
            condition_keys: vec![],
        };

        cache.save(&service).unwrap();
        assert!(cache.has("testservice"));

        let loaded = cache.load("testservice").unwrap().unwrap();
        assert_eq!(loaded.name, "testservice");

        let _ = cache.clear();
    }

    #[test]
    fn test_cache_missing_service() {
        let cache = test_cache();
        let _ = cache.clear();

        assert!(!cache.has("nonexistent"));
        assert!(cache.load("nonexistent").unwrap().is_none());

        let _ = cache.clear();
    }
}
