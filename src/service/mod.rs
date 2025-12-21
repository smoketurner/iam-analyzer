//! AWS service definitions for policy validation.
//!
//! This module provides access to AWS service definitions from the
//! Service Authorization Reference, enabling validation of:
//! - Action names
//! - Condition keys
//! - Resource ARN formats
//!
//! Service definitions are cached locally and fetched on-demand.

mod cache;
mod fetcher;
pub mod types;

pub use cache::ServiceCache;
pub use fetcher::ServiceFetcher;
pub use types::{ActionDefinition, ServiceDefinition, ServiceRegistry};

use crate::error::Result;

/// Service loader that manages fetching and caching of service definitions.
///
/// # Examples
///
/// ```
/// use iam_analyzer::ServiceLoader;
///
/// // Create a loader in offline mode (no network requests)
/// let loader = ServiceLoader::new(true);
/// assert!(loader.is_offline());
/// ```
pub struct ServiceLoader {
    cache: Option<ServiceCache>,
    fetcher: Option<ServiceFetcher>,
    offline: bool,
}

impl ServiceLoader {
    /// Create a new service loader.
    ///
    /// # Arguments
    /// * `offline` - If true, only use cached data (no network requests)
    pub fn new(offline: bool) -> Self {
        let cache = ServiceCache::new();
        let fetcher = if offline {
            None
        } else {
            ServiceFetcher::new().ok()
        };

        Self {
            cache,
            fetcher,
            offline,
        }
    }

    /// Check if the loader is in offline mode.
    pub fn is_offline(&self) -> bool {
        self.offline
    }

    /// Check if service definitions are available (cached or fetchable).
    pub fn is_available(&self) -> bool {
        self.cache.is_some() || self.fetcher.is_some()
    }

    /// Load a service definition by name.
    ///
    /// Returns None if:
    /// - In offline mode and service is not cached
    /// - Service cannot be fetched (network error, unknown service)
    pub fn load(&self, service_name: &str) -> Result<Option<ServiceDefinition>> {
        // Try to load from cache first
        if let Some(cache) = &self.cache
            && let Some(service) = cache.load(service_name)?
        {
            return Ok(Some(service));
        }

        // If offline, we can't fetch
        if self.offline {
            return Ok(None);
        }

        // Try to fetch from API
        if let Some(fetcher) = &self.fetcher {
            match fetcher.fetch_service(service_name) {
                Ok(service) => {
                    // Cache the fetched service
                    if let Some(cache) = &self.cache {
                        let _ = cache.save(&service);
                    }
                    return Ok(Some(service));
                }
                Err(_) => {
                    // Service not found or fetch error
                    return Ok(None);
                }
            }
        }

        Ok(None)
    }

    /// Force refresh of a service definition from the API.
    ///
    /// Returns None if in offline mode or fetch fails.
    pub fn refresh(&self, service_name: &str) -> Result<Option<ServiceDefinition>> {
        if self.offline {
            return Ok(None);
        }

        if let Some(fetcher) = &self.fetcher {
            match fetcher.fetch_service(service_name) {
                Ok(service) => {
                    if let Some(cache) = &self.cache {
                        let _ = cache.save(&service);
                    }
                    return Ok(Some(service));
                }
                Err(_) => return Ok(None),
            }
        }

        Ok(None)
    }

    /// Check if a service is cached.
    pub fn is_cached(&self, service_name: &str) -> bool {
        self.cache
            .as_ref()
            .map(|c| c.has(service_name))
            .unwrap_or(false)
    }

    /// List all cached services.
    pub fn list_cached(&self) -> Result<Vec<String>> {
        if let Some(cache) = &self.cache {
            cache.list_cached()
        } else {
            Ok(Vec::new())
        }
    }

    /// Refresh all cached services from the API.
    pub fn refresh_all(&self) -> Result<usize> {
        if self.offline {
            return Ok(0);
        }

        let cached = self.list_cached()?;
        let mut refreshed = 0;

        for service_name in cached {
            if self.refresh(&service_name)?.is_some() {
                refreshed += 1;
            }
        }

        Ok(refreshed)
    }
}

impl Default for ServiceLoader {
    fn default() -> Self {
        Self::new(false)
    }
}

/// Extract the service name from an action string (e.g., "s3:GetObject" -> "s3").
pub fn extract_service_name(action: &str) -> Option<&str> {
    action.split(':').next()
}

/// Extract the action name from an action string (e.g., "s3:GetObject" -> "GetObject").
pub fn extract_action_name(action: &str) -> Option<&str> {
    action.split(':').nth(1)
}

/// Check if an action string contains wildcards.
pub fn has_wildcard(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_service_name() {
        assert_eq!(extract_service_name("s3:GetObject"), Some("s3"));
        assert_eq!(extract_service_name("iam:CreateUser"), Some("iam"));
        assert_eq!(extract_service_name("ec2:*"), Some("ec2"));
        assert_eq!(extract_service_name("invalid"), Some("invalid"));
    }

    #[test]
    fn test_extract_action_name() {
        assert_eq!(extract_action_name("s3:GetObject"), Some("GetObject"));
        assert_eq!(extract_action_name("iam:CreateUser"), Some("CreateUser"));
        assert_eq!(extract_action_name("ec2:*"), Some("*"));
        assert_eq!(extract_action_name("invalid"), None);
    }

    #[test]
    fn test_has_wildcard() {
        assert!(has_wildcard("s3:*"));
        assert!(has_wildcard("s3:Get*"));
        assert!(has_wildcard("s3:Get?bject"));
        assert!(!has_wildcard("s3:GetObject"));
    }

    #[test]
    fn test_offline_loader() {
        let loader = ServiceLoader::new(true);
        assert!(loader.is_offline());
        // Should return None for uncached service
        assert!(loader.load("nonexistent").unwrap().is_none());
    }
}
