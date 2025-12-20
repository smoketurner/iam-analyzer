//! Fetcher for AWS service definitions from the Service Authorization Reference.

use super::types::{ServiceDefinition, ServiceListEntry};
use crate::error::{Error, Result};

/// Base URL for the AWS Service Authorization Reference API.
const SERVICE_REFERENCE_BASE_URL: &str = "https://servicereference.us-east-1.amazonaws.com";

/// Fetcher for AWS service definitions.
pub struct ServiceFetcher {
    client: reqwest::blocking::Client,
}

impl ServiceFetcher {
    /// Create a new fetcher instance.
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Other(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client })
    }

    /// Fetch the list of all available services.
    pub fn fetch_service_list(&self) -> Result<Vec<ServiceListEntry>> {
        let url = format!("{}/", SERVICE_REFERENCE_BASE_URL);

        let response = self
            .client
            .get(&url)
            .send()
            .map_err(|e| Error::Other(format!("Failed to fetch service list: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Failed to fetch service list: HTTP {}",
                response.status()
            )));
        }

        let services: Vec<ServiceListEntry> = response
            .json()
            .map_err(|e| Error::Other(format!("Failed to parse service list: {}", e)))?;

        Ok(services)
    }

    /// Fetch a specific service definition by name.
    pub fn fetch_service(&self, service_name: &str) -> Result<ServiceDefinition> {
        let url = format!(
            "{}/v1/{}/{}.json",
            SERVICE_REFERENCE_BASE_URL,
            service_name.to_lowercase(),
            service_name.to_lowercase()
        );

        let response = self.client.get(&url).send().map_err(|e| {
            Error::Other(format!("Failed to fetch service '{}': {}", service_name, e))
        })?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Failed to fetch service '{}': HTTP {}",
                service_name,
                response.status()
            )));
        }

        let service: ServiceDefinition = response.json().map_err(|e| {
            Error::Other(format!("Failed to parse service '{}': {}", service_name, e))
        })?;

        Ok(service)
    }

    /// Fetch a service definition from a specific URL.
    pub fn fetch_service_from_url(&self, url: &str) -> Result<ServiceDefinition> {
        let response =
            self.client.get(url).send().map_err(|e| {
                Error::Other(format!("Failed to fetch service from '{}': {}", url, e))
            })?;

        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "Failed to fetch service from '{}': HTTP {}",
                url,
                response.status()
            )));
        }

        let service: ServiceDefinition = response
            .json()
            .map_err(|e| Error::Other(format!("Failed to parse service from '{}': {}", url, e)))?;

        Ok(service)
    }
}

impl Default for ServiceFetcher {
    fn default() -> Self {
        Self::new().expect("Failed to create HTTP client")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires network access
    fn test_fetch_service_list() {
        let fetcher = ServiceFetcher::new().unwrap();
        let services = fetcher.fetch_service_list().unwrap();
        assert!(!services.is_empty());
        assert!(services.iter().any(|s| s.service == "s3"));
    }

    #[test]
    #[ignore] // Requires network access
    fn test_fetch_s3_service() {
        let fetcher = ServiceFetcher::new().unwrap();
        let service = fetcher.fetch_service("s3").unwrap();
        assert_eq!(service.name.to_lowercase(), "s3");
        assert!(!service.actions.is_empty());
        assert!(service.has_action("GetObject"));
    }
}
