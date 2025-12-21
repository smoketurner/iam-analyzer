//! Types for AWS service definitions from the Service Authorization Reference.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A service definition from the AWS Service Authorization Reference.
///
/// # Examples
///
/// ```
/// use iam_analyzer::ServiceDefinition;
///
/// let json = r#"{
///     "Name": "s3",
///     "Actions": [
///         {"Name": "GetObject", "ActionConditionKeys": [], "Resources": []},
///         {"Name": "PutObject", "ActionConditionKeys": [], "Resources": []}
///     ],
///     "Resources": [],
///     "ConditionKeys": []
/// }"#;
///
/// let service: ServiceDefinition = serde_json::from_str(json).unwrap();
/// assert_eq!(service.name, "s3");
/// assert!(service.has_action("GetObject"));
/// assert!(service.has_action("putobject")); // case-insensitive
/// assert!(!service.has_action("DeleteObject"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ServiceDefinition {
    /// Service name (e.g., "s3", "iam", "ec2").
    pub name: String,

    /// List of actions supported by this service.
    #[serde(default)]
    pub actions: Vec<ActionDefinition>,

    /// List of resource types for this service.
    #[serde(default)]
    pub resources: Vec<ResourceDefinition>,

    /// List of condition keys for this service.
    #[serde(default)]
    pub condition_keys: Vec<ConditionKeyDefinition>,
}

/// An action definition within a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActionDefinition {
    /// Action name (e.g., "GetObject", "PutObject").
    pub name: String,

    /// Condition keys applicable to this action.
    #[serde(default)]
    pub action_condition_keys: Vec<String>,

    /// Resources this action can operate on.
    #[serde(default)]
    pub resources: Vec<ActionResource>,

    /// Action metadata annotations.
    #[serde(default)]
    pub annotations: Option<ActionAnnotations>,
}

/// A resource reference within an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActionResource {
    /// Resource name (e.g., "object", "bucket").
    pub name: String,

    /// Whether this resource is required.
    #[serde(default)]
    pub required: bool,
}

/// Annotations/metadata for an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActionAnnotations {
    /// Action properties.
    #[serde(default)]
    pub properties: Option<ActionProperties>,
}

/// Properties describing the action type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ActionProperties {
    /// Whether this is a list/discovery action.
    #[serde(default)]
    pub is_list: bool,

    /// Whether this is a write action.
    #[serde(default)]
    pub is_write: bool,

    /// Whether this is a permission management action.
    #[serde(default)]
    pub is_permission_management: bool,

    /// Whether this action only modifies tags.
    #[serde(default)]
    pub is_tagging_only: bool,
}

/// A resource type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ResourceDefinition {
    /// Resource name (e.g., "bucket", "object").
    pub name: String,

    /// ARN format for this resource.
    #[serde(default)]
    pub arn: Option<String>,

    /// Condition keys applicable to this resource.
    #[serde(default)]
    pub condition_keys: Vec<String>,
}

/// A condition key definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ConditionKeyDefinition {
    /// Condition key name (e.g., "s3:x-amz-acl").
    pub name: String,

    /// Condition key type (e.g., "String", "Numeric", "Date").
    #[serde(rename = "Type", default)]
    pub key_type: Option<String>,
}

/// Entry in the service list from the API root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceListEntry {
    /// Service name.
    pub service: String,

    /// URL to fetch the service definition.
    pub url: String,
}

impl ServiceDefinition {
    /// Check if an action exists in this service.
    pub fn has_action(&self, action_name: &str) -> bool {
        self.actions
            .iter()
            .any(|a| a.name.eq_ignore_ascii_case(action_name))
    }

    /// Get an action definition by name.
    pub fn get_action(&self, action_name: &str) -> Option<&ActionDefinition> {
        self.actions
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(action_name))
    }

    /// Get all action names for fuzzy matching suggestions.
    pub fn action_names(&self) -> Vec<&str> {
        self.actions.iter().map(|a| a.name.as_str()).collect()
    }

    /// Get all condition keys for this service.
    pub fn all_condition_keys(&self) -> Vec<&str> {
        self.condition_keys
            .iter()
            .map(|k| k.name.as_str())
            .collect()
    }
}

impl ActionDefinition {
    /// Check if a condition key is valid for this action.
    pub fn has_condition_key(&self, key: &str) -> bool {
        self.action_condition_keys
            .iter()
            .any(|k| k.eq_ignore_ascii_case(key))
    }
}

/// Registry of loaded service definitions.
#[derive(Debug, Default)]
pub struct ServiceRegistry {
    /// Loaded service definitions by service name (lowercase).
    services: HashMap<String, ServiceDefinition>,
}

impl ServiceRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a service definition to the registry.
    pub fn add(&mut self, service: ServiceDefinition) {
        self.services.insert(service.name.to_lowercase(), service);
    }

    /// Get a service definition by name.
    pub fn get(&self, service_name: &str) -> Option<&ServiceDefinition> {
        self.services.get(&service_name.to_lowercase())
    }

    /// Check if a service is loaded.
    pub fn has(&self, service_name: &str) -> bool {
        self.services.contains_key(&service_name.to_lowercase())
    }

    /// Get all loaded service names.
    pub fn service_names(&self) -> Vec<&str> {
        self.services.keys().map(|s| s.as_str()).collect()
    }
}
