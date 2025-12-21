//! Organization configuration file parsing.
//!
//! Provides types for loading SCP and RCP hierarchies from a single YAML file
//! instead of multiple CLI flags.

use serde::Deserialize;

/// Configuration for organization policies loaded from YAML.
///
/// The hierarchy represents the path from organization root to the principal's account.
/// AWS SCPs use AND logic between levels (every level must allow) but OR logic
/// within a level (any policy at a level can provide the allow).
#[derive(Debug, Deserialize, Default)]
pub struct OrganizationConfig {
    /// SCP hierarchy configuration
    #[serde(default)]
    pub scp_hierarchy: Option<HierarchyConfig>,

    /// RCP hierarchy configuration
    #[serde(default)]
    pub rcp_hierarchy: Option<HierarchyConfig>,
}

/// Hierarchy configuration for SCP or RCP.
#[derive(Debug, Deserialize, Default)]
pub struct HierarchyConfig {
    /// Policies at organization root level (list of file paths)
    #[serde(default)]
    pub root: Vec<String>,

    /// OU-level policies (ordered from root to account)
    #[serde(default)]
    pub ous: Vec<OuConfig>,

    /// Policies at account level (list of file paths)
    #[serde(default)]
    pub account: Vec<String>,
}

/// Configuration for a single OU in the hierarchy.
#[derive(Debug, Deserialize)]
pub struct OuConfig {
    /// OU identifier (e.g., "ou-xxxx-xxxxxxxx")
    /// Used for clearer error messages
    pub id: String,

    /// Human-readable OU name (optional)
    #[serde(default)]
    pub name: Option<String>,

    /// Policies attached to this OU (list of file paths)
    pub policies: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_full_config() {
        let yaml = r#"
scp_hierarchy:
  root:
    - scp/root-policy.json
  ous:
    - id: ou-engineering
      name: Engineering
      policies:
        - scp/engineering.json
    - id: ou-web-tier
      name: Web Tier
      policies:
        - scp/web-tier.json
  account:
    - scp/account-policy.json

rcp_hierarchy:
  root: []
  ous: []
  account:
    - rcp/s3-restrict.json
"#;

        let config: OrganizationConfig = serde_yml::from_str(yaml).unwrap();

        // Check SCP hierarchy
        let scp = config.scp_hierarchy.unwrap();
        assert_eq!(scp.root.len(), 1);
        assert_eq!(scp.root[0], "scp/root-policy.json");
        assert_eq!(scp.ous.len(), 2);
        assert_eq!(scp.ous[0].id, "ou-engineering");
        assert_eq!(scp.ous[0].name, Some("Engineering".to_string()));
        assert_eq!(scp.ous[0].policies.len(), 1);
        assert_eq!(scp.ous[1].id, "ou-web-tier");
        assert_eq!(scp.account.len(), 1);

        // Check RCP hierarchy
        let rcp = config.rcp_hierarchy.unwrap();
        assert!(rcp.root.is_empty());
        assert!(rcp.ous.is_empty());
        assert_eq!(rcp.account.len(), 1);
    }

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
scp_hierarchy:
  root:
    - policy.json
"#;

        let config: OrganizationConfig = serde_yml::from_str(yaml).unwrap();

        let scp = config.scp_hierarchy.unwrap();
        assert_eq!(scp.root.len(), 1);
        assert!(scp.ous.is_empty());
        assert!(scp.account.is_empty());
        assert!(config.rcp_hierarchy.is_none());
    }

    #[test]
    fn test_parse_empty_config() {
        let yaml = "{}";
        let config: OrganizationConfig = serde_yml::from_str(yaml).unwrap();
        assert!(config.scp_hierarchy.is_none());
        assert!(config.rcp_hierarchy.is_none());
    }
}
