//! Policy AST types.
//!
//! These types represent the structure of an IAM policy document.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A complete IAM policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Policy {
    /// Policy version (2012-10-17 or 2008-10-17)
    #[serde(default)]
    pub version: Option<String>,
    /// Optional policy ID
    #[serde(default)]
    pub id: Option<String>,
    /// Policy statements
    pub statement: Vec<Statement>,
}

/// A single policy statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    /// Optional statement ID
    #[serde(default)]
    pub sid: Option<String>,
    /// Effect: Allow or Deny
    pub effect: Effect,
    /// Principal block (for resource-based policies)
    #[serde(default)]
    pub principal: Option<PrincipalBlock>,
    /// NotPrincipal block
    #[serde(default)]
    pub not_principal: Option<PrincipalBlock>,
    /// Action block
    #[serde(default)]
    pub action: Option<ActionBlock>,
    /// NotAction block
    #[serde(default)]
    pub not_action: Option<ActionBlock>,
    /// Resource block
    #[serde(default)]
    pub resource: Option<ResourceBlock>,
    /// NotResource block
    #[serde(default)]
    pub not_resource: Option<ResourceBlock>,
    /// Condition block
    #[serde(default)]
    pub condition: Option<ConditionBlock>,
}

/// Effect: Allow or Deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
}

/// Principal block - can be "*" or a map of principal types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PrincipalBlock {
    /// Wildcard principal - matches everyone
    Wildcard(String),
    /// Map of principal types to principal IDs
    Map(HashMap<String, Principal>),
}

/// A principal value - can be a single string or array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Principal {
    Single(String),
    Multiple(Vec<String>),
}

/// Action block - can be "*", a single action, or array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ActionBlock {
    Single(String),
    Multiple(Vec<String>),
}

/// Resource block - can be "*", a single resource, or array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceBlock {
    Single(String),
    Multiple(Vec<String>),
}

/// Condition block - map of operator to conditions.
pub type ConditionBlock = HashMap<String, HashMap<String, Condition>>;

/// A condition value - can be a single value or array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Condition {
    Single(serde_json::Value),
    Multiple(Vec<serde_json::Value>),
}

/// Parsed condition operator with modifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionOperator {
    /// The base operator (StringEquals, NumericLessThan, etc.)
    pub base: String,
    /// ForAllValues modifier
    pub for_all_values: bool,
    /// ForAnyValue modifier
    pub for_any_value: bool,
    /// IfExists modifier
    pub if_exists: bool,
}

impl ConditionOperator {
    /// Parse a condition operator string.
    pub fn parse(s: &str) -> Self {
        let mut remaining = s;
        let mut for_all_values = false;
        let mut for_any_value = false;

        // Check for set operator prefixes
        if let Some(rest) = remaining.strip_prefix("ForAllValues:") {
            for_all_values = true;
            remaining = rest;
        } else if let Some(rest) = remaining.strip_prefix("ForAnyValue:") {
            for_any_value = true;
            remaining = rest;
        }

        // Check for IfExists suffix
        let (base, if_exists) = if let Some(base) = remaining.strip_suffix("IfExists") {
            (base.to_string(), true)
        } else {
            (remaining.to_string(), false)
        };

        Self {
            base,
            for_all_values,
            for_any_value,
            if_exists,
        }
    }
}

impl ActionBlock {
    /// Convert to a vector of action strings.
    pub fn to_vec(&self) -> Vec<&str> {
        match self {
            ActionBlock::Single(s) => vec![s.as_str()],
            ActionBlock::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

impl ResourceBlock {
    /// Convert to a vector of resource strings.
    pub fn to_vec(&self) -> Vec<&str> {
        match self {
            ResourceBlock::Single(s) => vec![s.as_str()],
            ResourceBlock::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

impl Principal {
    /// Convert to a vector of principal strings.
    pub fn to_vec(&self) -> Vec<&str> {
        match self {
            Principal::Single(s) => vec![s.as_str()],
            Principal::Multiple(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_policy() {
        let json = r#"{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(policy.version, Some("2012-10-17".to_string()));
        assert_eq!(policy.statement.len(), 1);
        assert_eq!(policy.statement[0].effect, Effect::Allow);
    }

    #[test]
    fn test_parse_multi_action_policy() {
        let json = r#"{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*"
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        let stmt = &policy.statement[0];
        if let Some(ActionBlock::Multiple(actions)) = &stmt.action {
            assert_eq!(actions.len(), 2);
        } else {
            panic!("Expected multiple actions");
        }
    }

    #[test]
    fn test_parse_principal_wildcard() {
        let json = r#"{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        let stmt = &policy.statement[0];
        assert!(matches!(stmt.principal, Some(PrincipalBlock::Wildcard(_))));
    }

    #[test]
    fn test_parse_principal_map() {
        let json = r#"{
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        let stmt = &policy.statement[0];
        if let Some(PrincipalBlock::Map(map)) = &stmt.principal {
            assert!(map.contains_key("AWS"));
        } else {
            panic!("Expected principal map");
        }
    }

    #[test]
    fn test_parse_condition() {
        let json = r#"{
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": {
                        "StringNotEquals": {
                            "aws:PrincipalAccount": "123456789012"
                        }
                    }
                }
            ]
        }"#;

        let policy: Policy = serde_json::from_str(json).unwrap();
        let stmt = &policy.statement[0];
        let condition = stmt.condition.as_ref().unwrap();
        assert!(condition.contains_key("StringNotEquals"));
    }

    #[test]
    fn test_condition_operator_parse() {
        let op = ConditionOperator::parse("StringEquals");
        assert_eq!(op.base, "StringEquals");
        assert!(!op.for_all_values);
        assert!(!op.for_any_value);
        assert!(!op.if_exists);

        let op = ConditionOperator::parse("StringEqualsIfExists");
        assert_eq!(op.base, "StringEquals");
        assert!(op.if_exists);

        let op = ConditionOperator::parse("ForAllValues:StringEquals");
        assert_eq!(op.base, "StringEquals");
        assert!(op.for_all_values);

        let op = ConditionOperator::parse("ForAnyValue:StringLikeIfExists");
        assert_eq!(op.base, "StringLike");
        assert!(op.for_any_value);
        assert!(op.if_exists);
    }
}
