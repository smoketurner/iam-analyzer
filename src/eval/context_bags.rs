//! Context bags for IAM condition key evaluation.
//!
//! AWS IAM internally uses separate "context bags" for different scopes of a request.
//! This module implements that architecture with typed stores for:
//! - Principal context (who is making the request)
//! - Resource context (what is being accessed)
//! - Request context (properties of the request itself)
//! - Network context (network properties)
//! - Session context (role session properties)

use std::collections::HashMap;

/// Typed condition value preserving semantics.
///
/// AWS condition keys have different value types that affect how they're evaluated.
/// This enum preserves that type information for proper condition matching.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionValue {
    /// Single string value
    String(String),
    /// Multiple string values (for multi-valued keys like aws:CalledVia)
    StringList(Vec<String>),
    /// Boolean value (for aws:SecureTransport, aws:MultiFactorAuthPresent, etc.)
    Bool(bool),
    /// Integer value (for aws:MultiFactorAuthAge, aws:EpochTime)
    Integer(i64),
    /// DateTime value in ISO 8601 format (for aws:CurrentTime, aws:TokenIssueTime)
    DateTime(String),
    /// IP address value (for aws:SourceIp, aws:VpcSourceIp)
    IpAddress(String),
}

impl ConditionValue {
    /// Convert to string representation(s) for condition evaluation.
    ///
    /// This is the unified interface for ConditionEvaluator - all values
    /// are ultimately compared as strings.
    pub fn to_strings(&self) -> Option<Vec<String>> {
        match self {
            ConditionValue::String(s) => Some(vec![s.clone()]),
            ConditionValue::StringList(v) if v.is_empty() => None,
            ConditionValue::StringList(v) => Some(v.clone()),
            ConditionValue::Bool(b) => Some(vec![b.to_string()]),
            ConditionValue::Integer(i) => Some(vec![i.to_string()]),
            ConditionValue::DateTime(s) => Some(vec![s.clone()]),
            ConditionValue::IpAddress(s) => Some(vec![s.clone()]),
        }
    }

    /// Get first value as string (for single-value contexts).
    pub fn first_string(&self) -> Option<String> {
        self.to_strings().and_then(|v| v.into_iter().next())
    }

    /// Check if this is a boolean value and return it.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ConditionValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Check if this is an integer value and return it.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            ConditionValue::Integer(i) => Some(*i),
            _ => None,
        }
    }
}

/// A context bag - holds condition key/value pairs for a specific scope.
///
/// This is the core storage type. Keys are stored in lowercase for
/// case-insensitive matching per AWS IAM behavior.
#[derive(Debug, Clone, Default)]
pub struct ContextBag {
    values: HashMap<String, ConditionValue>,
}

impl ContextBag {
    /// Create a new empty context bag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a condition key value.
    ///
    /// Keys are stored as-is. Callers should handle case-sensitivity appropriately:
    /// - For non-tag keys, lowercase before calling set()
    /// - For tag keys, preserve the original case of the tag key portion
    pub fn set(&mut self, key: &str, value: ConditionValue) {
        self.values.insert(key.to_string(), value);
    }

    /// Get a condition value by key.
    ///
    /// Keys are matched exactly. Callers should handle case-sensitivity appropriately.
    pub fn get(&self, key: &str) -> Option<&ConditionValue> {
        self.values.get(key)
    }

    /// Get string representation for condition evaluation.
    pub fn get_strings(&self, key: &str) -> Option<Vec<String>> {
        self.get(key).and_then(|v| v.to_strings())
    }

    /// Check if a key exists in the bag.
    pub fn contains(&self, key: &str) -> bool {
        self.values.contains_key(key)
    }

    /// Get all keys in the bag.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.values.keys()
    }

    /// Check if the bag is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Principal context - who is making the request.
///
/// Contains condition keys related to the principal (identity) making the request:
/// - aws:PrincipalArn, aws:PrincipalAccount, aws:PrincipalOrgID, aws:PrincipalOrgPaths
/// - aws:PrincipalTag/*, aws:PrincipalType, aws:PrincipalIsAWSService
/// - aws:PrincipalServiceName, aws:PrincipalServiceNamesList
/// - aws:userid, aws:username
#[derive(Debug, Clone, Default)]
pub struct PrincipalContext {
    bag: ContextBag,
    /// Whether the principal is a service-linked role (bypasses SCPs)
    pub is_service_linked_role: bool,
    /// Whether the principal is from the management account (bypasses SCPs)
    pub is_management_account: bool,
}

impl PrincipalContext {
    /// Create a new empty principal context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a condition key value.
    pub fn set(&mut self, key: &str, value: ConditionValue) {
        self.bag.set(key, value);
    }

    /// Get a condition value by key.
    pub fn get(&self, key: &str) -> Option<&ConditionValue> {
        self.bag.get(key)
    }

    /// Get string representation for condition evaluation.
    pub fn get_strings(&self, key: &str) -> Option<Vec<String>> {
        self.bag.get_strings(key)
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.bag.contains(key)
    }
}

/// Resource context - what is being accessed.
///
/// Contains condition keys related to the resource being accessed:
/// - aws:ResourceAccount, aws:ResourceOrgID, aws:ResourceOrgPaths
/// - aws:ResourceTag/*
#[derive(Debug, Clone, Default)]
pub struct ResourceContext {
    bag: ContextBag,
}

impl ResourceContext {
    /// Create a new empty resource context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a condition key value.
    pub fn set(&mut self, key: &str, value: ConditionValue) {
        self.bag.set(key, value);
    }

    /// Get a condition value by key.
    pub fn get(&self, key: &str) -> Option<&ConditionValue> {
        self.bag.get(key)
    }

    /// Get string representation for condition evaluation.
    pub fn get_strings(&self, key: &str) -> Option<Vec<String>> {
        self.bag.get_strings(key)
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.bag.contains(key)
    }
}

/// Request context - properties of the request itself.
///
/// Contains condition keys related to the request:
/// - aws:CalledVia, aws:CalledViaFirst, aws:CalledViaLast, aws:ViaAWSService
/// - aws:CurrentTime, aws:EpochTime, aws:RequestedRegion
/// - aws:RequestTag/*, aws:TagKeys, aws:SecureTransport
/// - aws:SourceAccount, aws:SourceArn, aws:SourceOrgID, aws:SourceOrgPaths
/// - aws:referer, aws:UserAgent, aws:IsMcpServiceAction
#[derive(Debug, Clone, Default)]
pub struct RequestBag {
    bag: ContextBag,
}

impl RequestBag {
    /// Create a new empty request bag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a condition key value.
    pub fn set(&mut self, key: &str, value: ConditionValue) {
        self.bag.set(key, value);
    }

    /// Get a condition value by key.
    pub fn get(&self, key: &str) -> Option<&ConditionValue> {
        self.bag.get(key)
    }

    /// Get string representation for condition evaluation.
    pub fn get_strings(&self, key: &str) -> Option<Vec<String>> {
        self.bag.get_strings(key)
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.bag.contains(key)
    }

    /// Get all tag keys from aws:RequestTag/* entries.
    ///
    /// This is used to populate aws:TagKeys.
    pub fn get_request_tag_keys(&self) -> Vec<String> {
        self.bag
            .keys()
            .filter_map(|k| k.strip_prefix("aws:requesttag/").map(|s| s.to_string()))
            .collect()
    }
}

/// Network context - network properties of the request.
///
/// Contains condition keys related to network properties:
/// - aws:SourceIp, aws:SourceVpc, aws:SourceVpcArn, aws:SourceVpce
/// - aws:VpceAccount, aws:VpceOrgID, aws:VpceOrgPaths, aws:VpcSourceIp
#[derive(Debug, Clone, Default)]
pub struct NetworkContext {
    bag: ContextBag,
}

impl NetworkContext {
    /// Create a new empty network context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a condition key value.
    pub fn set(&mut self, key: &str, value: ConditionValue) {
        self.bag.set(key, value);
    }

    /// Get a condition value by key.
    pub fn get(&self, key: &str) -> Option<&ConditionValue> {
        self.bag.get(key)
    }

    /// Get string representation for condition evaluation.
    pub fn get_strings(&self, key: &str) -> Option<Vec<String>> {
        self.bag.get_strings(key)
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.bag.contains(key)
    }
}

/// Session context - role session properties.
///
/// Contains condition keys related to the session (temporary credentials):
/// - aws:AssumedRoot, aws:FederatedProvider, aws:TokenIssueTime
/// - aws:MultiFactorAuthAge, aws:MultiFactorAuthPresent
/// - aws:ChatbotSourceArn, aws:SourceIdentity
/// - aws:Ec2InstanceSourceVpc, aws:Ec2InstanceSourcePrivateIPv4
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    bag: ContextBag,
}

impl SessionContext {
    /// Create a new empty session context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a condition key value.
    pub fn set(&mut self, key: &str, value: ConditionValue) {
        self.bag.set(key, value);
    }

    /// Get a condition value by key.
    pub fn get(&self, key: &str) -> Option<&ConditionValue> {
        self.bag.get(key)
    }

    /// Get string representation for condition evaluation.
    pub fn get_strings(&self, key: &str) -> Option<Vec<String>> {
        self.bag.get_strings(key)
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &str) -> bool {
        self.bag.contains(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_value_string() {
        let value = ConditionValue::String("test".to_string());
        assert_eq!(value.to_strings(), Some(vec!["test".to_string()]));
        assert_eq!(value.first_string(), Some("test".to_string()));
    }

    #[test]
    fn test_condition_value_string_list() {
        let value = ConditionValue::StringList(vec!["a".to_string(), "b".to_string()]);
        assert_eq!(
            value.to_strings(),
            Some(vec!["a".to_string(), "b".to_string()])
        );
        assert_eq!(value.first_string(), Some("a".to_string()));
    }

    #[test]
    fn test_condition_value_empty_list() {
        let value = ConditionValue::StringList(vec![]);
        assert_eq!(value.to_strings(), None);
        assert_eq!(value.first_string(), None);
    }

    #[test]
    fn test_condition_value_bool() {
        let value = ConditionValue::Bool(true);
        assert_eq!(value.to_strings(), Some(vec!["true".to_string()]));
        assert_eq!(value.as_bool(), Some(true));
    }

    #[test]
    fn test_condition_value_integer() {
        let value = ConditionValue::Integer(300);
        assert_eq!(value.to_strings(), Some(vec!["300".to_string()]));
        assert_eq!(value.as_integer(), Some(300));
    }

    #[test]
    fn test_context_bag_set_get() {
        let mut bag = ContextBag::new();
        // Keys are stored exactly as provided
        bag.set(
            "aws:sourceip",
            ConditionValue::IpAddress("192.168.1.1".to_string()),
        );

        assert!(bag.contains("aws:sourceip"));
        // Case-sensitive lookup - exact match only
        assert!(!bag.contains("AWS:SOURCEIP"));
        assert_eq!(
            bag.get_strings("aws:sourceip"),
            Some(vec!["192.168.1.1".to_string()])
        );
    }

    #[test]
    fn test_context_bag_exact_match() {
        let mut bag = ContextBag::new();
        // Keys are stored exactly as provided - callers should lowercase non-tag keys
        bag.set(
            "aws:principalarn",
            ConditionValue::String("arn:aws:iam::123456789012:user/test".to_string()),
        );

        // Exact match works
        assert_eq!(
            bag.get("aws:principalarn"),
            Some(&ConditionValue::String(
                "arn:aws:iam::123456789012:user/test".to_string()
            ))
        );
        // Different case does NOT match (caller should handle case-insensitivity)
        assert_eq!(bag.get("AWS:PRINCIPALARN"), None);
    }

    #[test]
    fn test_principal_context() {
        let mut ctx = PrincipalContext::new();
        // Keys should be stored lowercase for non-tag keys
        ctx.set(
            "aws:principalarn",
            ConditionValue::String("arn:aws:iam::123456789012:user/alice".to_string()),
        );
        ctx.set(
            "aws:principalaccount",
            ConditionValue::String("123456789012".to_string()),
        );
        ctx.is_service_linked_role = false;
        ctx.is_management_account = false;

        assert_eq!(
            ctx.get_strings("aws:principalarn"),
            Some(vec!["arn:aws:iam::123456789012:user/alice".to_string()])
        );
        assert_eq!(
            ctx.get_strings("aws:principalaccount"),
            Some(vec!["123456789012".to_string()])
        );
    }

    #[test]
    fn test_session_context_mfa() {
        let mut ctx = SessionContext::new();
        // Keys should be stored lowercase
        ctx.set("aws:multifactorauthpresent", ConditionValue::Bool(true));
        ctx.set("aws:multifactorauthage", ConditionValue::Integer(300));

        assert_eq!(
            ctx.get_strings("aws:multifactorauthpresent"),
            Some(vec!["true".to_string()])
        );
        assert_eq!(
            ctx.get_strings("aws:multifactorauthage"),
            Some(vec!["300".to_string()])
        );
        assert_eq!(
            ctx.get("aws:multifactorauthpresent")
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            ctx.get("aws:multifactorauthage")
                .and_then(|v| v.as_integer()),
            Some(300)
        );
    }

    #[test]
    fn test_network_context() {
        let mut ctx = NetworkContext::new();
        // Keys should be stored lowercase for non-tag keys (caller's responsibility)
        ctx.set(
            "aws:sourceip",
            ConditionValue::IpAddress("10.0.0.1".to_string()),
        );
        ctx.set(
            "aws:sourcevpc",
            ConditionValue::String("vpc-12345".to_string()),
        );

        assert_eq!(
            ctx.get_strings("aws:sourceip"),
            Some(vec!["10.0.0.1".to_string()])
        );
        assert_eq!(
            ctx.get_strings("aws:sourcevpc"),
            Some(vec!["vpc-12345".to_string()])
        );
    }

    #[test]
    fn test_request_bag_tag_keys() {
        let mut ctx = RequestBag::new();
        // Tag keys use lowercase prefix but preserve tag key case
        ctx.set(
            "aws:requesttag/Environment",
            ConditionValue::String("Production".to_string()),
        );
        ctx.set(
            "aws:requesttag/CostCenter",
            ConditionValue::String("12345".to_string()),
        );

        let tag_keys = ctx.get_request_tag_keys();
        assert_eq!(tag_keys.len(), 2);
        // Tag keys preserve their original case
        assert!(tag_keys.contains(&"Environment".to_string()));
        assert!(tag_keys.contains(&"CostCenter".to_string()));
    }

    #[test]
    fn test_resource_context() {
        let mut ctx = ResourceContext::new();
        // Non-tag keys stored lowercase, tag keys preserve case
        ctx.set(
            "aws:resourceaccount",
            ConditionValue::String("987654321098".to_string()),
        );
        ctx.set(
            "aws:resourcetag/Team",
            ConditionValue::String("Platform".to_string()),
        );

        assert_eq!(
            ctx.get_strings("aws:resourceaccount"),
            Some(vec!["987654321098".to_string()])
        );
        // Tag key "Team" preserves case in lookup
        assert_eq!(
            ctx.get_strings("aws:resourcetag/Team"),
            Some(vec!["Platform".to_string()])
        );
    }
}
