//! Statement matching logic.
//!
//! Determines if a request matches a policy statement based on:
//! - Action matching (with wildcards)
//! - Resource matching (ARN patterns)
//! - Principal matching
//! - Condition evaluation

use super::condition_eval::ConditionEvaluator;
use super::context::RequestContext;
use super::variables::resolve_variables;
use crate::arn::ArnPattern;
use crate::arn::pattern::glob_match;
use crate::error::Result;
use crate::policy::action::ActionPattern;
use crate::policy::{
    ActionBlock, ConditionBlock, Principal, PrincipalBlock, ResourceBlock, Statement,
};

use serde::Serialize;

/// Detail about a single condition evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct ConditionMatchDetail {
    /// The condition operator (e.g., "StringEquals", "IpAddress").
    pub operator: String,
    /// The condition key being evaluated (e.g., "aws:SourceIp").
    pub key: String,
    /// The values expected by the policy.
    pub expected_values: Vec<String>,
    /// The actual values from the request context (None if key was missing).
    pub actual_values: Option<Vec<String>>,
    /// Whether this condition matched.
    pub matched: bool,
    /// Whether the condition key was missing from the request context.
    pub key_missing: bool,
}

impl ConditionMatchDetail {
    /// Create a new condition match detail.
    pub fn new(
        operator: impl Into<String>,
        key: impl Into<String>,
        expected_values: Vec<String>,
        actual_values: Option<Vec<String>>,
        matched: bool,
    ) -> Self {
        let key_missing = actual_values.is_none();
        Self {
            operator: operator.into(),
            key: key.into(),
            expected_values,
            actual_values,
            matched,
            key_missing,
        }
    }
}

impl std::fmt::Display for ConditionMatchDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({}", self.operator, self.key)?;
        if self.key_missing {
            write!(f, " [KEY MISSING]")?;
        } else if let Some(actual) = &self.actual_values {
            write!(f, " actual={:?}", actual)?;
        }
        write!(f, " expected={:?})", self.expected_values)?;
        write!(f, " -> {}", if self.matched { "MATCH" } else { "NO MATCH" })
    }
}

/// Detailed breakdown of what matched or didn't match in a statement.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MatchBreakdown {
    /// Whether the action element matched (None if not evaluated).
    pub action_matched: Option<bool>,
    /// Details about action matching.
    pub action_details: Option<String>,
    /// Whether the resource element matched (None if not evaluated).
    pub resource_matched: Option<bool>,
    /// Details about resource matching.
    pub resource_details: Option<String>,
    /// Whether the principal element matched (None if not present/evaluated).
    pub principal_matched: Option<bool>,
    /// Details about principal matching.
    pub principal_details: Option<String>,
    /// Details about each condition evaluation.
    pub conditions: Vec<ConditionMatchDetail>,
    /// Whether all conditions matched (None if no conditions present).
    pub conditions_matched: Option<bool>,
}

impl MatchBreakdown {
    /// Create a new empty breakdown.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set action match result.
    pub fn with_action(mut self, matched: bool, details: impl Into<String>) -> Self {
        self.action_matched = Some(matched);
        self.action_details = Some(details.into());
        self
    }

    /// Set resource match result.
    pub fn with_resource(mut self, matched: bool, details: impl Into<String>) -> Self {
        self.resource_matched = Some(matched);
        self.resource_details = Some(details.into());
        self
    }

    /// Set principal match result.
    pub fn with_principal(mut self, matched: bool, details: impl Into<String>) -> Self {
        self.principal_matched = Some(matched);
        self.principal_details = Some(details.into());
        self
    }

    /// Add a condition evaluation result.
    pub fn add_condition(&mut self, detail: ConditionMatchDetail) {
        self.conditions.push(detail);
    }

    /// Set the overall conditions match result.
    pub fn with_conditions_result(mut self, matched: bool) -> Self {
        self.conditions_matched = Some(matched);
        self
    }

    /// Check if any condition key was missing.
    pub fn has_missing_keys(&self) -> bool {
        self.conditions.iter().any(|c| c.key_missing)
    }

    /// Get the list of missing condition keys.
    pub fn missing_keys(&self) -> Vec<&str> {
        self.conditions
            .iter()
            .filter(|c| c.key_missing)
            .map(|c| c.key.as_str())
            .collect()
    }
}

impl std::fmt::Display for MatchBreakdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(matched) = self.action_matched {
            write!(f, "Action: {} ", if matched { "✓" } else { "✗" })?;
            if let Some(details) = &self.action_details {
                write!(f, "({})", details)?;
            }
            writeln!(f)?;
        }
        if let Some(matched) = self.resource_matched {
            write!(f, "Resource: {} ", if matched { "✓" } else { "✗" })?;
            if let Some(details) = &self.resource_details {
                write!(f, "({})", details)?;
            }
            writeln!(f)?;
        }
        if let Some(matched) = self.principal_matched {
            write!(f, "Principal: {} ", if matched { "✓" } else { "✗" })?;
            if let Some(details) = &self.principal_details {
                write!(f, "({})", details)?;
            }
            writeln!(f)?;
        }
        if !self.conditions.is_empty() {
            writeln!(f, "Conditions:")?;
            for cond in &self.conditions {
                writeln!(f, "  {}", cond)?;
            }
        }
        Ok(())
    }
}

/// Result of matching a statement against a request.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Whether the statement matches the request.
    pub matches: bool,
    /// Details about why it matched or didn't match.
    pub details: String,
    /// Detailed breakdown of what matched or didn't.
    pub breakdown: MatchBreakdown,
}

impl MatchResult {
    fn matched(details: impl Into<String>, breakdown: MatchBreakdown) -> Self {
        Self {
            matches: true,
            details: details.into(),
            breakdown,
        }
    }

    fn not_matched(details: impl Into<String>, breakdown: MatchBreakdown) -> Self {
        Self {
            matches: false,
            details: details.into(),
            breakdown,
        }
    }
}

/// Check if a statement matches the request.
pub fn statement_matches(statement: &Statement, context: &RequestContext) -> Result<MatchResult> {
    let mut breakdown = MatchBreakdown::new();

    // 1. Check action match
    let (action_match, action_detail) = match (&statement.action, &statement.not_action) {
        (Some(action), None) => {
            let patterns = action.to_vec().join(", ");
            let matched = action_matches(action, &context.action)?;
            (
                matched,
                format!("Action '{}' vs pattern [{}]", context.action, patterns),
            )
        }
        (None, Some(not_action)) => {
            let patterns = not_action.to_vec().join(", ");
            let matched = !action_matches(not_action, &context.action)?;
            (
                matched,
                format!("Action '{}' vs NotAction [{}]", context.action, patterns),
            )
        }
        _ => {
            let bd = breakdown.with_action(false, "No Action or NotAction in statement");
            return Ok(MatchResult::not_matched(
                "Statement has no Action or NotAction",
                bd,
            ));
        }
    };
    breakdown = breakdown.with_action(action_match, &action_detail);

    if !action_match {
        return Ok(MatchResult::not_matched(
            format!("Action '{}' does not match", context.action),
            breakdown,
        ));
    }

    // 2. Check resource match
    let (resource_match, resource_detail) = match (&statement.resource, &statement.not_resource) {
        (Some(resource), None) => {
            let patterns = resource.to_vec().join(", ");
            let matched = resource_matches(resource, &context.resource, context)?;
            (
                matched,
                format!("Resource '{}' vs pattern [{}]", context.resource, patterns),
            )
        }
        (None, Some(not_resource)) => {
            let patterns = not_resource.to_vec().join(", ");
            let matched = !resource_matches(not_resource, &context.resource, context)?;
            (
                matched,
                format!(
                    "Resource '{}' vs NotResource [{}]",
                    context.resource, patterns
                ),
            )
        }
        _ => {
            let bd = breakdown.with_resource(false, "No Resource or NotResource in statement");
            return Ok(MatchResult::not_matched(
                "Statement has no Resource or NotResource",
                bd,
            ));
        }
    };
    breakdown = breakdown.with_resource(resource_match, &resource_detail);

    if !resource_match {
        return Ok(MatchResult::not_matched(
            format!("Resource '{}' does not match", context.resource),
            breakdown,
        ));
    }

    // 3. Check principal match (if present - only for resource-based policies)
    if let Some(principal) = &statement.principal {
        let principal_match = principal_matches(principal, context)?;
        let principal_detail = format!(
            "Principal {:?} vs {:?}",
            context.principal_arn.as_deref().unwrap_or("(none)"),
            principal
        );
        breakdown = breakdown.with_principal(principal_match, principal_detail);
        if !principal_match {
            return Ok(MatchResult::not_matched(
                "Principal does not match",
                breakdown,
            ));
        }
    }
    if let Some(not_principal) = &statement.not_principal {
        let principal_match = principal_matches(not_principal, context)?;
        let principal_detail = format!(
            "Principal {:?} vs NotPrincipal {:?}",
            context.principal_arn.as_deref().unwrap_or("(none)"),
            not_principal
        );
        // For NotPrincipal, if it matches, we should NOT match the statement
        breakdown = breakdown.with_principal(!principal_match, principal_detail);
        if principal_match {
            return Ok(MatchResult::not_matched(
                "NotPrincipal excludes this principal",
                breakdown,
            ));
        }
    }

    // 4. Check condition match (if present)
    if let Some(conditions) = &statement.condition {
        let (condition_match, condition_details) =
            conditions_match_with_details(conditions, context)?;
        for detail in condition_details {
            breakdown.add_condition(detail);
        }
        breakdown = breakdown.with_conditions_result(condition_match);

        if !condition_match {
            let missing_keys = breakdown.missing_keys();
            let detail_msg = if !missing_keys.is_empty() {
                format!(
                    "Condition not satisfied (missing keys: {})",
                    missing_keys.join(", ")
                )
            } else {
                "Condition not satisfied".to_string()
            };
            return Ok(MatchResult::not_matched(detail_msg, breakdown));
        }
    }

    Ok(MatchResult::matched(
        "All statement elements match",
        breakdown,
    ))
}

/// Check if the action block matches the request action.
fn action_matches(action_block: &ActionBlock, request_action: &str) -> Result<bool> {
    let patterns = action_block.to_vec();

    for pattern_str in patterns {
        // Handle "*" wildcard
        if pattern_str == "*" {
            return Ok(true);
        }

        // Parse and match
        if let Ok(pattern) = ActionPattern::parse(pattern_str) {
            if pattern.matches(request_action) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Check if the resource block matches the request resource.
fn resource_matches(
    resource_block: &ResourceBlock,
    request_resource: &str,
    context: &RequestContext,
) -> Result<bool> {
    let patterns = resource_block.to_vec();

    for pattern_str in patterns {
        // Resolve any policy variables in the pattern
        let resolved = resolve_variables(pattern_str, context);

        // Handle "*" wildcard
        if resolved == "*" {
            return Ok(true);
        }

        // Parse and match as ARN pattern
        if let Ok(pattern) = ArnPattern::parse(&resolved) {
            if pattern.matches_str(request_resource) {
                return Ok(true);
            }
        } else {
            // If not a valid ARN pattern, try simple glob match
            if glob_match(&resolved, request_resource) {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Check if the principal block matches the request principal.
fn principal_matches(principal_block: &PrincipalBlock, context: &RequestContext) -> Result<bool> {
    match principal_block {
        PrincipalBlock::Wildcard(s) if s == "*" => Ok(true),
        PrincipalBlock::Wildcard(_) => Ok(false),
        PrincipalBlock::Map(map) => {
            // Check each principal type
            for (principal_type, principals) in map {
                if principal_type_matches(principal_type, principals, context)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Extract the account ID from a root ARN like "arn:aws:iam::123456789012:root".
/// Returns None if the ARN is not a root ARN.
fn extract_root_account_from_arn(arn: &str) -> Option<&str> {
    // Root ARN format: arn:aws:iam::ACCOUNT:root
    // or: arn:aws-cn:iam::ACCOUNT:root, arn:aws-us-gov:iam::ACCOUNT:root
    if !arn.ends_with(":root") {
        return None;
    }

    let parts: Vec<&str> = arn.split(':').collect();
    // ARN parts: arn:partition:service:region:account:resource
    // For IAM root: arn:aws:iam::ACCOUNT:root (6 parts, region is empty)
    if parts.len() == 6 && parts[0] == "arn" && parts[2] == "iam" && parts[5] == "root" {
        let account = parts[4];
        if !account.is_empty() {
            return Some(account);
        }
    }
    None
}

/// Check if a specific principal type matches.
fn principal_type_matches(
    principal_type: &str,
    principals: &Principal,
    context: &RequestContext,
) -> Result<bool> {
    let principal_values = principals.to_vec();

    for value in principal_values {
        if value == "*" {
            return Ok(true);
        }

        match principal_type.to_uppercase().as_str() {
            "AWS" => {
                // Can be account ID, ARN, or "*"
                if let Some(principal_arn) = &context.principal_arn {
                    // Check if it matches the full ARN
                    if glob_match(value, principal_arn) {
                        return Ok(true);
                    }
                }

                // Check if principal account matches
                if let Some(account) = &context.principal_account {
                    // Direct account ID match
                    if value == *account {
                        return Ok(true);
                    }

                    // If policy specifies arn:aws:iam::ACCOUNT:root, it matches ANY principal from that account
                    // Parse the root ARN pattern: arn:aws:iam::ACCOUNT:root or arn:aws-*:iam::ACCOUNT:root
                    if let Some(root_account) = extract_root_account_from_arn(value) {
                        if root_account == *account {
                            return Ok(true);
                        }
                    }
                }
            }
            "SERVICE" => {
                // Service principals like "s3.amazonaws.com"
                if let Some(ctx_service) = context.get_context_key("aws:principalservicename") {
                    for svc in ctx_service {
                        if glob_match(value, svc) {
                            return Ok(true);
                        }
                    }
                }
            }
            "FEDERATED" => {
                // Federated identity providers
                if let Some(ctx_fed) = context.get_context_key("aws:federatedprovider") {
                    for fed in ctx_fed {
                        if glob_match(value, fed) {
                            return Ok(true);
                        }
                    }
                }
            }
            "CANONICALUSER" => {
                // S3 canonical user ID
                if let Some(ctx_canonical) = context.get_context_key("aws:canonicaluser") {
                    for canonical in ctx_canonical {
                        if value == canonical {
                            return Ok(true);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    Ok(false)
}

/// Check if all conditions in the condition block are satisfied.
#[allow(dead_code)]
fn conditions_match(conditions: &ConditionBlock, context: &RequestContext) -> Result<bool> {
    let (matched, _) = conditions_match_with_details(conditions, context)?;
    Ok(matched)
}

/// Check if all conditions in the condition block are satisfied, returning detailed results.
fn conditions_match_with_details(
    conditions: &ConditionBlock,
    context: &RequestContext,
) -> Result<(bool, Vec<ConditionMatchDetail>)> {
    let mut details = Vec::new();
    let mut all_matched = true;

    // All condition operators must match (AND logic)
    for (operator, condition_map) in conditions {
        for (key, values) in condition_map {
            // Get context values for this key
            let context_values = get_condition_context_values(key, context);

            // Convert condition values to strings
            // Note: With #[serde(untagged)], arrays may be parsed as Single(Array(...))
            // so we need to handle that case specially
            let policy_values: Vec<String> = match values {
                crate::policy::Condition::Single(v) => {
                    // If the single value is actually an array, expand it
                    if let serde_json::Value::Array(arr) = v {
                        arr.iter().map(value_to_string).collect()
                    } else {
                        vec![value_to_string(v)]
                    }
                }
                crate::policy::Condition::Multiple(vs) => vs.iter().map(value_to_string).collect(),
            };

            // Resolve variables in policy values
            let resolved_values: Vec<String> = policy_values
                .iter()
                .map(|v| resolve_variables(v, context))
                .collect();

            // Evaluate the condition
            let matched =
                ConditionEvaluator::evaluate(operator, context_values.as_ref(), &resolved_values)?;

            // Record the detail
            details.push(ConditionMatchDetail::new(
                operator.to_string(),
                key.clone(),
                resolved_values,
                context_values.clone(),
                matched,
            ));

            if !matched {
                all_matched = false;
            }
        }
    }

    Ok((all_matched, details))
}

/// Get context values for a condition key.
///
/// Delegates to the unified context bags lookup via `RequestContext::get_condition_value()`.
fn get_condition_context_values(key: &str, context: &RequestContext) -> Option<Vec<String>> {
    context.get_condition_value(key)
}

/// Convert a JSON value to a string for comparison.
fn value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn parse_policy(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    fn make_context(action: &str, resource: &str) -> RequestContext {
        RequestContext::builder()
            .action(action)
            .resource(resource)
            .build()
            .unwrap()
    }

    // ===================
    // Action matching tests
    // ===================

    #[test]
    fn test_action_exact_match() {
        let action_block = ActionBlock::Single("s3:GetObject".to_string());
        assert!(action_matches(&action_block, "s3:GetObject").unwrap());
        assert!(!action_matches(&action_block, "s3:PutObject").unwrap());
    }

    #[test]
    fn test_action_wildcard_all() {
        let action_block = ActionBlock::Single("*".to_string());
        assert!(action_matches(&action_block, "s3:GetObject").unwrap());
        assert!(action_matches(&action_block, "ec2:RunInstances").unwrap());
    }

    #[test]
    fn test_action_wildcard_service() {
        let action_block = ActionBlock::Single("s3:*".to_string());
        assert!(action_matches(&action_block, "s3:GetObject").unwrap());
        assert!(action_matches(&action_block, "s3:PutObject").unwrap());
        assert!(!action_matches(&action_block, "ec2:RunInstances").unwrap());
    }

    #[test]
    fn test_action_wildcard_prefix() {
        let action_block = ActionBlock::Single("s3:Get*".to_string());
        assert!(action_matches(&action_block, "s3:GetObject").unwrap());
        assert!(action_matches(&action_block, "s3:GetBucketLocation").unwrap());
        assert!(!action_matches(&action_block, "s3:PutObject").unwrap());
    }

    #[test]
    fn test_action_multiple() {
        let action_block =
            ActionBlock::Multiple(vec!["s3:GetObject".to_string(), "s3:PutObject".to_string()]);
        assert!(action_matches(&action_block, "s3:GetObject").unwrap());
        assert!(action_matches(&action_block, "s3:PutObject").unwrap());
        assert!(!action_matches(&action_block, "s3:DeleteObject").unwrap());
    }

    // ===================
    // Resource matching tests
    // ===================

    #[test]
    fn test_resource_exact_match() {
        let resource_block = ResourceBlock::Single("arn:aws:s3:::my-bucket".to_string());
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::my-bucket");
        assert!(resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::other-bucket");
        assert!(!resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());
    }

    #[test]
    fn test_resource_wildcard_all() {
        let resource_block = ResourceBlock::Single("*".to_string());
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt");
        assert!(resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());
    }

    #[test]
    fn test_resource_wildcard_suffix() {
        let resource_block = ResourceBlock::Single("arn:aws:s3:::my-bucket/*".to_string());
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt");
        assert!(resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::my-bucket/path/to/file.txt");
        assert!(resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::other-bucket/file.txt");
        assert!(!resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());
    }

    #[test]
    fn test_resource_with_variable() {
        let resource_block =
            ResourceBlock::Single("arn:aws:s3:::bucket-${aws:PrincipalAccount}/*".to_string());
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket-123456789012/file.txt")
            .principal_account("123456789012")
            .build()
            .unwrap();
        assert!(resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket-999999999999/file.txt")
            .principal_account("123456789012")
            .build()
            .unwrap();
        assert!(!resource_matches(&resource_block, &ctx.resource, &ctx).unwrap());
    }

    // ===================
    // Statement matching tests
    // ===================

    #[test]
    fn test_statement_matches_simple() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }"#,
        );

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);
    }

    #[test]
    fn test_statement_action_mismatch() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }"#,
        );

        let ctx = make_context("s3:PutObject", "arn:aws:s3:::my-bucket/file.txt");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
        assert!(result.details.contains("Action"));
    }

    #[test]
    fn test_statement_resource_mismatch() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }]
        }"#,
        );

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::other-bucket/file.txt");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
        assert!(result.details.contains("Resource"));
    }

    #[test]
    fn test_statement_not_action() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Deny",
                "NotAction": "s3:GetObject",
                "Resource": "*"
            }]
        }"#,
        );

        // NotAction: anything except s3:GetObject
        let ctx = make_context("s3:PutObject", "arn:aws:s3:::my-bucket/file.txt");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::my-bucket/file.txt");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
    }

    #[test]
    fn test_statement_not_resource() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "NotResource": "arn:aws:s3:::protected-bucket/*"
            }]
        }"#,
        );

        // NotResource: anything except protected-bucket
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::other-bucket/file.txt");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::protected-bucket/file.txt");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
    }

    #[test]
    fn test_statement_with_condition() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalAccount": "123456789012"
                    }
                }
            }]
        }"#,
        );

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_account("123456789012")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_account("999999999999")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
    }

    #[test]
    fn test_statement_with_ip_condition() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {
                        "aws:SourceIp": "192.168.1.0/24"
                    }
                }
            }]
        }"#,
        );

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .context_key("aws:SourceIp", "192.168.1.100")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .context_key("aws:SourceIp", "10.0.0.1")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
    }

    #[test]
    fn test_statement_with_principal_wildcard() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }"#,
        );

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);
    }

    #[test]
    fn test_statement_with_principal_account() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "AWS": "123456789012"
                },
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }"#,
        );

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_account("123456789012")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_account("999999999999")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
    }

    #[test]
    fn test_statement_with_principal_arn() {
        let policy = parse_policy(
            r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:user/johndoe"
                },
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }"#,
        );

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::123456789012:user/johndoe")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(result.matches);

        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::123456789012:user/alice")
            .build()
            .unwrap();
        let result = statement_matches(&policy.statement[0], &ctx).unwrap();
        assert!(!result.matches);
    }
}
