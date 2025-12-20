//! Policy validation.
//!
//! Validates IAM policy documents for common issues and provides helpful error messages.
//! Includes service-aware validation using AWS Service Authorization Reference data.

use super::ast::{Policy, Statement};
use crate::error::{Error, Result};
use crate::service::{ServiceLoader, extract_action_name, extract_service_name, has_wildcard};

/// A validation warning or error.
#[derive(Debug, Clone)]
pub struct ValidationIssue {
    /// The severity of the issue.
    pub severity: Severity,
    /// The statement ID or index where the issue was found.
    pub location: String,
    /// Description of the issue.
    pub message: String,
}

/// Severity levels for validation issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// An error that will prevent the policy from working correctly.
    Error,
    /// A warning about potential issues or deprecated features.
    Warning,
}

impl std::fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix = match self.severity {
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
        };
        write!(f, "[{}] {}: {}", prefix, self.location, self.message)
    }
}

/// Validate a policy document and return any issues found.
pub fn validate_policy(policy: &Policy) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();

    // Check policy version
    if let Some(version) = &policy.version {
        if version != "2012-10-17" && version != "2008-10-17" {
            issues.push(ValidationIssue {
                severity: Severity::Warning,
                location: "Policy.Version".to_string(),
                message: format!(
                    "Unrecognized policy version '{}'. Expected '2012-10-17' or '2008-10-17'.",
                    version
                ),
            });
        }
        if version == "2008-10-17" {
            issues.push(ValidationIssue {
                severity: Severity::Warning,
                location: "Policy.Version".to_string(),
                message:
                    "Policy version '2008-10-17' is deprecated. Consider upgrading to '2012-10-17'."
                        .to_string(),
            });
        }
    }

    // Validate each statement
    for (i, statement) in policy.statement.iter().enumerate() {
        let location = statement
            .sid
            .clone()
            .unwrap_or_else(|| format!("Statement[{}]", i));

        validate_statement(statement, &location, &mut issues);
    }

    issues
}

/// Validate a single statement.
fn validate_statement(statement: &Statement, location: &str, issues: &mut Vec<ValidationIssue>) {
    // Check for Action or NotAction
    if statement.action.is_none() && statement.not_action.is_none() {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            location: location.to_string(),
            message: "Statement must have either 'Action' or 'NotAction'.".to_string(),
        });
    }

    // Check for Resource or NotResource
    if statement.resource.is_none() && statement.not_resource.is_none() {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            location: location.to_string(),
            message: "Statement must have either 'Resource' or 'NotResource'.".to_string(),
        });
    }

    // Check for both Action and NotAction (not allowed)
    if statement.action.is_some() && statement.not_action.is_some() {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            location: location.to_string(),
            message: "Statement cannot have both 'Action' and 'NotAction'.".to_string(),
        });
    }

    // Check for both Resource and NotResource (not allowed)
    if statement.resource.is_some() && statement.not_resource.is_some() {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            location: location.to_string(),
            message: "Statement cannot have both 'Resource' and 'NotResource'.".to_string(),
        });
    }

    // Check for both Principal and NotPrincipal (not allowed)
    if statement.principal.is_some() && statement.not_principal.is_some() {
        issues.push(ValidationIssue {
            severity: Severity::Error,
            location: location.to_string(),
            message: "Statement cannot have both 'Principal' and 'NotPrincipal'.".to_string(),
        });
    }

    // Warn about NotAction usage (often misunderstood)
    if statement.not_action.is_some() {
        issues.push(ValidationIssue {
            severity: Severity::Warning,
            location: location.to_string(),
            message: "NotAction is used. Ensure this is intentional - it matches ALL actions EXCEPT those listed.".to_string(),
        });
    }

    // Warn about NotResource usage
    if statement.not_resource.is_some() {
        issues.push(ValidationIssue {
            severity: Severity::Warning,
            location: location.to_string(),
            message: "NotResource is used. Ensure this is intentional - it matches ALL resources EXCEPT those listed.".to_string(),
        });
    }

    // Warn about NotPrincipal usage
    if statement.not_principal.is_some() {
        issues.push(ValidationIssue {
            severity: Severity::Warning,
            location: location.to_string(),
            message: "NotPrincipal is used. This is rarely needed and can be confusing. Consider using Principal with Conditions instead.".to_string(),
        });
    }
}

/// Check if all validation issues are warnings (no errors).
pub fn has_errors(issues: &[ValidationIssue]) -> bool {
    issues.iter().any(|i| i.severity == Severity::Error)
}

// =============================================================================
// Service-aware validation
// =============================================================================

/// Global condition keys that are valid for all actions.
const GLOBAL_CONDITION_KEYS: &[&str] = &[
    // Principal keys
    "aws:PrincipalArn",
    "aws:PrincipalAccount",
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:PrincipalTag/",
    "aws:PrincipalType",
    "aws:PrincipalIsAWSService",
    "aws:PrincipalServiceName",
    "aws:PrincipalServiceNamesList",
    "aws:userid",
    "aws:username",
    // Resource keys
    "aws:ResourceAccount",
    "aws:ResourceOrgID",
    "aws:ResourceOrgPaths",
    "aws:ResourceTag/",
    // Network keys
    "aws:SourceIp",
    "aws:SourceVpc",
    "aws:SourceVpcArn",
    "aws:SourceVpce",
    "aws:VpcSourceIp",
    "aws:VpceAccount",
    "aws:VpceOrgID",
    "aws:VpceOrgPaths",
    // Session keys
    "aws:MultiFactorAuthPresent",
    "aws:MultiFactorAuthAge",
    "aws:TokenIssueTime",
    "aws:SourceIdentity",
    "aws:FederatedProvider",
    "aws:AssumedRoot",
    "aws:ChatbotSourceArn",
    "aws:Ec2InstanceSourceVpc",
    "aws:Ec2InstanceSourcePrivateIPv4",
    // Request keys
    "aws:RequestTag/",
    "aws:TagKeys",
    "aws:CalledVia",
    "aws:CalledViaFirst",
    "aws:CalledViaLast",
    "aws:ViaAWSService",
    "aws:SourceArn",
    "aws:SourceAccount",
    "aws:SourceOrgID",
    "aws:SourceOrgPaths",
    "aws:RequestedRegion",
    "aws:SecureTransport",
    "aws:CurrentTime",
    "aws:EpochTime",
    "aws:referer",
    "aws:UserAgent",
    "aws:IsMcpServiceAction",
];

/// Check if a condition key is a global AWS condition key.
fn is_global_condition_key(key: &str) -> bool {
    let key_lower = key.to_lowercase();
    for global_key in GLOBAL_CONDITION_KEYS {
        let global_lower = global_key.to_lowercase();
        if global_lower.ends_with('/') {
            // Prefix match for tag keys like aws:PrincipalTag/
            if key_lower.starts_with(&global_lower) {
                return true;
            }
        } else if key_lower == global_lower {
            return true;
        }
    }
    false
}

/// Result of validating an action against service definitions.
#[derive(Debug)]
pub struct ActionValidationResult {
    /// Whether the action is valid.
    pub valid: bool,
    /// Error message if invalid.
    pub error: Option<String>,
    /// Suggestion for similar action name.
    pub suggestion: Option<String>,
}

/// Result of validating a condition key against service definitions.
#[derive(Debug)]
pub struct ConditionKeyValidationResult {
    /// Whether the condition key is valid.
    pub valid: bool,
    /// Error message if invalid.
    pub error: Option<String>,
}

/// Validate an action against service definitions.
///
/// # Arguments
/// * `action` - The action string (e.g., "s3:GetObject")
/// * `loader` - The service loader to use
///
/// # Returns
/// * `Ok(ActionValidationResult)` - Validation result
/// * `Err` - If the service cannot be loaded (network error, etc.)
pub fn validate_action(action: &str, loader: &ServiceLoader) -> Result<ActionValidationResult> {
    // Skip wildcard actions - can't validate patterns like "s3:*"
    if has_wildcard(action) {
        return Ok(ActionValidationResult {
            valid: true,
            error: None,
            suggestion: None,
        });
    }

    let service_name = match extract_service_name(action) {
        Some(s) => s,
        None => {
            return Ok(ActionValidationResult {
                valid: false,
                error: Some(format!("Invalid action format: '{}'", action)),
                suggestion: None,
            });
        }
    };

    let action_name = match extract_action_name(action) {
        Some(a) => a,
        None => {
            return Ok(ActionValidationResult {
                valid: false,
                error: Some(format!("Invalid action format: '{}'", action)),
                suggestion: None,
            });
        }
    };

    // Try to load service definition
    let service = match loader.load(service_name)? {
        Some(s) => s,
        None => {
            // Service not available - skip validation
            return Ok(ActionValidationResult {
                valid: true,
                error: None,
                suggestion: None,
            });
        }
    };

    // Check if action exists
    if service.has_action(action_name) {
        return Ok(ActionValidationResult {
            valid: true,
            error: None,
            suggestion: None,
        });
    }

    // Action not found - try to find a similar one
    let suggestion = find_similar_action(&service.action_names(), action_name);

    Ok(ActionValidationResult {
        valid: false,
        error: Some(format!("Unknown action '{}'", action)),
        suggestion,
    })
}

/// Validate a condition key against service definitions for a specific action.
///
/// # Arguments
/// * `key` - The condition key (e.g., "s3:x-amz-acl")
/// * `action` - The action string (e.g., "s3:GetObject")
/// * `loader` - The service loader to use
///
/// # Returns
/// * `Ok(ConditionKeyValidationResult)` - Validation result
pub fn validate_condition_key(
    key: &str,
    action: &str,
    loader: &ServiceLoader,
) -> Result<ConditionKeyValidationResult> {
    // Global condition keys are always valid
    if is_global_condition_key(key) {
        return Ok(ConditionKeyValidationResult {
            valid: true,
            error: None,
        });
    }

    // Skip if action has wildcards
    if has_wildcard(action) {
        return Ok(ConditionKeyValidationResult {
            valid: true,
            error: None,
        });
    }

    let service_name = match extract_service_name(action) {
        Some(s) => s,
        None => {
            return Ok(ConditionKeyValidationResult {
                valid: true,
                error: None,
            });
        }
    };

    let action_name = match extract_action_name(action) {
        Some(a) => a,
        None => {
            return Ok(ConditionKeyValidationResult {
                valid: true,
                error: None,
            });
        }
    };

    // Try to load service definition
    let service = match loader.load(service_name)? {
        Some(s) => s,
        None => {
            // Service not available - skip validation
            return Ok(ConditionKeyValidationResult {
                valid: true,
                error: None,
            });
        }
    };

    // Get the action definition
    let action_def = match service.get_action(action_name) {
        Some(a) => a,
        None => {
            // Action not found - skip condition key validation
            return Ok(ConditionKeyValidationResult {
                valid: true,
                error: None,
            });
        }
    };

    // Check if condition key is valid for this action
    if action_def.has_condition_key(key) {
        return Ok(ConditionKeyValidationResult {
            valid: true,
            error: None,
        });
    }

    // Also check service-level condition keys
    let service_keys: Vec<&str> = service.all_condition_keys();
    if service_keys.iter().any(|k| k.eq_ignore_ascii_case(key)) {
        return Ok(ConditionKeyValidationResult {
            valid: true,
            error: None,
        });
    }

    Ok(ConditionKeyValidationResult {
        valid: false,
        error: Some(format!(
            "Condition key '{}' is not valid for action '{}'",
            key, action
        )),
    })
}

/// Validate all policies against service definitions.
///
/// # Arguments
/// * `policies` - List of policies to validate
/// * `request_action` - The action being requested (for condition key validation)
/// * `loader` - The service loader to use
///
/// # Returns
/// * `Ok(())` - If all validations pass
/// * `Err(ValidationFailed)` - If any validations fail
pub fn validate_against_service_definitions(
    policies: &[&Policy],
    request_action: &str,
    loader: &ServiceLoader,
) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();

    // Validate the request action
    let action_result = validate_action(request_action, loader)?;
    if !action_result.valid {
        let mut msg = action_result.error.unwrap_or_default();
        if let Some(suggestion) = action_result.suggestion {
            msg.push_str(&format!(" - did you mean '{}'?", suggestion));
        }
        errors.push(msg);
    }

    // Validate actions in policies
    for policy in policies {
        for statement in &policy.statement {
            // Validate actions
            if let Some(actions) = &statement.action {
                for action in actions.to_vec() {
                    let result = validate_action(action, loader)?;
                    if !result.valid {
                        let mut msg = result.error.unwrap_or_default();
                        if let Some(suggestion) = result.suggestion {
                            msg.push_str(&format!(" - did you mean '{}'?", suggestion));
                        }
                        errors.push(msg);
                    }
                }
            }

            // Validate condition keys
            if let Some(conditions) = &statement.condition {
                for (_operator, key_values) in conditions {
                    for key in key_values.keys() {
                        let result = validate_condition_key(key, request_action, loader)?;
                        if !result.valid {
                            if let Some(error) = result.error {
                                errors.push(error);
                            }
                        }
                    }
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(Error::ValidationFailed(errors))
    }
}

/// Find a similar action name using simple string distance.
fn find_similar_action(candidates: &[&str], target: &str) -> Option<String> {
    let target_lower = target.to_lowercase();

    // First, try prefix match
    for candidate in candidates {
        if candidate.to_lowercase().starts_with(&target_lower) {
            return Some(candidate.to_string());
        }
    }

    // Then try substring match
    for candidate in candidates {
        if candidate.to_lowercase().contains(&target_lower) {
            return Some(candidate.to_string());
        }
    }

    // Finally, try finding one with lowest edit distance
    let mut best_match: Option<&str> = None;
    let mut best_distance = usize::MAX;

    for candidate in candidates {
        let distance = levenshtein_distance(&target_lower, &candidate.to_lowercase());
        if distance < best_distance && distance <= 3 {
            best_distance = distance;
            best_match = Some(candidate);
        }
    }

    best_match.map(|s| s.to_string())
}

/// Simple Levenshtein distance implementation.
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut matrix = vec![vec![0; b_len + 1]; a_len + 1];

    for i in 0..=a_len {
        matrix[i][0] = i;
    }
    for j in 0..=b_len {
        matrix[0][j] = j;
    }

    for i in 1..=a_len {
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[a_len][b_len]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_policy(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn test_valid_policy() {
        let policy = parse_policy(
            r#"{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }]
            }"#,
        );

        let issues = validate_policy(&policy);
        assert!(issues.is_empty());
    }

    #[test]
    fn test_deprecated_version() {
        let policy = parse_policy(
            r#"{
                "Version": "2008-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }]
            }"#,
        );

        let issues = validate_policy(&policy);
        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].severity, Severity::Warning);
        assert!(issues[0].message.contains("deprecated"));
    }

    #[test]
    fn test_missing_action() {
        let policy = parse_policy(
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Resource": "arn:aws:s3:::bucket/*"
                }]
            }"#,
        );

        let issues = validate_policy(&policy);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("Action")));
    }

    #[test]
    fn test_missing_resource() {
        let policy = parse_policy(
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject"
                }]
            }"#,
        );

        let issues = validate_policy(&policy);
        assert!(has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("Resource")));
    }

    #[test]
    fn test_both_action_and_notaction() {
        let policy = parse_policy(
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "NotAction": "s3:DeleteObject",
                    "Resource": "*"
                }]
            }"#,
        );

        let issues = validate_policy(&policy);
        assert!(has_errors(&issues));
        assert!(
            issues
                .iter()
                .any(|i| i.message.contains("both 'Action' and 'NotAction'"))
        );
    }

    #[test]
    fn test_notaction_warning() {
        let policy = parse_policy(
            r#"{
                "Statement": [{
                    "Effect": "Deny",
                    "NotAction": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let issues = validate_policy(&policy);
        assert!(!has_errors(&issues));
        assert!(issues.iter().any(|i| i.message.contains("NotAction")));
    }

    #[test]
    fn test_statement_with_sid() {
        let policy = parse_policy(
            r#"{
                "Statement": [{
                    "Sid": "MyStatement",
                    "Effect": "Allow",
                    "Resource": "*"
                }]
            }"#,
        );

        let issues = validate_policy(&policy);
        assert!(has_errors(&issues));
        assert!(issues[0].location.contains("MyStatement"));
    }
}
