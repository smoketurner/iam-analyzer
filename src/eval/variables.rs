//! Policy variable resolution.
//!
//! Substitutes policy variables like `${aws:username}` with values from the request context.
//!
//! Supported variables:
//! - `${aws:username}` - Principal's username
//! - `${aws:userid}` - Principal's unique ID
//! - `${aws:PrincipalAccount}` - Principal's AWS account ID
//! - `${aws:PrincipalArn}` - Principal's ARN
//! - `${aws:PrincipalTag/tag-key}` - Tag values from principal
//! - `${aws:RequestTag/tag-key}` - Tags in the request
//! - `${aws:ResourceTag/tag-key}` - Tags on the resource
//! - `${aws:CurrentTime}` - Current date/time (ISO 8601)
//! - `${aws:EpochTime}` - Current time as epoch seconds
//! - `${aws:SourceIp}` - Requester's IP address
//! - `${aws:SecureTransport}` - Whether HTTPS was used
//! - `${s3:prefix}` - S3-specific prefix variable
//! - And other context keys

use super::context::RequestContext;
use chrono::Utc;

/// Resolve policy variables in a string.
///
/// # Examples
///
/// ```
/// use iam_analyzer::eval::variables::resolve_variables;
/// use iam_analyzer::RequestContext;
///
/// let ctx = RequestContext::builder()
///     .action("s3:GetObject")
///     .resource("arn:aws:s3:::bucket/key")
///     .principal_account("123456789012")
///     .build()
///     .unwrap();
///
/// let resolved = resolve_variables("arn:aws:s3:::bucket-${aws:PrincipalAccount}/*", &ctx);
/// assert_eq!(resolved, "arn:aws:s3:::bucket-123456789012/*");
/// ```
pub fn resolve_variables(input: &str, context: &RequestContext) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' && chars.peek() == Some(&'{') {
            chars.next(); // consume '{'

            // Collect variable name until '}'
            let mut var_name = String::new();
            let mut found_close = false;
            while let Some(&c) = chars.peek() {
                if c == '}' {
                    chars.next(); // consume '}'
                    found_close = true;
                    break;
                }
                var_name.push(chars.next().unwrap());
            }

            if !found_close {
                // Unclosed variable - keep as-is
                result.push_str("${");
                result.push_str(&var_name);
            } else if let Some(value) = resolve_variable(&var_name, context) {
                // Resolve the variable
                result.push_str(&value);
            } else {
                // Keep the original variable if not resolved
                result.push_str("${");
                result.push_str(&var_name);
                result.push('}');
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Resolve a single variable name to its value.
///
/// Uses the unified context bags lookup. All condition values are stored in
/// the appropriate context bag and looked up via `get_condition_value()`.
fn resolve_variable(var_name: &str, context: &RequestContext) -> Option<String> {
    // Normalize variable name for comparison (but preserve tag key case)
    let lower_name = var_name.to_lowercase();

    // Special handling for dynamic time variables - check context first, then generate
    if lower_name == "aws:currenttime" {
        return context
            .get_condition_value("aws:currenttime")
            .and_then(|v| v.into_iter().next())
            .or_else(|| Some(format_current_time()));
    }
    if lower_name == "aws:epochtime" {
        return context
            .get_condition_value("aws:epochtime")
            .and_then(|v| v.into_iter().next())
            .or_else(|| Some(format_epoch_time()));
    }

    // Special handling for aws:username - derive from principal ARN if not set
    if lower_name == "aws:username" {
        // Try context bags first
        if let Some(values) = context.get_condition_value("aws:username")
            && let Some(first) = values.into_iter().next()
        {
            return Some(first);
        }
        // Fall back to deriving from principal ARN (looked up from bag)
        return context
            .get_condition_value("aws:principalarn")
            .and_then(|v| v.into_iter().next())
            .and_then(|arn| derive_username_from_arn(&arn));
    }

    // Unified lookup via context bags
    context
        .get_condition_value(var_name)
        .and_then(|v| v.into_iter().next())
}

/// Derive aws:username from a principal ARN.
///
/// AWS automatically populates aws:username based on the principal type:
/// - IAM user: the username portion (arn:aws:iam::123456789012:user/johndoe -> johndoe)
/// - Assumed role: the session name (arn:aws:sts::123456789012:assumed-role/Role/Session -> Session)
/// - Federated user: the user name (arn:aws:sts::123456789012:federated-user/Name -> Name)
fn derive_username_from_arn(arn: &str) -> Option<String> {
    // IAM user: arn:aws:iam::123456789012:user/johndoe
    if let Some(user_part) = arn.rsplit_once("user/") {
        return Some(user_part.1.to_string());
    }
    // Assumed role: arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
    if arn.contains("assumed-role/")
        && let Some(role_part) = arn.rsplit_once("assumed-role/")
        && let Some(session_name) = role_part.1.rsplit_once('/')
    {
        return Some(session_name.1.to_string());
    }
    // Federated user: arn:aws:sts::123456789012:federated-user/UserName
    if let Some(fed_part) = arn.rsplit_once("federated-user/") {
        return Some(fed_part.1.to_string());
    }
    None
}

/// Format current time in ISO 8601 format.
fn format_current_time() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Format current epoch time as string.
fn format_epoch_time() -> String {
    Utc::now().timestamp().to_string()
}

/// Check if a string contains any policy variables.
pub fn contains_variables(s: &str) -> bool {
    s.contains("${")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> RequestContext {
        RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::123456789012:user/johndoe")
            .principal_account("123456789012")
            .context_key("aws:sourceip", "192.168.1.100")
            .context_key("aws:securetransport", "true")
            .principal_tag("Department", "Engineering")
            .resource_tag("Environment", "Production")
            .request_tag("CostCenter", "12345")
            .build()
            .unwrap()
    }

    #[test]
    fn test_no_variables() {
        let ctx = make_context();
        let result = resolve_variables("arn:aws:s3:::my-bucket/*", &ctx);
        assert_eq!(result, "arn:aws:s3:::my-bucket/*");
    }

    #[test]
    fn test_principal_account() {
        let ctx = make_context();
        let result = resolve_variables("arn:aws:s3:::bucket-${aws:PrincipalAccount}/*", &ctx);
        assert_eq!(result, "arn:aws:s3:::bucket-123456789012/*");
    }

    #[test]
    fn test_principal_arn() {
        let ctx = make_context();
        let result = resolve_variables("${aws:PrincipalArn}", &ctx);
        assert_eq!(result, "arn:aws:iam::123456789012:user/johndoe");
    }

    #[test]
    fn test_username() {
        let ctx = make_context();
        let result = resolve_variables("users/${aws:username}/*", &ctx);
        assert_eq!(result, "users/johndoe/*");
    }

    #[test]
    fn test_source_ip() {
        let ctx = make_context();
        let result = resolve_variables("${aws:SourceIp}", &ctx);
        assert_eq!(result, "192.168.1.100");
    }

    #[test]
    fn test_secure_transport() {
        let ctx = make_context();
        let result = resolve_variables("${aws:SecureTransport}", &ctx);
        assert_eq!(result, "true");
    }

    #[test]
    fn test_principal_tag() {
        let ctx = make_context();
        let result = resolve_variables("${aws:PrincipalTag/Department}", &ctx);
        assert_eq!(result, "Engineering");
    }

    #[test]
    fn test_resource_tag() {
        let ctx = make_context();
        let result = resolve_variables("${aws:ResourceTag/Environment}", &ctx);
        assert_eq!(result, "Production");
    }

    #[test]
    fn test_request_tag() {
        let ctx = make_context();
        let result = resolve_variables("${aws:RequestTag/CostCenter}", &ctx);
        assert_eq!(result, "12345");
    }

    #[test]
    fn test_multiple_variables() {
        let ctx = make_context();
        let result = resolve_variables(
            "arn:aws:s3:::${aws:PrincipalAccount}-${aws:PrincipalTag/Department}/*",
            &ctx,
        );
        assert_eq!(result, "arn:aws:s3:::123456789012-Engineering/*");
    }

    #[test]
    fn test_unknown_variable() {
        let ctx = make_context();
        let result = resolve_variables("${unknown:variable}", &ctx);
        // Unknown variables are kept as-is
        assert_eq!(result, "${unknown:variable}");
    }

    #[test]
    fn test_partial_variable_syntax() {
        let ctx = make_context();
        // Unclosed variable
        let result = resolve_variables("test-${aws:PrincipalAccount", &ctx);
        assert_eq!(result, "test-${aws:PrincipalAccount");

        // Just dollar sign
        let result = resolve_variables("test$value", &ctx);
        assert_eq!(result, "test$value");
    }

    #[test]
    fn test_case_insensitive() {
        let ctx = make_context();
        // Variables should be case-insensitive
        let result = resolve_variables("${AWS:PRINCIPALACCOUNT}", &ctx);
        assert_eq!(result, "123456789012");
    }

    #[test]
    fn test_contains_variables() {
        assert!(contains_variables(
            "arn:aws:s3:::bucket-${aws:PrincipalAccount}/*"
        ));
        assert!(contains_variables("${aws:username}"));
        assert!(!contains_variables("arn:aws:s3:::bucket/*"));
        assert!(!contains_variables("no variables here"));
    }

    #[test]
    fn test_empty_string() {
        let ctx = make_context();
        let result = resolve_variables("", &ctx);
        assert_eq!(result, "");
    }

    #[test]
    fn test_username_from_role() {
        // When principal is a role (not assumed role), username extraction should fail
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::123456789012:role/MyRole")
            .build()
            .unwrap();

        let result = resolve_variables("${aws:username}", &ctx);
        // Username can't be extracted from role ARN, so variable is preserved
        assert_eq!(result, "${aws:username}");
    }

    #[test]
    fn test_username_from_assumed_role() {
        // When principal is an assumed role, extract the session name
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:sts::123456789012:assumed-role/MyRole/MySessionName")
            .build()
            .unwrap();

        let result = resolve_variables("${aws:username}", &ctx);
        // Should extract the session name from assumed role ARN
        assert_eq!(result, "MySessionName");
    }

    #[test]
    fn test_username_from_federated_user() {
        // When principal is a federated user, extract the username
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:sts::123456789012:federated-user/FederatedUserName")
            .build()
            .unwrap();

        let result = resolve_variables("${aws:username}", &ctx);
        // Should extract the username from federated user ARN
        assert_eq!(result, "FederatedUserName");
    }

    #[test]
    fn test_tag_case_sensitivity() {
        // Tag keys in AWS are case-sensitive (unlike condition key names which are case-insensitive)
        // The tag was set with "Department" (capital D), so lowercase "department" will NOT match
        let ctx = make_context();
        let result = resolve_variables("${aws:PrincipalTag/department}", &ctx);
        // Variable remains unresolved because tag key "department" != "Department"
        assert_eq!(result, "${aws:PrincipalTag/department}");

        // But the condition key prefix (aws:PrincipalTag) IS case-insensitive
        let result = resolve_variables("${AWS:PRINCIPALTAG/Department}", &ctx);
        assert_eq!(result, "Engineering");
    }
}
