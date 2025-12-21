//! Action pattern parsing and matching.
//!
//! IAM action format: `service:action_name`
//! Supports wildcards: `*` (zero or more) and `?` (exactly one)

use crate::arn::pattern::glob_match;
use crate::error::{Error, Result};

/// A parsed action pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPattern {
    /// The service name pattern (e.g., "s3", "ec2", "*")
    pub service: String,
    /// The action name pattern (e.g., "GetObject", "*", "Describe*")
    pub action: String,
}

impl ActionPattern {
    /// Parse an action pattern string.
    ///
    /// # Examples
    ///
    /// ```
    /// use iam_analyzer::policy::action::ActionPattern;
    ///
    /// let pattern = ActionPattern::parse("s3:GetObject").unwrap();
    /// assert_eq!(pattern.service, "s3");
    /// assert_eq!(pattern.action, "GetObject");
    ///
    /// let pattern = ActionPattern::parse("*").unwrap();
    /// assert_eq!(pattern.service, "*");
    /// assert_eq!(pattern.action, "*");
    /// ```
    #[must_use = "parsing may fail, check the Result"]
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();

        // Special case: "*" matches all services and actions
        if s == "*" {
            return Ok(Self {
                service: "*".to_string(),
                action: "*".to_string(),
            });
        }

        // Must contain exactly one colon
        let colon_count = s.chars().filter(|&c| c == ':').count();
        if colon_count != 1 {
            return Err(Error::InvalidAction(
                s.to_string(),
                "action must be in format 'service:action' or '*'".to_string(),
            ));
        }

        let parts: Vec<&str> = s.splitn(2, ':').collect();
        let service = parts[0];
        let action = parts[1];

        // Validate service pattern
        if service.is_empty() {
            return Err(Error::InvalidAction(
                s.to_string(),
                "service name cannot be empty".to_string(),
            ));
        }

        // Validate action pattern
        if action.is_empty() {
            return Err(Error::InvalidAction(
                s.to_string(),
                "action name cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            service: service.to_string(),
            action: action.to_string(),
        })
    }

    /// Check if this pattern matches an action string.
    ///
    /// # Examples
    ///
    /// ```
    /// use iam_analyzer::policy::action::ActionPattern;
    ///
    /// let pattern = ActionPattern::parse("s3:Get*").unwrap();
    /// assert!(pattern.matches("s3:GetObject"));
    /// assert!(pattern.matches("s3:GetBucketLocation"));
    /// assert!(!pattern.matches("s3:PutObject"));
    /// assert!(!pattern.matches("ec2:GetObject"));
    /// ```
    pub fn matches(&self, action: &str) -> bool {
        // Parse the target action
        let target = match Self::parse(action) {
            Ok(t) => t,
            Err(_) => return false,
        };

        // Match service pattern (case-insensitive for service names)
        let service_match =
            glob_match(&self.service.to_lowercase(), &target.service.to_lowercase());

        // Match action pattern (case-insensitive for action names)
        let action_match = glob_match(&self.action.to_lowercase(), &target.action.to_lowercase());

        service_match && action_match
    }

    /// Check if this is a wildcard pattern that matches all actions.
    pub fn is_wildcard(&self) -> bool {
        self.service == "*" && self.action == "*"
    }
}

impl std::fmt::Display for ActionPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_wildcard() {
            write!(f, "*")
        } else {
            write!(f, "{}:{}", self.service, self.action)
        }
    }
}

impl std::str::FromStr for ActionPattern {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===================
    // Parsing tests
    // ===================

    #[test]
    fn test_parse_simple_action() {
        let pattern = ActionPattern::parse("s3:GetObject").unwrap();
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.action, "GetObject");
    }

    #[test]
    fn test_parse_wildcard_all() {
        let pattern = ActionPattern::parse("*").unwrap();
        assert_eq!(pattern.service, "*");
        assert_eq!(pattern.action, "*");
        assert!(pattern.is_wildcard());
    }

    #[test]
    fn test_parse_wildcard_action() {
        let pattern = ActionPattern::parse("s3:*").unwrap();
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.action, "*");
    }

    #[test]
    fn test_parse_wildcard_prefix() {
        let pattern = ActionPattern::parse("s3:Get*").unwrap();
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.action, "Get*");
    }

    #[test]
    fn test_parse_wildcard_suffix() {
        let pattern = ActionPattern::parse("s3:*Object").unwrap();
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.action, "*Object");
    }

    #[test]
    fn test_parse_service_with_hyphen() {
        let pattern = ActionPattern::parse("api-gateway:GET").unwrap();
        assert_eq!(pattern.service, "api-gateway");
    }

    #[test]
    fn test_parse_invalid_no_colon() {
        let result = ActionPattern::parse("s3GetObject");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty_service() {
        let result = ActionPattern::parse(":GetObject");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty_action() {
        let result = ActionPattern::parse("s3:");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_with_whitespace() {
        let pattern = ActionPattern::parse("  s3:GetObject  ").unwrap();
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.action, "GetObject");
    }

    // ===================
    // Matching tests
    // ===================

    #[test]
    fn test_matches_exact() {
        let pattern = ActionPattern::parse("s3:GetObject").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        assert!(!pattern.matches("s3:PutObject"));
        assert!(!pattern.matches("ec2:GetObject"));
    }

    #[test]
    fn test_matches_case_insensitive() {
        let pattern = ActionPattern::parse("s3:GetObject").unwrap();
        assert!(pattern.matches("S3:getobject"));
        assert!(pattern.matches("S3:GETOBJECT"));
        assert!(pattern.matches("s3:getObject"));
    }

    #[test]
    fn test_matches_wildcard_all() {
        let pattern = ActionPattern::parse("*").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        assert!(pattern.matches("ec2:RunInstances"));
        assert!(pattern.matches("iam:CreateUser"));
    }

    #[test]
    fn test_matches_wildcard_action() {
        let pattern = ActionPattern::parse("s3:*").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        assert!(pattern.matches("s3:PutObject"));
        assert!(pattern.matches("s3:ListBucket"));
        assert!(!pattern.matches("ec2:RunInstances"));
    }

    #[test]
    fn test_matches_wildcard_prefix() {
        let pattern = ActionPattern::parse("s3:Get*").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        assert!(pattern.matches("s3:GetBucketLocation"));
        assert!(pattern.matches("s3:GetBucketPolicy"));
        assert!(!pattern.matches("s3:PutObject"));
        assert!(!pattern.matches("s3:ListBucket"));
    }

    #[test]
    fn test_matches_wildcard_suffix() {
        let pattern = ActionPattern::parse("s3:*Object").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        assert!(pattern.matches("s3:PutObject"));
        assert!(pattern.matches("s3:DeleteObject"));
        assert!(!pattern.matches("s3:ListBucket"));
    }

    #[test]
    fn test_matches_wildcard_middle() {
        let pattern = ActionPattern::parse("s3:Get*Location").unwrap();
        assert!(pattern.matches("s3:GetBucketLocation"));
        assert!(pattern.matches("s3:GetObjectLocation"));
        assert!(!pattern.matches("s3:GetBucket"));
    }

    #[test]
    fn test_matches_question_mark() {
        let pattern = ActionPattern::parse("s3:Get?bject").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        assert!(!pattern.matches("s3:Getbject"));
        assert!(!pattern.matches("s3:GetXXbject"));
    }

    #[test]
    fn test_matches_wildcard_service() {
        let pattern = ActionPattern::parse("*:GetObject").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        // Note: EC2 doesn't have GetObject, but pattern matching is just string matching
        assert!(pattern.matches("ec2:GetObject"));
    }

    #[test]
    fn test_matches_complex_pattern() {
        let pattern = ActionPattern::parse("*:*").unwrap();
        assert!(pattern.matches("s3:GetObject"));
        assert!(pattern.matches("ec2:RunInstances"));
    }

    #[test]
    fn test_matches_ec2_describe_wildcard() {
        let pattern = ActionPattern::parse("ec2:Describe*").unwrap();
        assert!(pattern.matches("ec2:DescribeInstances"));
        assert!(pattern.matches("ec2:DescribeVolumes"));
        assert!(pattern.matches("ec2:DescribeSecurityGroups"));
        assert!(!pattern.matches("ec2:RunInstances"));
        assert!(!pattern.matches("ec2:StartInstances"));
    }

    // ===================
    // Display tests
    // ===================

    #[test]
    fn test_display() {
        let pattern = ActionPattern::parse("s3:GetObject").unwrap();
        assert_eq!(pattern.to_string(), "s3:GetObject");

        let wildcard = ActionPattern::parse("*").unwrap();
        assert_eq!(wildcard.to_string(), "*");
    }

    #[test]
    fn test_from_str() {
        let pattern: ActionPattern = "s3:GetObject".parse().unwrap();
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.action, "GetObject");
    }
}
