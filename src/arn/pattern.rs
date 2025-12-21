//! ARN pattern matching with wildcards.
//!
//! Supports matching ARNs against patterns that contain `*` and `?` wildcards.
//! Wildcards are matched per-segment as per AWS documentation.

use crate::error::{Error, Result};
use std::fmt;

/// A pattern for matching ARNs with wildcards.
///
/// Supports `*` (match zero or more characters) and `?` (match exactly one character).
/// Wildcards are evaluated per-segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArnPattern {
    /// The partition pattern
    pub partition: String,
    /// The service pattern
    pub service: String,
    /// The region pattern
    pub region: String,
    /// The account pattern
    pub account: String,
    /// The resource pattern
    pub resource: String,
}

impl ArnPattern {
    /// Parse an ARN pattern from a policy string.
    ///
    /// # Examples
    ///
    /// ```
    /// use iam_analyzer::ArnPattern;
    ///
    /// // Match any S3 bucket
    /// let pattern = ArnPattern::parse("arn:aws:s3:::*").unwrap();
    ///
    /// // Match any object in a specific bucket
    /// let pattern = ArnPattern::parse("arn:aws:s3:::my-bucket/*").unwrap();
    ///
    /// // Match any EC2 instance in any region
    /// let pattern = ArnPattern::parse("arn:aws:ec2:*:123456789012:instance/*").unwrap();
    /// ```
    #[must_use = "parsing may fail, check the Result"]
    pub fn parse(s: &str) -> Result<Self> {
        // Special case: "*" matches everything
        if s == "*" {
            return Ok(Self {
                partition: "*".to_string(),
                service: "*".to_string(),
                region: "*".to_string(),
                account: "*".to_string(),
                resource: "*".to_string(),
            });
        }

        let parts: Vec<&str> = s.splitn(6, ':').collect();

        if parts.len() < 6 {
            return Err(Error::InvalidArn(
                s.to_string(),
                format!("expected 6 colon-separated parts, found {}", parts.len()),
            ));
        }

        if parts[0] != "arn" {
            return Err(Error::InvalidArn(
                s.to_string(),
                format!("must start with 'arn:', found '{}'", parts[0]),
            ));
        }

        Ok(Self {
            partition: parts[1].to_string(),
            service: parts[2].to_string(),
            region: parts[3].to_string(),
            account: parts[4].to_string(),
            resource: parts[5].to_string(),
        })
    }

    /// Check if an ARN matches this pattern.
    ///
    /// Each segment is matched independently using glob-style wildcards.
    ///
    /// # Examples
    ///
    /// ```
    /// use iam_analyzer::{Arn, ArnPattern};
    ///
    /// let pattern = ArnPattern::parse("arn:aws:s3:::my-bucket/*").unwrap();
    /// let arn = Arn::parse("arn:aws:s3:::my-bucket/file.txt").unwrap();
    /// assert!(pattern.matches(&arn));
    ///
    /// let other = Arn::parse("arn:aws:s3:::other-bucket/file.txt").unwrap();
    /// assert!(!pattern.matches(&other));
    /// ```
    pub fn matches(&self, arn: &super::Arn) -> bool {
        glob_match(&self.partition, &arn.partition)
            && glob_match(&self.service, &arn.service)
            && glob_match(&self.region, &arn.region)
            && glob_match(&self.account, &arn.account)
            && glob_match(&self.resource, &arn.resource)
    }

    /// Check if a string ARN matches this pattern (parses the ARN first).
    pub fn matches_str(&self, arn: &str) -> bool {
        match super::Arn::parse(arn) {
            Ok(parsed) => self.matches(&parsed),
            Err(_) => false,
        }
    }

    /// Check if this pattern is a wildcard that matches everything.
    pub fn is_wildcard(&self) -> bool {
        self.partition == "*"
            && self.service == "*"
            && self.region == "*"
            && self.account == "*"
            && self.resource == "*"
    }
}

impl fmt::Display for ArnPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_wildcard() {
            write!(f, "*")
        } else {
            write!(
                f,
                "arn:{}:{}:{}:{}:{}",
                self.partition, self.service, self.region, self.account, self.resource
            )
        }
    }
}

impl std::str::FromStr for ArnPattern {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

/// Match a glob pattern against text.
///
/// Supports:
/// - `*` - matches zero or more characters
/// - `?` - matches exactly one character
///
/// This is a simple recursive implementation without regex.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    glob_match_impl(&pattern, &text)
}

fn glob_match_impl(pattern: &[char], text: &[char]) -> bool {
    match (pattern.first(), text.first()) {
        // Both empty - match
        (None, None) => true,
        // Pattern empty but text remains - no match
        (None, Some(_)) => false,
        // Pattern has * - try matching zero or more characters
        (Some('*'), _) => {
            // Skip consecutive *s
            let mut p = pattern;
            while p.first() == Some(&'*') {
                p = &p[1..];
            }
            // If pattern is exhausted after *s, match everything
            if p.is_empty() {
                return true;
            }
            // Try matching * as zero characters, then one, then two, etc.
            let mut t = text;
            loop {
                if glob_match_impl(p, t) {
                    return true;
                }
                if t.is_empty() {
                    return false;
                }
                t = &t[1..];
            }
        }
        // Pattern has ? - match exactly one character
        (Some('?'), Some(_)) => glob_match_impl(&pattern[1..], &text[1..]),
        // Pattern has ? but text is empty - no match
        (Some('?'), None) => false,
        // Literal character match
        (Some(p), Some(t)) if *p == *t => glob_match_impl(&pattern[1..], &text[1..]),
        // Literal character mismatch
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arn::Arn;

    // ===================
    // glob_match tests
    // ===================

    #[test]
    fn test_glob_exact_match() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
        assert!(!glob_match("hello", "hell"));
        assert!(!glob_match("hell", "hello"));
    }

    #[test]
    fn test_glob_empty() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "a"));
        assert!(!glob_match("a", ""));
    }

    #[test]
    fn test_glob_star_basic() {
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", "a/b/c"));
    }

    #[test]
    fn test_glob_star_prefix() {
        assert!(glob_match("prefix*", "prefix"));
        assert!(glob_match("prefix*", "prefix-suffix"));
        assert!(glob_match("prefix*", "prefixanything"));
        assert!(!glob_match("prefix*", "notprefix"));
    }

    #[test]
    fn test_glob_star_suffix() {
        assert!(glob_match("*suffix", "suffix"));
        assert!(glob_match("*suffix", "prefix-suffix"));
        assert!(glob_match("*suffix", "anythingsuffix"));
        assert!(!glob_match("*suffix", "suffixnot"));
    }

    #[test]
    fn test_glob_star_middle() {
        assert!(glob_match("pre*fix", "prefix"));
        assert!(glob_match("pre*fix", "pre-middle-fix"));
        assert!(glob_match("pre*fix", "preANYTHINGfix"));
        assert!(!glob_match("pre*fix", "pre"));
        assert!(!glob_match("pre*fix", "fix"));
    }

    #[test]
    fn test_glob_multiple_stars() {
        assert!(glob_match("*/*", "a/b"));
        assert!(glob_match("*/*", "anything/else"));
        assert!(glob_match("**", "anything"));
        assert!(glob_match("a*b*c", "abc"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(glob_match("?", "a"));
        assert!(glob_match("?", "X"));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("?", "ab"));
    }

    #[test]
    fn test_glob_question_mark_multiple() {
        assert!(glob_match("???", "abc"));
        assert!(glob_match("???", "123"));
        assert!(!glob_match("???", "ab"));
        assert!(!glob_match("???", "abcd"));
    }

    #[test]
    fn test_glob_question_and_star() {
        assert!(glob_match("?*", "a"));
        assert!(glob_match("?*", "abc"));
        assert!(!glob_match("?*", ""));
        assert!(glob_match("*?", "a"));
        assert!(glob_match("*?", "abc"));
        assert!(!glob_match("*?", ""));
    }

    #[test]
    fn test_glob_complex_patterns() {
        assert!(glob_match("user/*", "user/johndoe"));
        assert!(glob_match("user/*", "user/"));
        assert!(!glob_match("user/*", "user"));
        assert!(glob_match("bucket/*/file.txt", "bucket/any/file.txt"));
        assert!(!glob_match("bucket/*/file.txt", "bucket/file.txt"));
    }

    // ===================
    // ArnPattern parse tests
    // ===================

    #[test]
    fn test_parse_wildcard_all() {
        let pattern = ArnPattern::parse("*").unwrap();
        assert!(pattern.is_wildcard());
        assert_eq!(pattern.to_string(), "*");
    }

    #[test]
    fn test_parse_s3_bucket_pattern() {
        let pattern = ArnPattern::parse("arn:aws:s3:::my-bucket").unwrap();
        assert_eq!(pattern.partition, "aws");
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.region, "");
        assert_eq!(pattern.account, "");
        assert_eq!(pattern.resource, "my-bucket");
    }

    #[test]
    fn test_parse_s3_wildcard_pattern() {
        let pattern = ArnPattern::parse("arn:aws:s3:::my-bucket/*").unwrap();
        assert_eq!(pattern.resource, "my-bucket/*");
    }

    #[test]
    fn test_parse_ec2_wildcard_region() {
        let pattern = ArnPattern::parse("arn:aws:ec2:*:123456789012:instance/*").unwrap();
        assert_eq!(pattern.region, "*");
        assert_eq!(pattern.account, "123456789012");
        assert_eq!(pattern.resource, "instance/*");
    }

    #[test]
    fn test_parse_iam_all_users() {
        let pattern = ArnPattern::parse("arn:aws:iam::*:user/*").unwrap();
        assert_eq!(pattern.account, "*");
        assert_eq!(pattern.resource, "user/*");
    }

    #[test]
    fn test_parse_invalid_pattern() {
        assert!(ArnPattern::parse("not-an-arn").is_err());
        assert!(ArnPattern::parse("arn:aws:s3").is_err());
    }

    // ===================
    // ArnPattern matches tests
    // ===================

    #[test]
    fn test_matches_wildcard_all() {
        let pattern = ArnPattern::parse("*").unwrap();
        assert!(pattern.matches_str("arn:aws:s3:::bucket"));
        assert!(pattern.matches_str("arn:aws:ec2:us-east-1:123456789012:instance/i-123"));
        assert!(pattern.matches_str("arn:aws-cn:iam::111111111111:user/alice"));
    }

    #[test]
    fn test_matches_exact() {
        let pattern = ArnPattern::parse("arn:aws:s3:::my-bucket").unwrap();
        let arn = Arn::parse("arn:aws:s3:::my-bucket").unwrap();
        assert!(pattern.matches(&arn));

        let other = Arn::parse("arn:aws:s3:::other-bucket").unwrap();
        assert!(!pattern.matches(&other));
    }

    #[test]
    fn test_matches_resource_wildcard() {
        let pattern = ArnPattern::parse("arn:aws:s3:::my-bucket/*").unwrap();

        assert!(pattern.matches_str("arn:aws:s3:::my-bucket/file.txt"));
        assert!(pattern.matches_str("arn:aws:s3:::my-bucket/path/to/file.txt"));
        assert!(pattern.matches_str("arn:aws:s3:::my-bucket/"));
        assert!(!pattern.matches_str("arn:aws:s3:::my-bucket")); // no trailing /
        assert!(!pattern.matches_str("arn:aws:s3:::other-bucket/file.txt"));
    }

    #[test]
    fn test_matches_bucket_prefix_wildcard() {
        let pattern = ArnPattern::parse("arn:aws:s3:::prefix-*").unwrap();

        assert!(pattern.matches_str("arn:aws:s3:::prefix-bucket"));
        assert!(pattern.matches_str("arn:aws:s3:::prefix-anything"));
        assert!(pattern.matches_str("arn:aws:s3:::prefix-"));
        assert!(!pattern.matches_str("arn:aws:s3:::other-bucket"));
    }

    #[test]
    fn test_matches_region_wildcard() {
        let pattern = ArnPattern::parse("arn:aws:ec2:*:123456789012:instance/*").unwrap();

        assert!(pattern.matches_str("arn:aws:ec2:us-east-1:123456789012:instance/i-123"));
        assert!(pattern.matches_str("arn:aws:ec2:eu-west-1:123456789012:instance/i-456"));
        assert!(pattern.matches_str("arn:aws:ec2:ap-northeast-1:123456789012:instance/i-789"));
        assert!(!pattern.matches_str("arn:aws:ec2:us-east-1:999999999999:instance/i-123"));
    }

    #[test]
    fn test_matches_account_wildcard() {
        let pattern = ArnPattern::parse("arn:aws:iam::*:user/*").unwrap();

        assert!(pattern.matches_str("arn:aws:iam::111111111111:user/alice"));
        assert!(pattern.matches_str("arn:aws:iam::222222222222:user/bob"));
        assert!(!pattern.matches_str("arn:aws:iam::111111111111:role/MyRole"));
    }

    #[test]
    fn test_matches_service_wildcard() {
        let pattern = ArnPattern::parse("arn:aws:*:us-east-1:123456789012:*").unwrap();

        assert!(pattern.matches_str("arn:aws:ec2:us-east-1:123456789012:instance/i-123"));
        assert!(pattern.matches_str("arn:aws:lambda:us-east-1:123456789012:function:my-func"));
        assert!(!pattern.matches_str("arn:aws:ec2:us-west-2:123456789012:instance/i-123"));
    }

    #[test]
    fn test_matches_partition_wildcard() {
        let pattern = ArnPattern::parse("arn:*:s3:::my-bucket").unwrap();

        assert!(pattern.matches_str("arn:aws:s3:::my-bucket"));
        assert!(pattern.matches_str("arn:aws-cn:s3:::my-bucket"));
        assert!(pattern.matches_str("arn:aws-us-gov:s3:::my-bucket"));
    }

    #[test]
    fn test_matches_complex_resource_pattern() {
        let pattern = ArnPattern::parse("arn:aws:s3:::*-logs/*").unwrap();

        assert!(pattern.matches_str("arn:aws:s3:::app-logs/file.log"));
        assert!(pattern.matches_str("arn:aws:s3:::server-logs/2024/01/access.log"));
        assert!(!pattern.matches_str("arn:aws:s3:::app-data/file.txt"));
    }

    #[test]
    fn test_matches_question_mark_in_resource() {
        let pattern = ArnPattern::parse("arn:aws:s3:::bucket-?").unwrap();

        assert!(pattern.matches_str("arn:aws:s3:::bucket-a"));
        assert!(pattern.matches_str("arn:aws:s3:::bucket-1"));
        assert!(!pattern.matches_str("arn:aws:s3:::bucket-ab"));
        assert!(!pattern.matches_str("arn:aws:s3:::bucket-"));
    }

    #[test]
    fn test_matches_lambda_with_version() {
        let pattern = ArnPattern::parse("arn:aws:lambda:*:*:function:my-func*").unwrap();

        assert!(pattern.matches_str("arn:aws:lambda:us-east-1:123456789012:function:my-func"));
        assert!(
            pattern.matches_str("arn:aws:lambda:us-west-2:123456789012:function:my-func:$LATEST")
        );
        assert!(pattern.matches_str("arn:aws:lambda:eu-west-1:123456789012:function:my-func:1"));
        assert!(!pattern.matches_str("arn:aws:lambda:us-east-1:123456789012:function:other-func"));
    }

    #[test]
    fn test_matches_empty_segments() {
        // S3 has empty region and account
        let pattern = ArnPattern::parse("arn:aws:s3:::*").unwrap();
        assert_eq!(pattern.region, "");
        assert_eq!(pattern.account, "");

        assert!(pattern.matches_str("arn:aws:s3:::any-bucket"));
        // Should not match if region is provided
        assert!(!pattern.matches_str("arn:aws:s3:us-east-1::any-bucket"));
    }

    #[test]
    fn test_from_str() {
        let pattern: ArnPattern = "arn:aws:s3:::*".parse().unwrap();
        assert_eq!(pattern.service, "s3");
        assert_eq!(pattern.resource, "*");
    }

    #[test]
    fn test_display() {
        let pattern = ArnPattern::parse("arn:aws:s3:::my-bucket/*").unwrap();
        assert_eq!(pattern.to_string(), "arn:aws:s3:::my-bucket/*");

        let wildcard = ArnPattern::parse("*").unwrap();
        assert_eq!(wildcard.to_string(), "*");
    }
}
