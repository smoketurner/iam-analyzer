//! ARN parsing and validation.
//!
//! AWS ARN format:
//! ```text
//! arn:partition:service:region:account:resource
//! arn:partition:service:region:account:resource-type/resource-id
//! arn:partition:service:region:account:resource-type:resource-id
//! ```

use crate::error::{Error, Result};
use std::fmt;

/// A parsed, validated AWS ARN.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Arn {
    /// The partition (aws, aws-cn, aws-us-gov)
    pub partition: String,
    /// The service namespace (s3, ec2, iam, lambda, etc.)
    pub service: String,
    /// The region (us-east-1, eu-west-1, etc.) - empty for global services
    pub region: String,
    /// The account ID (12-digit) - empty for some resources like S3 buckets
    pub account: String,
    /// The resource portion (everything after the 5th colon)
    pub resource: String,
}

impl Arn {
    /// Parse an ARN string.
    ///
    /// # Examples
    ///
    /// ```
    /// use iam_analyzer::Arn;
    ///
    /// let arn = Arn::parse("arn:aws:s3:::my-bucket").unwrap();
    /// assert_eq!(arn.service, "s3");
    /// assert_eq!(arn.resource, "my-bucket");
    ///
    /// let arn = Arn::parse("arn:aws:iam::123456789012:user/johndoe").unwrap();
    /// assert_eq!(arn.service, "iam");
    /// assert_eq!(arn.account, "123456789012");
    /// assert_eq!(arn.resource, "user/johndoe");
    /// ```
    #[must_use = "parsing may fail, check the Result"]
    pub fn parse(s: &str) -> Result<Self> {
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

        let partition = parts[1];
        if partition.is_empty() {
            return Err(Error::InvalidArn(
                s.to_string(),
                "partition cannot be empty".to_string(),
            ));
        }

        let service = parts[2];
        if service.is_empty() {
            return Err(Error::InvalidArn(
                s.to_string(),
                "service cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            partition: partition.to_string(),
            service: service.to_string(),
            region: parts[3].to_string(),
            account: parts[4].to_string(),
            resource: parts[5].to_string(),
        })
    }

    /// Get the account ID if present.
    pub fn account_id(&self) -> Option<&str> {
        if self.account.is_empty() {
            None
        } else {
            Some(&self.account)
        }
    }

    /// Check if this ARN is for a global service (no region).
    pub fn is_global_service(&self) -> bool {
        self.region.is_empty()
            || matches!(
                self.service.as_str(),
                "iam" | "sts" | "s3" | "cloudfront" | "route53" | "organizations" | "waf"
            )
    }

    /// Extract the resource type from the resource portion.
    ///
    /// For `user/johndoe`, returns `Some("user")`.
    /// For `instance/i-12345`, returns `Some("instance")`.
    /// For `my-bucket`, returns `None`.
    pub fn resource_type(&self) -> Option<&str> {
        // Resource can be separated by / or :
        if let Some(idx) = self.resource.find('/') {
            Some(&self.resource[..idx])
        } else if let Some(idx) = self.resource.find(':') {
            Some(&self.resource[..idx])
        } else {
            None
        }
    }

    /// Extract the resource ID from the resource portion.
    ///
    /// For `user/johndoe`, returns `"johndoe"`.
    /// For `instance/i-12345`, returns `"i-12345"`.
    /// For `my-bucket`, returns `"my-bucket"`.
    pub fn resource_id(&self) -> &str {
        // Resource can be separated by / or :
        if let Some(idx) = self.resource.find('/') {
            &self.resource[idx + 1..]
        } else if let Some(idx) = self.resource.find(':') {
            &self.resource[idx + 1..]
        } else {
            &self.resource
        }
    }
}

impl fmt::Display for Arn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "arn:{}:{}:{}:{}:{}",
            self.partition, self.service, self.region, self.account, self.resource
        )
    }
}

impl std::str::FromStr for Arn {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_s3_bucket_arn() {
        let arn = Arn::parse("arn:aws:s3:::my-bucket").unwrap();
        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "s3");
        assert_eq!(arn.region, "");
        assert_eq!(arn.account, "");
        assert_eq!(arn.resource, "my-bucket");
        assert!(arn.is_global_service());
        assert_eq!(arn.account_id(), None);
        assert_eq!(arn.resource_type(), None);
        assert_eq!(arn.resource_id(), "my-bucket");
    }

    #[test]
    fn test_parse_s3_object_arn() {
        let arn = Arn::parse("arn:aws:s3:::my-bucket/path/to/object.txt").unwrap();
        assert_eq!(arn.resource, "my-bucket/path/to/object.txt");
        assert_eq!(arn.resource_type(), Some("my-bucket"));
        assert_eq!(arn.resource_id(), "path/to/object.txt");
    }

    #[test]
    fn test_parse_iam_user_arn() {
        let arn = Arn::parse("arn:aws:iam::123456789012:user/johndoe").unwrap();
        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "iam");
        assert_eq!(arn.region, "");
        assert_eq!(arn.account, "123456789012");
        assert_eq!(arn.resource, "user/johndoe");
        assert!(arn.is_global_service());
        assert_eq!(arn.account_id(), Some("123456789012"));
        assert_eq!(arn.resource_type(), Some("user"));
        assert_eq!(arn.resource_id(), "johndoe");
    }

    #[test]
    fn test_parse_iam_role_arn() {
        let arn = Arn::parse("arn:aws:iam::123456789012:role/MyRole").unwrap();
        assert_eq!(arn.service, "iam");
        assert_eq!(arn.resource, "role/MyRole");
        assert_eq!(arn.resource_type(), Some("role"));
        assert_eq!(arn.resource_id(), "MyRole");
    }

    #[test]
    fn test_parse_ec2_instance_arn() {
        let arn =
            Arn::parse("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0").unwrap();
        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "ec2");
        assert_eq!(arn.region, "us-east-1");
        assert_eq!(arn.account, "123456789012");
        assert_eq!(arn.resource, "instance/i-1234567890abcdef0");
        assert!(!arn.is_global_service());
        assert_eq!(arn.resource_type(), Some("instance"));
        assert_eq!(arn.resource_id(), "i-1234567890abcdef0");
    }

    #[test]
    fn test_parse_lambda_function_arn() {
        let arn = Arn::parse("arn:aws:lambda:us-west-2:123456789012:function:my-function").unwrap();
        assert_eq!(arn.service, "lambda");
        assert_eq!(arn.region, "us-west-2");
        assert_eq!(arn.resource, "function:my-function");
        // Resource uses colon separator
        assert_eq!(arn.resource_type(), Some("function"));
        assert_eq!(arn.resource_id(), "my-function");
    }

    #[test]
    fn test_parse_dynamodb_table_arn() {
        let arn = Arn::parse("arn:aws:dynamodb:us-east-1:123456789012:table/GameScores").unwrap();
        assert_eq!(arn.service, "dynamodb");
        assert_eq!(arn.resource, "table/GameScores");
        assert_eq!(arn.resource_type(), Some("table"));
    }

    #[test]
    fn test_parse_sns_topic_arn() {
        let arn = Arn::parse("arn:aws:sns:us-east-1:123456789012:my-topic").unwrap();
        assert_eq!(arn.service, "sns");
        assert_eq!(arn.resource, "my-topic");
        assert_eq!(arn.resource_type(), None);
        assert_eq!(arn.resource_id(), "my-topic");
    }

    #[test]
    fn test_parse_sqs_queue_arn() {
        let arn = Arn::parse("arn:aws:sqs:us-east-1:123456789012:my-queue").unwrap();
        assert_eq!(arn.service, "sqs");
        assert_eq!(arn.resource, "my-queue");
    }

    #[test]
    fn test_parse_china_partition() {
        let arn = Arn::parse("arn:aws-cn:s3:::my-bucket").unwrap();
        assert_eq!(arn.partition, "aws-cn");
        assert_eq!(arn.service, "s3");
    }

    #[test]
    fn test_parse_govcloud_partition() {
        let arn = Arn::parse("arn:aws-us-gov:s3:::my-bucket").unwrap();
        assert_eq!(arn.partition, "aws-us-gov");
    }

    #[test]
    fn test_parse_invalid_not_arn() {
        let result = Arn::parse("not-an-arn");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, Error::InvalidArn(_, _)));
    }

    #[test]
    fn test_parse_invalid_too_few_parts() {
        let result = Arn::parse("arn:aws:s3");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty_partition() {
        let result = Arn::parse("arn::s3:::bucket");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty_service() {
        let result = Arn::parse("arn:aws::::bucket");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_wrong_prefix() {
        let result = Arn::parse("notarn:aws:s3:::bucket");
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        let arn = Arn::parse("arn:aws:s3:::my-bucket").unwrap();
        assert_eq!(arn.to_string(), "arn:aws:s3:::my-bucket");

        let arn = Arn::parse("arn:aws:iam::123456789012:user/johndoe").unwrap();
        assert_eq!(arn.to_string(), "arn:aws:iam::123456789012:user/johndoe");
    }

    #[test]
    fn test_from_str() {
        let arn: Arn = "arn:aws:s3:::my-bucket".parse().unwrap();
        assert_eq!(arn.service, "s3");
    }

    #[test]
    fn test_resource_with_multiple_colons() {
        // Lambda function with version
        let arn =
            Arn::parse("arn:aws:lambda:us-west-2:123456789012:function:my-func:$LATEST").unwrap();
        assert_eq!(arn.resource, "function:my-func:$LATEST");
        assert_eq!(arn.resource_type(), Some("function"));
    }

    #[test]
    fn test_resource_with_multiple_slashes() {
        // S3 object with deep path
        let arn = Arn::parse("arn:aws:s3:::bucket/a/b/c/d/file.txt").unwrap();
        assert_eq!(arn.resource, "bucket/a/b/c/d/file.txt");
        assert_eq!(arn.resource_id(), "a/b/c/d/file.txt");
    }

    #[test]
    fn test_sts_assumed_role_arn() {
        let arn = Arn::parse("arn:aws:sts::123456789012:assumed-role/MyRole/session-name").unwrap();
        assert_eq!(arn.service, "sts");
        assert_eq!(arn.resource, "assumed-role/MyRole/session-name");
        assert_eq!(arn.resource_type(), Some("assumed-role"));
    }
}
