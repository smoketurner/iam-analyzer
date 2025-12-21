//! Condition operator evaluation.
//!
//! Implements all AWS IAM condition operators with support for:
//! - String operators (StringEquals, StringLike, etc.)
//! - Numeric operators (NumericEquals, NumericLessThan, etc.)
//! - Date operators (DateEquals, DateLessThan, etc.)
//! - Boolean operator (Bool)
//! - IP address operators (IpAddress, NotIpAddress)
//! - ARN operators (ArnEquals, ArnLike, etc.)
//! - Null operator (key existence check)
//! - Set operators (ForAllValues, ForAnyValue)
//! - IfExists modifier

use crate::arn::pattern::glob_match;
use crate::error::{Error, Result};
use crate::policy::ConditionOperator;
use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone, Utc};
use ipnet::IpNet;
use std::net::IpAddr;

/// Evaluate a condition block against the request context.
pub struct ConditionEvaluator;

impl ConditionEvaluator {
    /// Evaluate a single condition.
    ///
    /// # Arguments
    /// * `operator` - The condition operator (e.g., "StringEquals", "ForAllValues:StringLike")
    /// * `context_values` - Values from the request context (may be None if key doesn't exist)
    /// * `policy_values` - Values from the policy condition
    ///
    /// # Returns
    /// * `Ok(true)` if the condition matches
    /// * `Ok(false)` if the condition does not match
    /// * `Err` if the condition cannot be evaluated (e.g., invalid operator)
    pub fn evaluate(
        operator: &str,
        context_values: Option<&Vec<String>>,
        policy_values: &[String],
    ) -> Result<bool> {
        let parsed = ConditionOperator::parse(operator);

        // Handle Null operator specially
        if parsed.base == "Null" {
            return Self::evaluate_null(context_values, policy_values);
        }

        // Handle IfExists modifier
        if parsed.if_exists && context_values.is_none() {
            return Ok(true); // Condition is satisfied if key doesn't exist with IfExists
        }

        // If key doesn't exist and no IfExists, condition fails
        let context_values = match context_values {
            Some(v) => v,
            None => return Ok(false),
        };

        // Handle set operators
        if parsed.for_all_values {
            Self::evaluate_for_all_values(&parsed.base, context_values, policy_values)
        } else if parsed.for_any_value {
            Self::evaluate_for_any_value(&parsed.base, context_values, policy_values)
        } else if Self::is_negated_operator(&parsed.base) {
            // Negated operators use AND/NOR logic for multiple policy values
            Self::evaluate_negated_match(&parsed.base, context_values, policy_values)
        } else {
            // Default: any context value must match any policy value (OR logic)
            Self::evaluate_any_match(&parsed.base, context_values, policy_values)
        }
    }

    /// Evaluate ForAllValues: every context value must match at least one policy value.
    fn evaluate_for_all_values(
        base_operator: &str,
        context_values: &[String],
        policy_values: &[String],
    ) -> Result<bool> {
        // Empty context values satisfy ForAllValues
        if context_values.is_empty() {
            return Ok(true);
        }

        for ctx_val in context_values {
            let mut found_match = false;
            for policy_val in policy_values {
                if Self::compare_single(base_operator, ctx_val, policy_val)? {
                    found_match = true;
                    break;
                }
            }
            if !found_match {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Evaluate ForAnyValue: at least one context value must match at least one policy value.
    fn evaluate_for_any_value(
        base_operator: &str,
        context_values: &[String],
        policy_values: &[String],
    ) -> Result<bool> {
        for ctx_val in context_values {
            for policy_val in policy_values {
                if Self::compare_single(base_operator, ctx_val, policy_val)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Default evaluation: at least one context value must match at least one policy value.
    fn evaluate_any_match(
        base_operator: &str,
        context_values: &[String],
        policy_values: &[String],
    ) -> Result<bool> {
        for ctx_val in context_values {
            for policy_val in policy_values {
                if Self::compare_single(base_operator, ctx_val, policy_val)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Check if an operator is a negated operator that requires AND logic
    /// for multiple policy values (NOR semantics).
    ///
    /// Per AWS documentation, negated operators like StringNotEquals with multiple
    /// values use NOR logic: the condition matches only if the context value is
    /// different from ALL policy values.
    fn is_negated_operator(operator: &str) -> bool {
        matches!(
            operator,
            "StringNotEquals"
                | "StringNotEqualsIgnoreCase"
                | "StringNotLike"
                | "NumericNotEquals"
                | "DateNotEquals"
                | "ArnNotEquals"
                | "ArnNotLike"
                | "NotIpAddress"
        )
    }

    /// Evaluate negated operators with NOR semantics:
    /// For at least one context value, ALL comparisons with policy values must return true.
    /// (i.e., the context value must be different from ALL policy values)
    ///
    /// This differs from positive operators which use OR logic (match ANY policy value).
    fn evaluate_negated_match(
        base_operator: &str,
        context_values: &[String],
        policy_values: &[String],
    ) -> Result<bool> {
        // Special case: no policy values means nothing to compare against
        if policy_values.is_empty() {
            return Ok(true);
        }

        for ctx_val in context_values {
            let mut all_pass = true;
            for policy_val in policy_values {
                if !Self::compare_single(base_operator, ctx_val, policy_val)? {
                    // This context value matched a policy value it shouldn't have
                    all_pass = false;
                    break;
                }
            }
            if all_pass {
                // This context value is different from ALL policy values
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Evaluate Null operator: checks if the key exists.
    fn evaluate_null(
        context_values: Option<&Vec<String>>,
        policy_values: &[String],
    ) -> Result<bool> {
        let expect_null = policy_values
            .first()
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(true);

        let key_exists = context_values.is_some() && !context_values.unwrap().is_empty();

        // Null: true means key should NOT exist
        // Null: false means key should exist
        Ok(if expect_null { !key_exists } else { key_exists })
    }

    /// Compare a single context value against a single policy value.
    fn compare_single(operator: &str, context_val: &str, policy_val: &str) -> Result<bool> {
        match operator {
            // String operators
            "StringEquals" => Ok(context_val == policy_val),
            "StringNotEquals" => Ok(context_val != policy_val),
            "StringEqualsIgnoreCase" => Ok(context_val.eq_ignore_ascii_case(policy_val)),
            "StringNotEqualsIgnoreCase" => Ok(!context_val.eq_ignore_ascii_case(policy_val)),
            "StringLike" => Ok(glob_match(policy_val, context_val)),
            "StringNotLike" => Ok(!glob_match(policy_val, context_val)),

            // Numeric operators
            "NumericEquals" => compare_numeric(context_val, policy_val, |a, b| a == b),
            "NumericNotEquals" => compare_numeric(context_val, policy_val, |a, b| a != b),
            "NumericLessThan" => compare_numeric(context_val, policy_val, |a, b| a < b),
            "NumericLessThanEquals" => compare_numeric(context_val, policy_val, |a, b| a <= b),
            "NumericGreaterThan" => compare_numeric(context_val, policy_val, |a, b| a > b),
            "NumericGreaterThanEquals" => compare_numeric(context_val, policy_val, |a, b| a >= b),

            // Date operators
            "DateEquals" => compare_date(context_val, policy_val, |a, b| a == b),
            "DateNotEquals" => compare_date(context_val, policy_val, |a, b| a != b),
            "DateLessThan" => compare_date(context_val, policy_val, |a, b| a < b),
            "DateLessThanEquals" => compare_date(context_val, policy_val, |a, b| a <= b),
            "DateGreaterThan" => compare_date(context_val, policy_val, |a, b| a > b),
            "DateGreaterThanEquals" => compare_date(context_val, policy_val, |a, b| a >= b),

            // Boolean operator
            "Bool" => {
                let ctx_bool = parse_bool(context_val)?;
                let policy_bool = parse_bool(policy_val)?;
                Ok(ctx_bool == policy_bool)
            }

            // Binary operator (base64 comparison)
            "BinaryEquals" => Ok(context_val == policy_val),

            // IP address operators
            "IpAddress" => ip_in_cidr(context_val, policy_val),
            "NotIpAddress" => ip_in_cidr(context_val, policy_val).map(|r| !r),

            // ARN operators
            "ArnEquals" => Ok(context_val == policy_val),
            "ArnNotEquals" => Ok(context_val != policy_val),
            "ArnLike" => {
                // Parse as ARN patterns and match
                match (
                    crate::arn::Arn::parse(context_val),
                    crate::arn::ArnPattern::parse(policy_val),
                ) {
                    (Ok(arn), Ok(pattern)) => Ok(pattern.matches(&arn)),
                    _ => Ok(false),
                }
            }
            "ArnNotLike" => {
                match (
                    crate::arn::Arn::parse(context_val),
                    crate::arn::ArnPattern::parse(policy_val),
                ) {
                    (Ok(arn), Ok(pattern)) => Ok(!pattern.matches(&arn)),
                    _ => Ok(true),
                }
            }

            _ => Err(Error::UnknownOperator(operator.to_string())),
        }
    }
}

/// Compare two numeric values.
fn compare_numeric<F>(context_val: &str, policy_val: &str, cmp: F) -> Result<bool>
where
    F: Fn(f64, f64) -> bool,
{
    let ctx: f64 = context_val
        .parse()
        .map_err(|_| Error::InvalidConditionValue {
            operator: "Numeric".to_string(),
            message: format!("cannot parse '{}' as number", context_val),
        })?;
    let policy: f64 = policy_val
        .parse()
        .map_err(|_| Error::InvalidConditionValue {
            operator: "Numeric".to_string(),
            message: format!("cannot parse '{}' as number", policy_val),
        })?;
    Ok(cmp(ctx, policy))
}

/// Parse a date string to epoch seconds.
/// Supports ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ or YYYY-MM-DDTHH:MM:SS+HH:MM
/// Also handles fractional seconds and epoch seconds as integer.
fn parse_date_to_epoch(s: &str) -> Result<i64> {
    // Try parsing as epoch seconds first
    if let Ok(epoch) = s.parse::<i64>() {
        return Ok(epoch);
    }

    let s = s.trim();

    // Try parsing with timezone offset (e.g., 2024-01-15T10:30:00+05:00)
    if let Ok(dt) = DateTime::<FixedOffset>::parse_from_rfc3339(s) {
        return Ok(dt.timestamp());
    }

    // Try parsing with Z suffix by replacing Z with +00:00 for RFC3339
    if s.ends_with('Z') {
        let rfc3339 = format!("{}+00:00", &s[..s.len() - 1]);
        if let Ok(dt) = DateTime::<FixedOffset>::parse_from_rfc3339(&rfc3339) {
            return Ok(dt.timestamp());
        }
    }

    // Try parsing as naive datetime (no timezone) and assume UTC
    // Handle formats like "2024-01-15T10:30:00" or "2024-01-15"
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(Utc.from_utc_datetime(&ndt).timestamp());
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
        return Ok(Utc.from_utc_datetime(&ndt).timestamp());
    }
    if let Ok(nd) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let ndt = nd.and_hms_opt(0, 0, 0).unwrap();
        return Ok(Utc.from_utc_datetime(&ndt).timestamp());
    }

    Err(Error::InvalidConditionValue {
        operator: "Date".to_string(),
        message: format!("invalid date format: {}", s),
    })
}

/// Compare two date values.
fn compare_date<F>(context_val: &str, policy_val: &str, cmp: F) -> Result<bool>
where
    F: Fn(i64, i64) -> bool,
{
    let ctx = parse_date_to_epoch(context_val)?;
    let policy = parse_date_to_epoch(policy_val)?;
    Ok(cmp(ctx, policy))
}

/// Parse a boolean value.
fn parse_bool(s: &str) -> Result<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(Error::InvalidConditionValue {
            operator: "Bool".to_string(),
            message: format!("cannot parse '{}' as boolean", s),
        }),
    }
}

/// Check if an IP address is within a CIDR range.
pub fn ip_in_cidr(ip_str: &str, cidr: &str) -> Result<bool> {
    let ip: IpAddr = ip_str.parse().map_err(|_| Error::InvalidConditionValue {
        operator: "IpAddress".to_string(),
        message: format!("invalid IP address: {}", ip_str),
    })?;

    // Handle CIDR with or without prefix length
    let network: IpNet = if cidr.contains('/') {
        cidr.parse().map_err(|_| Error::InvalidConditionValue {
            operator: "IpAddress".to_string(),
            message: format!("invalid CIDR network: {}", cidr),
        })?
    } else {
        // No prefix, treat as single host (/32 for IPv4, /128 for IPv6)
        let addr: IpAddr = cidr.parse().map_err(|_| Error::InvalidConditionValue {
            operator: "IpAddress".to_string(),
            message: format!("invalid CIDR network: {}", cidr),
        })?;
        match addr {
            IpAddr::V4(v4) => IpNet::V4(ipnet::Ipv4Net::from(v4)),
            IpAddr::V6(v6) => IpNet::V6(ipnet::Ipv6Net::from(v6)),
        }
    };

    Ok(network.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===================
    // String operator tests
    // ===================

    #[test]
    fn test_string_equals() {
        let ctx = vec!["foo".to_string()];
        let policy = vec!["foo".to_string()];
        assert!(ConditionEvaluator::evaluate("StringEquals", Some(&ctx), &policy).unwrap());

        let policy = vec!["bar".to_string()];
        assert!(!ConditionEvaluator::evaluate("StringEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_not_equals() {
        let ctx = vec!["foo".to_string()];
        let policy = vec!["bar".to_string()];
        assert!(ConditionEvaluator::evaluate("StringNotEquals", Some(&ctx), &policy).unwrap());

        let policy = vec!["foo".to_string()];
        assert!(!ConditionEvaluator::evaluate("StringNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_equals_ignore_case() {
        let ctx = vec!["FOO".to_string()];
        let policy = vec!["foo".to_string()];
        assert!(
            ConditionEvaluator::evaluate("StringEqualsIgnoreCase", Some(&ctx), &policy).unwrap()
        );
    }

    #[test]
    fn test_string_like() {
        let ctx = vec!["test-value".to_string()];
        let policy = vec!["test-*".to_string()];
        assert!(ConditionEvaluator::evaluate("StringLike", Some(&ctx), &policy).unwrap());

        let policy = vec!["*-value".to_string()];
        assert!(ConditionEvaluator::evaluate("StringLike", Some(&ctx), &policy).unwrap());

        let policy = vec!["other-*".to_string()];
        assert!(!ConditionEvaluator::evaluate("StringLike", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_not_like() {
        let ctx = vec!["test-value".to_string()];
        let policy = vec!["other-*".to_string()];
        assert!(ConditionEvaluator::evaluate("StringNotLike", Some(&ctx), &policy).unwrap());
    }

    // ===================
    // Numeric operator tests
    // ===================

    #[test]
    fn test_numeric_equals() {
        let ctx = vec!["42".to_string()];
        let policy = vec!["42".to_string()];
        assert!(ConditionEvaluator::evaluate("NumericEquals", Some(&ctx), &policy).unwrap());

        let policy = vec!["43".to_string()];
        assert!(!ConditionEvaluator::evaluate("NumericEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_numeric_less_than() {
        let ctx = vec!["5".to_string()];
        let policy = vec!["10".to_string()];
        assert!(ConditionEvaluator::evaluate("NumericLessThan", Some(&ctx), &policy).unwrap());

        let ctx = vec!["15".to_string()];
        assert!(!ConditionEvaluator::evaluate("NumericLessThan", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_numeric_greater_than() {
        let ctx = vec!["10".to_string()];
        let policy = vec!["5".to_string()];
        assert!(ConditionEvaluator::evaluate("NumericGreaterThan", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_numeric_with_floats() {
        let ctx = vec!["3.14".to_string()];
        let policy = vec!["3.14".to_string()];
        assert!(ConditionEvaluator::evaluate("NumericEquals", Some(&ctx), &policy).unwrap());

        let policy = vec!["3.0".to_string()];
        assert!(ConditionEvaluator::evaluate("NumericGreaterThan", Some(&ctx), &policy).unwrap());
    }

    // ===================
    // Date operator tests
    // ===================

    #[test]
    fn test_date_equals() {
        let ctx = vec!["2024-01-15T10:30:00Z".to_string()];
        let policy = vec!["2024-01-15T10:30:00Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_less_than() {
        let ctx = vec!["2024-01-01T00:00:00Z".to_string()];
        let policy = vec!["2024-12-31T23:59:59Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateLessThan", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_with_epoch() {
        // Epoch seconds
        let ctx = vec!["1704067200".to_string()]; // 2024-01-01 00:00:00 UTC
        let policy = vec!["1704067200".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_with_positive_timezone() {
        // Test with +00:00 timezone (equivalent to Z)
        let ctx = vec!["2024-01-15T10:30:00+00:00".to_string()];
        let policy = vec!["2024-01-15T10:30:00Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_with_offset_timezone() {
        // Test with +05:00 timezone (5 hours ahead of UTC)
        // 2024-01-15T15:30:00+05:00 should equal 2024-01-15T10:30:00Z
        let ctx = vec!["2024-01-15T15:30:00+05:00".to_string()];
        let policy = vec!["2024-01-15T10:30:00Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_with_negative_timezone() {
        // Test with -05:00 timezone (5 hours behind UTC)
        // 2024-01-15T05:30:00-05:00 should equal 2024-01-15T10:30:00Z
        let ctx = vec!["2024-01-15T05:30:00-05:00".to_string()];
        let policy = vec!["2024-01-15T10:30:00Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_with_fractional_seconds() {
        // Fractional seconds should be truncated
        let ctx = vec!["2024-01-15T10:30:00.123Z".to_string()];
        let policy = vec!["2024-01-15T10:30:00Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_with_fractional_seconds_and_timezone() {
        // Both fractional seconds and timezone offset
        let ctx = vec!["2024-01-15T15:30:00.999+05:00".to_string()];
        let policy = vec!["2024-01-15T10:30:00Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEquals", Some(&ctx), &policy).unwrap());
    }

    // ===================
    // Boolean operator tests
    // ===================

    #[test]
    fn test_bool() {
        let ctx = vec!["true".to_string()];
        let policy = vec!["true".to_string()];
        assert!(ConditionEvaluator::evaluate("Bool", Some(&ctx), &policy).unwrap());

        let ctx = vec!["false".to_string()];
        assert!(!ConditionEvaluator::evaluate("Bool", Some(&ctx), &policy).unwrap());

        // Also test with "1" and "0"
        let ctx = vec!["1".to_string()];
        assert!(ConditionEvaluator::evaluate("Bool", Some(&ctx), &policy).unwrap());
    }

    // ===================
    // IP address operator tests
    // ===================

    #[test]
    fn test_ip_address_in_cidr() {
        let ctx = vec!["192.168.1.100".to_string()];
        let policy = vec!["192.168.1.0/24".to_string()];
        assert!(ConditionEvaluator::evaluate("IpAddress", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_ip_address_not_in_cidr() {
        let ctx = vec!["10.0.0.1".to_string()];
        let policy = vec!["192.168.1.0/24".to_string()];
        assert!(!ConditionEvaluator::evaluate("IpAddress", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_not_ip_address() {
        let ctx = vec!["10.0.0.1".to_string()];
        let policy = vec!["192.168.1.0/24".to_string()];
        assert!(ConditionEvaluator::evaluate("NotIpAddress", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_ip_address_exact() {
        let ctx = vec!["192.168.1.100".to_string()];
        let policy = vec!["192.168.1.100".to_string()]; // No /prefix means /32
        assert!(ConditionEvaluator::evaluate("IpAddress", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_ip_address_ipv6() {
        let ctx = vec!["2001:db8::1".to_string()];
        let policy = vec!["2001:db8::/32".to_string()];
        assert!(ConditionEvaluator::evaluate("IpAddress", Some(&ctx), &policy).unwrap());
    }

    // ===================
    // ARN operator tests
    // ===================

    #[test]
    fn test_arn_equals() {
        let ctx = vec!["arn:aws:s3:::my-bucket".to_string()];
        let policy = vec!["arn:aws:s3:::my-bucket".to_string()];
        assert!(ConditionEvaluator::evaluate("ArnEquals", Some(&ctx), &policy).unwrap());

        let policy = vec!["arn:aws:s3:::other-bucket".to_string()];
        assert!(!ConditionEvaluator::evaluate("ArnEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_arn_like() {
        let ctx = vec!["arn:aws:s3:::my-bucket/path/to/object".to_string()];
        let policy = vec!["arn:aws:s3:::my-bucket/*".to_string()];
        assert!(ConditionEvaluator::evaluate("ArnLike", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_arn_not_like() {
        let ctx = vec!["arn:aws:s3:::other-bucket/object".to_string()];
        let policy = vec!["arn:aws:s3:::my-bucket/*".to_string()];
        assert!(ConditionEvaluator::evaluate("ArnNotLike", Some(&ctx), &policy).unwrap());
    }

    // ===================
    // Null operator tests
    // ===================

    #[test]
    fn test_null_true_key_missing() {
        let policy = vec!["true".to_string()];
        assert!(ConditionEvaluator::evaluate("Null", None, &policy).unwrap());
    }

    #[test]
    fn test_null_true_key_exists() {
        let ctx = vec!["some-value".to_string()];
        let policy = vec!["true".to_string()];
        assert!(!ConditionEvaluator::evaluate("Null", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_null_false_key_exists() {
        let ctx = vec!["some-value".to_string()];
        let policy = vec!["false".to_string()];
        assert!(ConditionEvaluator::evaluate("Null", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_null_false_key_missing() {
        let policy = vec!["false".to_string()];
        assert!(!ConditionEvaluator::evaluate("Null", None, &policy).unwrap());
    }

    // ===================
    // IfExists modifier tests
    // ===================

    #[test]
    fn test_if_exists_key_missing() {
        let policy = vec!["expected-value".to_string()];
        // With IfExists, missing key should return true
        assert!(ConditionEvaluator::evaluate("StringEqualsIfExists", None, &policy).unwrap());
    }

    #[test]
    fn test_if_exists_key_present() {
        let ctx = vec!["expected-value".to_string()];
        let policy = vec!["expected-value".to_string()];
        assert!(ConditionEvaluator::evaluate("StringEqualsIfExists", Some(&ctx), &policy).unwrap());

        let ctx = vec!["other-value".to_string()];
        assert!(
            !ConditionEvaluator::evaluate("StringEqualsIfExists", Some(&ctx), &policy).unwrap()
        );
    }

    // ===================
    // Set operator tests
    // ===================

    #[test]
    fn test_for_all_values_all_match() {
        let ctx = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let policy = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        assert!(
            ConditionEvaluator::evaluate("ForAllValues:StringEquals", Some(&ctx), &policy).unwrap()
        );
    }

    #[test]
    fn test_for_all_values_one_missing() {
        let ctx = vec!["a".to_string(), "b".to_string(), "x".to_string()];
        let policy = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        assert!(
            !ConditionEvaluator::evaluate("ForAllValues:StringEquals", Some(&ctx), &policy)
                .unwrap()
        );
    }

    #[test]
    fn test_for_all_values_empty_context() {
        let ctx = vec![];
        let policy = vec!["a".to_string()];
        // Empty context satisfies ForAllValues
        assert!(
            ConditionEvaluator::evaluate("ForAllValues:StringEquals", Some(&ctx), &policy).unwrap()
        );
    }

    #[test]
    fn test_for_any_value_one_match() {
        let ctx = vec!["a".to_string(), "x".to_string(), "y".to_string()];
        let policy = vec!["a".to_string(), "b".to_string()];
        assert!(
            ConditionEvaluator::evaluate("ForAnyValue:StringEquals", Some(&ctx), &policy).unwrap()
        );
    }

    #[test]
    fn test_for_any_value_no_match() {
        let ctx = vec!["x".to_string(), "y".to_string(), "z".to_string()];
        let policy = vec!["a".to_string(), "b".to_string()];
        assert!(
            !ConditionEvaluator::evaluate("ForAnyValue:StringEquals", Some(&ctx), &policy).unwrap()
        );
    }

    #[test]
    fn test_for_any_value_with_if_exists() {
        // Combined modifiers
        let policy = vec!["a".to_string()];
        // Missing key with IfExists should return true
        assert!(
            ConditionEvaluator::evaluate("ForAnyValue:StringEqualsIfExists", None, &policy)
                .unwrap()
        );
    }

    // ===================
    // Multiple values tests
    // ===================

    #[test]
    fn test_multiple_context_values() {
        let ctx = vec!["foo".to_string(), "bar".to_string()];
        let policy = vec!["bar".to_string()];
        // Default behavior: any context value matching any policy value
        assert!(ConditionEvaluator::evaluate("StringEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_multiple_policy_values() {
        let ctx = vec!["bar".to_string()];
        let policy = vec!["foo".to_string(), "bar".to_string(), "baz".to_string()];
        assert!(ConditionEvaluator::evaluate("StringEquals", Some(&ctx), &policy).unwrap());
    }

    // ===================
    // ip_in_cidr function tests
    // ===================

    #[test]
    fn test_ip_in_cidr_basic() {
        assert!(ip_in_cidr("192.168.1.1", "192.168.1.0/24").unwrap());
        assert!(ip_in_cidr("192.168.1.254", "192.168.1.0/24").unwrap());
        assert!(!ip_in_cidr("192.168.2.1", "192.168.1.0/24").unwrap());
    }

    #[test]
    fn test_ip_in_cidr_smaller_range() {
        assert!(ip_in_cidr("10.0.0.1", "10.0.0.0/30").unwrap());
        assert!(ip_in_cidr("10.0.0.2", "10.0.0.0/30").unwrap());
        assert!(!ip_in_cidr("10.0.0.4", "10.0.0.0/30").unwrap());
    }

    #[test]
    fn test_ip_in_cidr_single_host() {
        assert!(ip_in_cidr("192.168.1.100", "192.168.1.100/32").unwrap());
        assert!(!ip_in_cidr("192.168.1.101", "192.168.1.100/32").unwrap());
    }

    #[test]
    fn test_ip_in_cidr_ipv6() {
        assert!(ip_in_cidr("2001:db8::1", "2001:db8::/32").unwrap());
        assert!(ip_in_cidr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db8::/32").unwrap());
        assert!(!ip_in_cidr("2001:db9::1", "2001:db8::/32").unwrap());
    }

    #[test]
    fn test_ip_in_cidr_invalid_ip() {
        assert!(ip_in_cidr("not-an-ip", "192.168.1.0/24").is_err());
    }

    #[test]
    fn test_ip_in_cidr_invalid_cidr() {
        assert!(ip_in_cidr("192.168.1.1", "not-a-cidr").is_err());
    }

    // ===================
    // Bug fix tests: Negated operators with multiple values
    // ===================

    #[test]
    fn test_string_not_equals_multiple_values_match_one() {
        // THE BUG CASE: value equals one of the policy values
        let ctx = vec!["us-east-1".to_string()];
        let policy = vec!["us-east-1".to_string(), "us-west-1".to_string()];
        // Should NOT match because "us-east-1" equals one of the values
        assert!(!ConditionEvaluator::evaluate("StringNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_not_equals_multiple_values_match_none() {
        let ctx = vec!["eu-west-1".to_string()];
        let policy = vec!["us-east-1".to_string(), "us-west-1".to_string()];
        // Should match because "eu-west-1" is different from ALL values
        assert!(ConditionEvaluator::evaluate("StringNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_not_equals_multiple_context_values() {
        let ctx = vec!["us-east-1".to_string(), "eu-west-1".to_string()];
        let policy = vec!["us-east-1".to_string(), "us-west-1".to_string()];
        // "eu-west-1" is different from ALL, so should match
        assert!(ConditionEvaluator::evaluate("StringNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_not_equals_ignore_case_multiple_values() {
        let ctx = vec!["US-EAST-1".to_string()];
        let policy = vec!["us-east-1".to_string(), "us-west-1".to_string()];
        // Should NOT match (case-insensitive equality)
        assert!(
            !ConditionEvaluator::evaluate("StringNotEqualsIgnoreCase", Some(&ctx), &policy)
                .unwrap()
        );
    }

    #[test]
    fn test_string_not_like_multiple_values() {
        let ctx = vec!["test-value".to_string()];
        let policy = vec!["test-*".to_string(), "other-*".to_string()];
        // Should NOT match because "test-value" matches "test-*"
        assert!(!ConditionEvaluator::evaluate("StringNotLike", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_not_like_multiple_values_no_match() {
        let ctx = vec!["prod-value".to_string()];
        let policy = vec!["test-*".to_string(), "dev-*".to_string()];
        // Should match because "prod-value" matches neither pattern
        assert!(ConditionEvaluator::evaluate("StringNotLike", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_numeric_not_equals_multiple_values() {
        let ctx = vec!["42".to_string()];
        let policy = vec!["42".to_string(), "100".to_string()];
        // Should NOT match because 42 equals one of the values
        assert!(!ConditionEvaluator::evaluate("NumericNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_numeric_not_equals_multiple_values_no_match() {
        let ctx = vec!["50".to_string()];
        let policy = vec!["42".to_string(), "100".to_string()];
        // Should match because 50 is different from all values
        assert!(ConditionEvaluator::evaluate("NumericNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_date_not_equals_multiple_values() {
        let ctx = vec!["2024-01-15T10:30:00Z".to_string()];
        let policy = vec![
            "2024-01-15T10:30:00Z".to_string(),
            "2024-06-01T00:00:00Z".to_string(),
        ];
        // Should NOT match because first date equals one of the values
        assert!(!ConditionEvaluator::evaluate("DateNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_arn_not_equals_multiple_values() {
        let ctx = vec!["arn:aws:s3:::bucket-a".to_string()];
        let policy = vec![
            "arn:aws:s3:::bucket-a".to_string(),
            "arn:aws:s3:::bucket-b".to_string(),
        ];
        // Should NOT match because ARN equals one of the values
        assert!(!ConditionEvaluator::evaluate("ArnNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_arn_not_like_multiple_values() {
        let ctx = vec!["arn:aws:s3:::my-bucket/file.txt".to_string()];
        let policy = vec![
            "arn:aws:s3:::my-bucket/*".to_string(),
            "arn:aws:s3:::other-bucket/*".to_string(),
        ];
        // Should NOT match because it matches the first pattern
        assert!(!ConditionEvaluator::evaluate("ArnNotLike", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_arn_not_like_multiple_values_no_match() {
        let ctx = vec!["arn:aws:s3:::third-bucket/file.txt".to_string()];
        let policy = vec![
            "arn:aws:s3:::my-bucket/*".to_string(),
            "arn:aws:s3:::other-bucket/*".to_string(),
        ];
        // Should match because it doesn't match any pattern
        assert!(ConditionEvaluator::evaluate("ArnNotLike", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_not_ip_address_multiple_cidrs_in_range() {
        let ctx = vec!["192.168.1.100".to_string()];
        let policy = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];
        // Should NOT match because IP is in first CIDR
        assert!(!ConditionEvaluator::evaluate("NotIpAddress", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_not_ip_address_multiple_cidrs_not_in_range() {
        let ctx = vec!["172.16.0.1".to_string()];
        let policy = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];
        // Should match because IP is not in any CIDR
        assert!(ConditionEvaluator::evaluate("NotIpAddress", Some(&ctx), &policy).unwrap());
    }

    // Regression tests for positive operators
    #[test]
    fn test_string_equals_multiple_values_still_works() {
        let ctx = vec!["us-east-1".to_string()];
        let policy = vec!["us-east-1".to_string(), "us-west-1".to_string()];
        // Should match (OR logic - unchanged)
        assert!(ConditionEvaluator::evaluate("StringEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_ip_address_multiple_cidrs_still_works() {
        let ctx = vec!["192.168.1.100".to_string()];
        let policy = vec!["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()];
        // Should match (OR logic - unchanged)
        assert!(ConditionEvaluator::evaluate("IpAddress", Some(&ctx), &policy).unwrap());
    }

    // Edge cases
    #[test]
    fn test_negated_operator_empty_policy_values() {
        let ctx = vec!["any".to_string()];
        let policy: Vec<String> = vec![];
        // With no policy values, condition passes (vacuously true)
        assert!(ConditionEvaluator::evaluate("StringNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_negated_operator_empty_context_values() {
        let ctx: Vec<String> = vec![];
        let policy = vec!["foo".to_string()];
        // No context values means no value can pass
        assert!(!ConditionEvaluator::evaluate("StringNotEquals", Some(&ctx), &policy).unwrap());
    }

    #[test]
    fn test_string_not_equals_if_exists_multiple_values() {
        let ctx = vec!["eu-west-1".to_string()];
        let policy = vec!["us-east-1".to_string(), "us-west-1".to_string()];
        assert!(
            ConditionEvaluator::evaluate("StringNotEqualsIfExists", Some(&ctx), &policy).unwrap()
        );

        // Missing key with IfExists returns true
        assert!(ConditionEvaluator::evaluate("StringNotEqualsIfExists", None, &policy).unwrap());
    }

    #[test]
    fn test_string_not_equals_if_exists_match_one() {
        let ctx = vec!["us-east-1".to_string()];
        let policy = vec!["us-east-1".to_string(), "us-west-1".to_string()];
        // Should NOT match because value equals one of the policy values
        assert!(
            !ConditionEvaluator::evaluate("StringNotEqualsIfExists", Some(&ctx), &policy).unwrap()
        );
    }

    // ===================
    // AWS Behavior Accuracy Tests
    // ===================

    /// ForAnyValue with empty context should FAIL (no values to match)
    /// AWS behavior: ForAnyValue requires at least one context value to match
    #[test]
    fn test_for_any_value_empty_context_fails() {
        let ctx: Vec<String> = vec![];
        let policy = vec!["a".to_string(), "b".to_string()];
        // Empty context means no value can match any policy value
        assert!(
            !ConditionEvaluator::evaluate("ForAnyValue:StringEquals", Some(&ctx), &policy).unwrap()
        );
    }

    /// Null operator with key present but empty string value
    /// AWS behavior: Key with empty string still EXISTS (Null:true should fail)
    #[test]
    fn test_null_true_key_exists_with_empty_string() {
        let ctx = vec!["".to_string()]; // Empty string, but key exists
        let policy = vec!["true".to_string()];
        // Key exists (even if empty), so Null:true should NOT match
        assert!(!ConditionEvaluator::evaluate("Null", Some(&ctx), &policy).unwrap());
    }

    /// IfExists modifier with ArnLike operator
    #[test]
    fn test_arn_like_if_exists_key_missing() {
        let policy = vec!["arn:aws:s3:::bucket/*".to_string()];
        // Missing key with IfExists should return true
        assert!(ConditionEvaluator::evaluate("ArnLikeIfExists", None, &policy).unwrap());
    }

    /// IfExists modifier with IpAddress operator
    #[test]
    fn test_ip_address_if_exists_key_missing() {
        let policy = vec!["10.0.0.0/8".to_string()];
        // Missing key with IfExists should return true
        assert!(ConditionEvaluator::evaluate("IpAddressIfExists", None, &policy).unwrap());
    }

    /// IfExists with key present should evaluate normally
    #[test]
    fn test_string_equals_if_exists_key_present_match() {
        let ctx = vec!["us-east-1".to_string()];
        let policy = vec!["us-east-1".to_string()];
        assert!(ConditionEvaluator::evaluate("StringEqualsIfExists", Some(&ctx), &policy).unwrap());
    }

    /// IfExists with key present but non-matching value
    #[test]
    fn test_string_equals_if_exists_key_present_no_match() {
        let ctx = vec!["eu-west-1".to_string()];
        let policy = vec!["us-east-1".to_string()];
        // Key present, but value doesn't match - should fail
        assert!(
            !ConditionEvaluator::evaluate("StringEqualsIfExists", Some(&ctx), &policy).unwrap()
        );
    }

    /// NumericEquals with IfExists modifier
    #[test]
    fn test_numeric_equals_if_exists_key_missing() {
        let policy = vec!["100".to_string()];
        assert!(ConditionEvaluator::evaluate("NumericEqualsIfExists", None, &policy).unwrap());
    }

    /// DateEquals with IfExists modifier
    #[test]
    fn test_date_equals_if_exists_key_missing() {
        let policy = vec!["2024-01-01T00:00:00Z".to_string()];
        assert!(ConditionEvaluator::evaluate("DateEqualsIfExists", None, &policy).unwrap());
    }

    /// Bool operator with IfExists modifier
    #[test]
    fn test_bool_if_exists_key_missing() {
        let policy = vec!["true".to_string()];
        assert!(ConditionEvaluator::evaluate("BoolIfExists", None, &policy).unwrap());
    }

    /// Combined modifiers: ForAllValues with IfExists
    #[test]
    fn test_for_all_values_if_exists_key_missing() {
        let policy = vec!["a".to_string()];
        // Missing key with IfExists should return true
        assert!(
            ConditionEvaluator::evaluate("ForAllValues:StringEqualsIfExists", None, &policy)
                .unwrap()
        );
    }

    /// Multiple conditions on same operator should use AND logic
    /// This is handled at the statement level, but testing the operator behavior
    #[test]
    fn test_ip_address_multiple_context_values() {
        // Context has multiple IPs, policy has one CIDR
        // Should match if ANY context IP is in the CIDR
        let ctx = vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()];
        let policy = vec!["192.168.1.0/24".to_string()];
        assert!(ConditionEvaluator::evaluate("IpAddress", Some(&ctx), &policy).unwrap());
    }

    /// NotIpAddress with multiple context values - all must be outside all CIDRs
    #[test]
    fn test_not_ip_address_multiple_context_values_all_outside() {
        let ctx = vec!["172.16.0.1".to_string(), "172.17.0.1".to_string()];
        let policy = vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()];
        // All context IPs are outside all CIDRs - any matching context value passes
        assert!(ConditionEvaluator::evaluate("NotIpAddress", Some(&ctx), &policy).unwrap());
    }

    /// NotIpAddress with one context value inside - should pass for the other
    #[test]
    fn test_not_ip_address_multiple_context_one_inside() {
        let ctx = vec!["172.16.0.1".to_string(), "192.168.1.100".to_string()];
        let policy = vec!["192.168.1.0/24".to_string()];
        // First IP is outside CIDR, so it passes the NotIpAddress check
        // For negated operators: any context value passing means condition matches
        assert!(ConditionEvaluator::evaluate("NotIpAddress", Some(&ctx), &policy).unwrap());
    }
}
