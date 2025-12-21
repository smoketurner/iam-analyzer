//! Integration tests using fixture files.
//!
//! These tests verify the IAM policy evaluation logic using
//! real-world policy examples from AWS documentation.

use iam_analyzer::{
    Decision, EvaluationEngine, NamedPolicy, OrganizationHierarchy, Policy, PolicySet,
    RequestContext,
};
use std::fs;

/// Load a policy from a fixture file.
fn load_policy(path: &str) -> NamedPolicy {
    let json =
        fs::read_to_string(path).unwrap_or_else(|_| panic!("Failed to read policy file: {}", path));
    let policy: Policy =
        serde_json::from_str(&json).unwrap_or_else(|_| panic!("Failed to parse policy: {}", path));
    // Extract just the filename for a cleaner policy name
    let name = std::path::Path::new(path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    NamedPolicy::new(name, policy)
}

// =============================================================================
// Identity-based Policy Tests
// =============================================================================

#[test]
fn test_identity_policy_allows_s3_read() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-read.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_identity_policy_allows_s3_list_bucket() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:ListBucket")
        .resource("arn:aws:s3:::my-bucket")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-read.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_identity_policy_denies_unallowed_action() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:PutObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-read.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

// =============================================================================
// Explicit Deny Override Tests
// =============================================================================

#[test]
fn test_explicit_deny_overrides_allow() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:DeleteObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![
            load_policy("tests/fixtures/identity/allow-s3-full.json"),
            load_policy("tests/fixtures/identity/deny-s3-delete.json"),
        ],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

#[test]
fn test_s3_full_allows_when_no_deny() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:PutObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

// =============================================================================
// Permission Boundary Tests
// =============================================================================

#[test]
fn test_permission_boundary_blocks_out_of_scope() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("iam:CreateUser")
        .resource("arn:aws:iam::123456789012:user/newuser")
        .principal_arn("arn:aws:iam::123456789012:user/admin")
        .principal_account("123456789012")
        .build()
        .unwrap();

    // Identity policy allows S3 full (so won't allow IAM)
    // Even if we added iam:* to identity, the boundary would block it
    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        permission_boundaries: vec![load_policy(
            "tests/fixtures/boundaries/s3-cloudwatch-ec2-only.json",
        )],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Should be implicit deny - IAM not in boundary and not in identity policy
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

#[test]
fn test_permission_boundary_allows_in_scope() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/developer")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        permission_boundaries: vec![load_policy(
            "tests/fixtures/boundaries/s3-cloudwatch-ec2-only.json",
        )],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // S3 is in both identity policy and boundary, so should be allowed
    assert_eq!(result.decision, Decision::Allow);
}

// =============================================================================
// SCP Tests
// =============================================================================

#[test]
fn test_scp_full_access_allows() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            ou_scps: vec![],
            account_scps: vec![],
        }),
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_scp_deny_leave_organization() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("organizations:LeaveOrganization")
        .resource("*")
        .principal_arn("arn:aws:iam::123456789012:user/admin")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/scp/deny-leave-organization.json"),
            ],
            ou_scps: vec![],
            account_scps: vec![],
        }),
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

// =============================================================================
// Resource-based Policy Tests
// =============================================================================

#[test]
fn test_anonymous_request_with_public_bucket() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::public-bucket/file.txt")
        // No principal - anonymous request
        .build()
        .unwrap();

    let policies = PolicySet {
        resource_policies: vec![load_policy(
            "tests/fixtures/resource/s3-bucket-public-read.json",
        )],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_anonymous_request_denied_without_resource_policy() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::private-bucket/file.txt")
        // No principal - anonymous request
        .build()
        .unwrap();

    // No resource policy
    let policies = PolicySet::default();

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

// =============================================================================
// Cross-Account Access Tests
// =============================================================================

#[test]
fn test_cross_account_requires_both_policies() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::shared-bucket/file.txt")
        .principal_arn("arn:aws:iam::111111111111:user/external")
        .principal_account("111111111111")
        .resource_account("222222222222")
        .cross_account(true)
        .build()
        .unwrap();

    // Only resource policy, no identity policy
    let policies = PolicySet {
        resource_policies: vec![load_policy(
            "tests/fixtures/resource/s3-bucket-cross-account.json",
        )],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Cross-account requires both policies
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

#[test]
fn test_cross_account_succeeds_with_both_policies() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::shared-bucket/file.txt")
        .principal_arn("arn:aws:iam::111111111111:user/external")
        .principal_account("111111111111")
        .resource_account("222222222222")
        .cross_account(true)
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-read.json")],
        resource_policies: vec![load_policy(
            "tests/fixtures/resource/s3-bucket-cross-account.json",
        )],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

// =============================================================================
// VPC Endpoint Policy Tests
// =============================================================================

#[test]
fn test_vpc_endpoint_allows_all() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        vpc_endpoint_policies: vec![load_policy("tests/fixtures/vpc-endpoint/allow-all.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_vpc_endpoint_restricts_to_read_only() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:PutObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        vpc_endpoint_policies: vec![load_policy("tests/fixtures/vpc-endpoint/s3-read-only.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // PutObject is not in the VPC endpoint policy allow list
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

// =============================================================================
// Session Policy Tests
// =============================================================================

#[test]
fn test_session_policy_restricts_access() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:us-east-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/developer")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        session_policies: vec![load_policy("tests/fixtures/session/s3-only-session.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Session policy only allows S3, so EC2 should be denied
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

#[test]
fn test_session_policy_allows_s3() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/developer")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        session_policies: vec![load_policy("tests/fixtures/session/s3-only-session.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // S3 is allowed by both identity and session policy
    assert_eq!(result.decision, Decision::Allow);
}

// =============================================================================
// DynamoDB Tests
// =============================================================================

#[test]
fn test_dynamodb_read_allowed() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("dynamodb:GetItem")
        .resource("arn:aws:dynamodb:us-east-1:123456789012:table/Users")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy(
            "tests/fixtures/identity/allow-dynamodb-read.json",
        )],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_dynamodb_write_denied_with_read_only_policy() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("dynamodb:PutItem")
        .resource("arn:aws:dynamodb:us-east-1:123456789012:table/Users")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy(
            "tests/fixtures/identity/allow-dynamodb-read.json",
        )],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

// =============================================================================
// Multiple Policy Type Combination Tests
// =============================================================================

#[test]
fn test_all_policies_must_allow() {
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            ou_scps: vec![],
            account_scps: vec![],
        }),
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        permission_boundaries: vec![load_policy(
            "tests/fixtures/boundaries/s3-cloudwatch-ec2-only.json",
        )],
        session_policies: vec![load_policy("tests/fixtures/session/s3-only-session.json")],
        vpc_endpoint_policies: vec![load_policy("tests/fixtures/vpc-endpoint/allow-all.json")],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // All policies allow S3, so this should succeed
    assert_eq!(result.decision, Decision::Allow);
}

// =============================================================================
// Condition Operator Bug Fix Tests (StringNotEquals with multiple values)
// =============================================================================

#[test]
fn test_scp_region_restriction_allows_us_region() {
    // This test validates the StringNotEquals bug fix
    // The SCP denies actions where aws:RequestedRegion is NOT in the US regions list
    // When the region IS us-east-1 (in the list), the deny should NOT match
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:us-east-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("us-east-1")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            // Account level needs BOTH: an Allow SCP + the deny SCP
            // This mirrors AWS behavior where each level must have an Allow
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/scp/deny-region-outside-us.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // us-east-1 IS in the allowed list, so the deny condition should NOT match
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_scp_region_restriction_allows_us_west_2() {
    // Test another US region from the list
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:us-west-2:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("us-west-2")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/scp/deny-region-outside-us.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_scp_region_restriction_denies_non_us_region() {
    // Test that a region NOT in the US list is denied
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:eu-west-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("eu-west-1")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/scp/deny-region-outside-us.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // eu-west-1 is NOT in the allowed regions, so the deny condition SHOULD match
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

#[test]
fn test_scp_region_restriction_denies_ap_region() {
    // Test another non-US region
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:ap-southeast-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("ap-southeast-1")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/scp/deny-region-outside-us.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

// =============================================================================
// Condition Operator Fixture Tests
// =============================================================================

#[test]
fn test_condition_string_not_equals_single_value_match() {
    // StringNotEquals with single value: us-east-1
    // When region IS us-east-1, condition should NOT match (deny doesn't apply)
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:us-east-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("us-east-1")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/string-not-equals-single.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_condition_string_not_equals_single_value_no_match() {
    // StringNotEquals with single value: us-east-1
    // When region is eu-west-1, condition SHOULD match (deny applies)
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:eu-west-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("eu-west-1")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/string-not-equals-single.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

#[test]
fn test_condition_string_not_equals_multiple_values_match_one() {
    // StringNotEquals with multiple values: ["us-east-1", "us-east-2", "us-west-1", "us-west-2"]
    // When region is us-west-2 (in list), condition should NOT match
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:us-west-2:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("us-west-2")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/string-not-equals-multiple.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_condition_string_not_equals_multiple_values_match_none() {
    // StringNotEquals with multiple values
    // When region is ap-northeast-1 (NOT in list), condition SHOULD match
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:ap-northeast-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("ap-northeast-1")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-ec2-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/string-not-equals-multiple.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

#[test]
fn test_condition_not_ip_address_in_whitelist() {
    // NotIpAddress with CIDRs: ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    // When IP is 10.1.2.3 (in 10.0.0.0/8), condition should NOT match
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::bucket/key")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("aws:SourceIp", "10.1.2.3")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/not-ip-address-multiple.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_condition_not_ip_address_not_in_whitelist() {
    // NotIpAddress with CIDRs: ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    // When IP is 203.0.113.50 (public IP, not in any CIDR), condition SHOULD match
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::bucket/key")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("aws:SourceIp", "203.0.113.50")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/not-ip-address-multiple.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

#[test]
fn test_condition_arn_not_like_principal_in_list() {
    // ArnNotLike with patterns: ["arn:aws:iam::111111111111:*", "arn:aws:iam::222222222222:*"]
    // When principal is from 111111111111, condition should NOT match
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::bucket/key")
        .principal_arn("arn:aws:iam::111111111111:user/alice")
        .principal_account("111111111111")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/arn-not-like-multiple.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_condition_arn_not_like_principal_not_in_list() {
    // ArnNotLike with patterns: ["arn:aws:iam::111111111111:*", "arn:aws:iam::222222222222:*"]
    // When principal is from 333333333333 (not in list), condition SHOULD match
    let engine = EvaluationEngine::new();

    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::bucket/key")
        .principal_arn("arn:aws:iam::333333333333:user/alice")
        .principal_account("333333333333")
        .build()
        .unwrap();

    let policies = PolicySet {
        identity_policies: vec![load_policy("tests/fixtures/identity/allow-s3-full.json")],
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![load_policy("tests/fixtures/scp/full-aws-access.json")],
            account_scps: vec![
                load_policy("tests/fixtures/scp/full-aws-access.json"),
                load_policy("tests/fixtures/conditions/arn-not-like-multiple.json"),
            ],
            ..Default::default()
        }),
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

// =============================================================================
// AWS Behavior Accuracy Tests - Cross-Account AssumeRole Variants
// =============================================================================

#[test]
fn test_cross_account_assume_role_with_saml() {
    // sts:AssumeRoleWithSAML should succeed with only trust policy
    // AWS behavior: All sts:AssumeRole* actions can work with trust policy alone
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("sts:AssumeRoleWithSAML")
        .resource("arn:aws:iam::222222222222:role/SAMLRole")
        .principal_account("111111111111")
        .resource_account("222222222222")
        .cross_account(true)
        .build()
        .unwrap();

    let trust_policy = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRoleWithSAML",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        resource_policies: vec![NamedPolicy::new("TrustPolicy", trust_policy)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_cross_account_assume_role_case_insensitive() {
    // Action names are case-insensitive in AWS
    // STS:ASSUMEROLE should work the same as sts:AssumeRole
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("STS:ASSUMEROLE") // Uppercase
        .resource("arn:aws:iam::222222222222:role/TestRole")
        .principal_arn("arn:aws:iam::111111111111:user/alice")
        .principal_account("111111111111")
        .resource_account("222222222222")
        .cross_account(true)
        .build()
        .unwrap();

    let trust_policy = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::111111111111:root"
                },
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        resource_policies: vec![NamedPolicy::new("TrustPolicy", trust_policy)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Should allow because action matching is case-insensitive
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_cross_account_assume_role_explicit_deny_in_identity() {
    // Even though trust policy alone can grant AssumeRole access,
    // an explicit deny in any policy still blocks
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("sts:AssumeRole")
        .resource("arn:aws:iam::222222222222:role/TestRole")
        .principal_arn("arn:aws:iam::111111111111:user/alice")
        .principal_account("111111111111")
        .resource_account("222222222222")
        .cross_account(true)
        .build()
        .unwrap();

    let trust_policy = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let deny_assume_role = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Sid": "DenyAssumeRole",
                "Effect": "Deny",
                "Action": "sts:AssumeRole",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        identity_policies: vec![NamedPolicy::new("DenyPolicy", deny_assume_role)],
        resource_policies: vec![NamedPolicy::new("TrustPolicy", trust_policy)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Explicit deny should still block
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

// =============================================================================
// AWS Behavior Accuracy Tests - Service-Linked Role SCP Bypass
// =============================================================================

#[test]
fn test_service_linked_role_bypasses_scp() {
    // Service-linked roles bypass SCPs
    // AWS behavior: SLRs are not affected by SCPs
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("dynamodb:GetItem")
        .resource("arn:aws:dynamodb:us-east-1:123456789012:table/Users")
        .principal_arn("arn:aws:iam::123456789012:role/aws-service-role/elasticloadbalancing.amazonaws.com/AWSServiceRoleForElasticLoadBalancing")
        .principal_account("123456789012")
        .service_linked_role(true) // This marks it as a service-linked role
        .build()
        .unwrap();

    // SCP only allows S3, should block DynamoDB for normal roles
    let restrictive_scp = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let full_access_identity = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![NamedPolicy::new("RestrictiveSCP", restrictive_scp)],
            ou_scps: vec![],
            account_scps: vec![],
        }),
        identity_policies: vec![NamedPolicy::new("FullAccess", full_access_identity)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Service-linked role bypasses SCPs, so this should be allowed
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_regular_role_blocked_by_scp() {
    // Regular roles ARE affected by SCPs (control case for above test)
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("dynamodb:GetItem")
        .resource("arn:aws:dynamodb:us-east-1:123456789012:table/Users")
        .principal_arn("arn:aws:iam::123456789012:role/RegularRole")
        .principal_account("123456789012")
        .service_linked_role(false) // Not a service-linked role
        .build()
        .unwrap();

    let restrictive_scp = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let full_access_identity = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![NamedPolicy::new("RestrictiveSCP", restrictive_scp)],
            ou_scps: vec![],
            account_scps: vec![],
        }),
        identity_policies: vec![NamedPolicy::new("FullAccess", full_access_identity)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Regular role should be blocked by SCP
    assert_eq!(result.decision, Decision::ImplicitDeny);
}

// =============================================================================
// AWS Behavior Accuracy Tests - Anonymous Access Edge Cases
// =============================================================================

#[test]
fn test_anonymous_request_bypasses_scp() {
    // Anonymous requests should not be evaluated against SCPs
    // (SCPs only apply to principals in the organization)
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::public-bucket/file.txt")
        // No principal - anonymous request
        .build()
        .unwrap();

    // SCP that would deny if it applied
    let deny_all_scp = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let public_bucket_policy = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![NamedPolicy::new("DenyAllSCP", deny_all_scp)],
            ou_scps: vec![],
            account_scps: vec![],
        }),
        resource_policies: vec![NamedPolicy::new("PublicBucket", public_bucket_policy)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Anonymous request should be allowed because SCPs don't apply to anonymous
    // and the resource policy allows it
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_anonymous_request_bypasses_permission_boundary() {
    // Anonymous requests should not be evaluated against permission boundaries
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::public-bucket/file.txt")
        // No principal - anonymous request
        .build()
        .unwrap();

    // Permission boundary that would block if it applied
    let restrictive_boundary = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "ec2:*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let public_bucket_policy = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::public-bucket/*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        permission_boundaries: vec![NamedPolicy::new(
            "RestrictiveBoundary",
            restrictive_boundary,
        )],
        resource_policies: vec![NamedPolicy::new("PublicBucket", public_bucket_policy)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Anonymous request should be allowed because permission boundaries don't apply
    assert_eq!(result.decision, Decision::Allow);
}

#[test]
fn test_anonymous_explicit_deny_in_resource_policy() {
    // Anonymous requests CAN be explicitly denied by resource policies
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::protected-bucket/file.txt")
        // No principal - anonymous request
        .build()
        .unwrap();

    let deny_anonymous_policy = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Sid": "DenyAnonymous",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::protected-bucket/*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        resource_policies: vec![NamedPolicy::new("DenyAnonymous", deny_anonymous_policy)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(result.decision, Decision::ExplicitDeny);
}

// =============================================================================
// AWS Behavior Accuracy Tests - Evaluation Order
// =============================================================================

#[test]
fn test_explicit_deny_short_circuits_before_scp() {
    // Explicit deny in identity policy should stop evaluation before SCP check
    // This validates the evaluation order
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::bucket/key")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .build()
        .unwrap();

    let deny_policy = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Sid": "DenyAll",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let full_access_scp = serde_json::from_str::<Policy>(
        r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }"#,
    )
    .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![NamedPolicy::new("FullAccess", full_access_scp)],
            ou_scps: vec![],
            account_scps: vec![],
        }),
        identity_policies: vec![NamedPolicy::new("DenyPolicy", deny_policy)],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    // Should be ExplicitDeny from identity policy, not Allow from SCP
    assert_eq!(result.decision, Decision::ExplicitDeny);
}
