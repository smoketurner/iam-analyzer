//! Integration tests using AWS sample policies.
//!
//! These tests validate IAM evaluation against real-world policy patterns
//! from official AWS sample repositories (data-perimeter-policy-examples,
//! service-control-policy-examples, resource-control-policy-examples).

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
    let name = std::path::Path::new(path)
        .file_name()
        .unwrap()
        .to_str()
        .unwrap();
    NamedPolicy::new(name, policy)
}

/// Create a full AWS access SCP for allowing all actions.
fn full_aws_access() -> NamedPolicy {
    let policy: Policy = serde_json::from_str(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }"#,
    )
    .unwrap();
    NamedPolicy::new("FullAWSAccess", policy)
}

/// Create a simple identity policy allowing all actions.
fn allow_all_identity() -> NamedPolicy {
    let policy: Policy = serde_json::from_str(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }"#,
    )
    .unwrap();
    NamedPolicy::new("AllowAll", policy)
}

// =============================================================================
// Null Operator Tests
// =============================================================================

#[test]
fn test_null_operator_s3_encryption_missing_denied() {
    // When s3:x-amz-server-side-encryption is not set (null), deny
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:PutObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        // Note: NOT setting s3:x-amz-server-side-encryption
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/require-s3-encryption.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny when encryption header is missing"
    );
}

#[test]
fn test_null_operator_s3_encryption_present_allowed() {
    // When s3:x-amz-server-side-encryption is set, allow
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:PutObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("s3:x-amz-server-side-encryption", "AES256")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/require-s3-encryption.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow when encryption header is present"
    );
}

#[test]
fn test_null_operator_oidc_claim_present() {
    // GitHub OIDC RCP: denies if token.actions.githubusercontent.com:sub is present but doesn't match
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("sts:AssumeRoleWithWebIdentity")
        .resource("arn:aws:iam::123456789012:role/GitHubActionsRole")
        .principal_arn("arn:aws:sts::123456789012:assumed-role/GitHubActionsRole/session")
        .principal_account("123456789012")
        .context_key(
            "token.actions.githubusercontent.com:sub",
            "repo:untrusted-org/repo:ref:refs/heads/main",
        )
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/restrict-github-oidc.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny OIDC from untrusted org"
    );
}

#[test]
fn test_null_operator_oidc_claim_trusted_org() {
    // GitHub OIDC RCP: allows if token matches trusted org pattern
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("sts:AssumeRoleWithWebIdentity")
        .resource("arn:aws:iam::123456789012:role/GitHubActionsRole")
        .principal_arn("arn:aws:sts::123456789012:assumed-role/GitHubActionsRole/session")
        .principal_account("123456789012")
        .context_key(
            "token.actions.githubusercontent.com:sub",
            "repo:trusted-org/myrepo:ref:refs/heads/main",
        )
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/restrict-github-oidc.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow OIDC from trusted org"
    );
}

// =============================================================================
// NumericLessThan/NumericGreaterThan Operator Tests
// =============================================================================

#[test]
fn test_numeric_less_than_kms_deletion_window_too_short() {
    // Deny KMS key deletion with less than 30 days window
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("kms:ScheduleKeyDeletion")
        .resource("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("kms:ScheduleKeyDeletionPendingWindowInDays", "7")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/enforce-kms-deletion-window.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny KMS deletion with < 30 day window"
    );
}

#[test]
fn test_numeric_less_than_kms_deletion_window_sufficient() {
    // Allow KMS key deletion with 30+ days window
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("kms:ScheduleKeyDeletion")
        .resource("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("kms:ScheduleKeyDeletionPendingWindowInDays", "30")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/enforce-kms-deletion-window.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow KMS deletion with >= 30 day window"
    );
}

#[test]
fn test_numeric_less_than_s3_tls_version_too_low() {
    // RCP denies S3 access with TLS version < 1.2
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("s3:TlsVersion", "1.1")
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/enforce-s3-tls-version.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny S3 access with TLS < 1.2"
    );
}

#[test]
fn test_numeric_greater_than_presigned_url_too_old() {
    // RCP denies S3 access when signature age exceeds limit (1 hour = 3600000ms)
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("s3:signatureAge", "7200000") // 2 hours
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/enforce-s3-presigned-expiry.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny presigned URL older than 1 hour"
    );
}

// =============================================================================
// BoolIfExists Operator Tests
// =============================================================================

#[test]
fn test_bool_if_exists_secure_transport_false_denied() {
    // RCP denies non-HTTPS requests
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .secure_transport(false)
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/enforce-https-only.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny non-HTTPS request"
    );
}

#[test]
fn test_bool_if_exists_secure_transport_true_allowed() {
    // RCP allows HTTPS requests
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .secure_transport(true)
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/enforce-https-only.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow HTTPS request"
    );
}

#[test]
fn test_bool_if_exists_mfa_required_denied() {
    // SCP denies IAM actions without MFA
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("iam:CreateUser")
        .resource("arn:aws:iam::123456789012:user/newuser")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .mfa_present(false)
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/require-mfa-for-iam.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny IAM action without MFA"
    );
}

#[test]
fn test_bool_if_exists_mfa_present_allowed() {
    // SCP allows IAM actions with MFA
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("iam:CreateUser")
        .resource("arn:aws:iam::123456789012:user/newuser")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .mfa_present(true)
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/require-mfa-for-iam.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow IAM action with MFA"
    );
}

// =============================================================================
// Region Restriction Tests (StringNotEquals with NotAction)
// =============================================================================

#[test]
fn test_region_restriction_denied_outside_allowed() {
    // SCP denies EC2 actions in non-US regions
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
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/deny-region-outside-allowed.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny EC2 in eu-west-1"
    );
}

#[test]
fn test_region_restriction_allowed_in_us() {
    // SCP allows EC2 actions in US regions
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
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/deny-region-outside-allowed.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow EC2 in us-east-1"
    );
}

#[test]
fn test_region_restriction_iam_exempt_via_notaction() {
    // SCP exempts IAM actions from region restrictions via NotAction
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("iam:CreateRole")
        .resource("arn:aws:iam::123456789012:role/myrole")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .requested_region("eu-west-1")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/deny-region-outside-allowed.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "IAM actions should be exempt from region restrictions"
    );
}

// =============================================================================
// Service-Specific Condition Key Tests
// =============================================================================

#[test]
fn test_ec2_imdsv2_required_denied() {
    // SCP denies RunInstances without IMDSv2 token requirement
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:us-east-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("ec2:MetadataHttpTokens", "optional")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/prevent-imdsv1.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny RunInstances without IMDSv2 required"
    );
}

#[test]
fn test_ec2_imdsv2_required_allowed() {
    // SCP allows RunInstances with IMDSv2 token requirement
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("ec2:RunInstances")
        .resource("arn:aws:ec2:us-east-1:123456789012:instance/*")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("ec2:MetadataHttpTokens", "required")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/prevent-imdsv1.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow RunInstances with IMDSv2 required"
    );
}

#[test]
fn test_kms_grant_for_aws_resource_denied() {
    // RCP denies KMS CreateGrant when not for AWS resource
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("kms:CreateGrant")
        .resource("arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .context_key("kms:GrantIsForAWSResource", "false")
        .principal_is_aws_service(false)
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/restrict-kms-grants.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny KMS grant not for AWS resource"
    );
}

// =============================================================================
// RCP Identity Perimeter Tests
// =============================================================================

#[test]
fn test_rcp_identity_perimeter_blocks_external_principal() {
    // RCP denies access from principals outside the org
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::999999999999:user/external")
        .principal_account("999999999999")
        .principal_org_id("o-externalorg")
        .principal_is_aws_service(false)
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/identity-perimeter.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny access from external org"
    );
}

#[test]
fn test_rcp_identity_perimeter_allows_org_principal() {
    // RCP allows access from principals within the org
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .principal_org_id("o-testorg123")
        .principal_is_aws_service(false)
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/identity-perimeter.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow access from org principal"
    );
}

#[test]
fn test_rcp_identity_perimeter_allows_aws_service() {
    // RCP allows access from AWS service principals
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn(
            "arn:aws:iam::123456789012:role/aws-service-role/s3.amazonaws.com/AWSServiceRoleForS3",
        )
        .principal_account("123456789012")
        .principal_is_aws_service(true)
        .build()
        .unwrap();

    let policies = PolicySet {
        rcp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/rcp/identity-perimeter.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow access from AWS service principal"
    );
}

// =============================================================================
// VPC Endpoint Policy Tests
// =============================================================================

#[test]
fn test_vpc_endpoint_allows_org_to_org() {
    // VPC endpoint policy allows org principal accessing org resource
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .principal_org_id("o-testorg123")
        .resource_org_id("o-testorg123")
        .build()
        .unwrap();

    let policies = PolicySet {
        vpc_endpoint_policies: vec![load_policy(
            "tests/fixtures/aws-samples/vpc-endpoint/default-endpoint-policy.json",
        )],
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow org principal to access org resource via VPC endpoint"
    );
}

#[test]
fn test_vpc_endpoint_allows_aws_service() {
    // VPC endpoint policy allows AWS service principals
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:role/aws-service-role")
        .principal_account("123456789012")
        .principal_is_aws_service(true)
        .build()
        .unwrap();

    let policies = PolicySet {
        vpc_endpoint_policies: vec![load_policy(
            "tests/fixtures/aws-samples/vpc-endpoint/default-endpoint-policy.json",
        )],
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow AWS service principal via VPC endpoint"
    );
}

#[test]
fn test_vpc_endpoint_denies_cross_org() {
    // VPC endpoint policy denies cross-org access without exclusion tag
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::external-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .principal_org_id("o-testorg123")
        .resource_org_id("o-externalorg")
        .principal_is_aws_service(false)
        .build()
        .unwrap();

    let policies = PolicySet {
        vpc_endpoint_policies: vec![load_policy(
            "tests/fixtures/aws-samples/vpc-endpoint/default-endpoint-policy.json",
        )],
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ImplicitDeny,
        "Should deny cross-org access via VPC endpoint"
    );
}

// =============================================================================
// ForAllValues/ForAnyValue Operator Tests
// =============================================================================

#[test]
fn test_for_all_values_called_via_allowed() {
    // Data perimeter SCP allows when CalledVia matches allowed services
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::dataexchange-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .resource_org_id("o-testorg123")
        .called_via("dataexchange.amazonaws.com")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/data-perimeter-resource.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow when CalledVia matches dataexchange"
    );
}

#[test]
fn test_for_any_value_tag_keys_protected() {
    // Data perimeter governance SCP denies tag modifications for non-admins
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("ec2:CreateTags")
        .resource("arn:aws:ec2:us-east-1:123456789012:instance/i-12345678")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .principal_tag("team", "engineering") // Not admin
        .context_key("aws:TagKeys", "dp:exclude:network")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/data-perimeter-governance.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny non-admin modifying dp:* tags"
    );
}

// =============================================================================
// Network Perimeter Tests
// =============================================================================

#[test]
fn test_network_perimeter_allows_corporate_ip() {
    // Network perimeter SCP allows from corporate CIDR
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .source_ip("10.1.2.3")
        .via_aws_service(false)
        .principal_tag("dp:include:network", "true")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/data-perimeter-network-vpceorgid.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow from corporate IP range"
    );
}

#[test]
fn test_network_perimeter_denies_external_ip() {
    // Network perimeter SCP denies from external IP
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .source_ip("203.0.113.50") // External IP
        .via_aws_service(false)
        .principal_tag("dp:include:network", "true")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/data-perimeter-network-vpceorgid.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::ExplicitDeny,
        "Should deny from external IP"
    );
}

#[test]
fn test_network_perimeter_allows_via_aws_service() {
    // Network perimeter SCP allows when via AWS service
    let engine = EvaluationEngine::new();
    let ctx = RequestContext::builder()
        .action("s3:GetObject")
        .resource("arn:aws:s3:::my-bucket/file.txt")
        .principal_arn("arn:aws:iam::123456789012:user/alice")
        .principal_account("123456789012")
        .source_ip("203.0.113.50") // External IP but via AWS service
        .via_aws_service(true)
        .principal_tag("dp:include:network", "true")
        .build()
        .unwrap();

    let policies = PolicySet {
        scp_hierarchy: Some(OrganizationHierarchy {
            root_scps: vec![full_aws_access()],
            account_scps: vec![
                full_aws_access(),
                load_policy("tests/fixtures/aws-samples/scp/data-perimeter-network-vpceorgid.json"),
            ],
            ..Default::default()
        }),
        identity_policies: vec![allow_all_identity()],
        ..Default::default()
    };

    let result = engine.evaluate(&ctx, &policies);
    assert_eq!(
        result.decision,
        Decision::Allow,
        "Should allow when via AWS service"
    );
}
