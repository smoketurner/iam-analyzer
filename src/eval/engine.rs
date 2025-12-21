//! Main evaluation engine.
//!
//! Implements the complete AWS IAM policy evaluation flow.

use super::context::RequestContext;
use super::decision::{EvaluationResult, PolicyType, ReasoningStep};
use super::hierarchy::{
    check_allows, check_explicit_deny, evaluate_rcp_hierarchy, evaluate_scp_hierarchy,
};
use super::matchers::statement_matches;
use crate::error::Result;
use crate::policy::{Effect, Policy};

/// Result type for checking explicit denies across policy types.
type DenyCheckResult = Result<Option<(PolicyType, String, Option<String>, Vec<ReasoningStep>)>>;

/// A named policy with its source file name.
#[derive(Debug, Clone)]
pub struct NamedPolicy {
    /// The policy name or file path.
    pub name: String,
    /// The parsed policy.
    pub policy: Policy,
}

/// SCPs at an OU level.
#[derive(Debug, Clone)]
pub struct OuScpSet {
    /// The OU ID.
    pub ou_id: String,
    /// The OU name (optional).
    pub ou_name: Option<String>,
    /// Policies attached to this OU.
    pub policies: Vec<NamedPolicy>,
}

/// The SCP/RCP hierarchy for evaluation.
#[derive(Debug, Clone, Default)]
pub struct OrganizationHierarchy {
    /// SCPs at organization root level.
    pub root_scps: Vec<NamedPolicy>,
    /// SCPs at each OU level in the path (ordered from root to account).
    pub ou_scps: Vec<OuScpSet>,
    /// SCPs directly attached to the account.
    pub account_scps: Vec<NamedPolicy>,
}

/// The complete set of policies to evaluate.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    /// SCP hierarchy (optional).
    pub scp_hierarchy: Option<OrganizationHierarchy>,
    /// RCP hierarchy (optional).
    pub rcp_hierarchy: Option<OrganizationHierarchy>,
    /// VPC endpoint policies.
    pub vpc_endpoint_policies: Vec<NamedPolicy>,
    /// Identity-based policies.
    pub identity_policies: Vec<NamedPolicy>,
    /// Resource-based policies.
    pub resource_policies: Vec<NamedPolicy>,
    /// Permission boundaries.
    pub permission_boundaries: Vec<NamedPolicy>,
    /// Session policies.
    pub session_policies: Vec<NamedPolicy>,
}

/// The IAM policy evaluation engine.
///
/// Implements the exact AWS IAM policy evaluation logic.
#[derive(Debug, Default)]
pub struct EvaluationEngine;

impl EvaluationEngine {
    /// Create a new evaluation engine.
    pub fn new() -> Self {
        Self
    }

    /// Evaluate a request against a set of policies.
    ///
    /// Follows the AWS IAM evaluation flow:
    /// 1. Check for explicit deny in ALL policies
    /// 2. Check SCP hierarchy (every level must allow)
    /// 3. Check RCP hierarchy (every level must allow)
    /// 4. Check VPC endpoint policy
    /// 5. Check permission boundaries
    /// 6. Check session policies
    /// 7. Check identity + resource policies (union same-account, intersection cross-account)
    pub fn evaluate(&self, context: &RequestContext, policies: &PolicySet) -> EvaluationResult {
        match self.evaluate_impl(context, policies) {
            Ok(result) => result,
            Err(e) => {
                // Return an error result
                let step = ReasoningStep {
                    policy_type: PolicyType::IdentityBased,
                    policy_name: String::new(),
                    statement_sid: None,
                    matched: false,
                    effect: None,
                    details: format!("Evaluation error: {}", e),
                    breakdown: None,
                };
                EvaluationResult::implicit_deny(PolicyType::IdentityBased, vec![step])
            }
        }
    }

    fn evaluate_impl(
        &self,
        context: &RequestContext,
        policies: &PolicySet,
    ) -> Result<EvaluationResult> {
        let mut all_reasoning = Vec::new();

        // Check if this is an anonymous request (no principal)
        // Anonymous requests bypass SCPs, permission boundaries, and session policies
        // but NOT RCPs or VPC endpoint policies (which protect resources/network)
        let is_anonymous = context.principal_arn.is_none() && context.principal_account.is_none();

        // Step 1: Check for EXPLICIT DENY across ALL policies
        // Explicit deny in any policy type immediately denies the request
        // For anonymous requests, only check resource policies for explicit deny
        let deny_result = self.check_all_explicit_denies(context, policies, is_anonymous)?;
        if let Some((policy_type, policy_name, statement_sid, reasoning)) = deny_result {
            all_reasoning.extend(reasoning);
            return Ok(EvaluationResult::explicit_deny(
                policy_type,
                Some(format!(
                    "{} - {}",
                    policy_name,
                    statement_sid.unwrap_or_else(|| "unnamed".to_string())
                )),
                all_reasoning,
            ));
        }

        // Step 2: Check SCP hierarchy (if present)
        // Anonymous requests bypass SCPs (no principal in organization)
        if let Some(scp_hierarchy) = &policies.scp_hierarchy {
            // Anonymous requests, management account principals, and service-linked roles bypass SCPs
            if is_anonymous {
                let step = ReasoningStep {
                    policy_type: PolicyType::Scp,
                    policy_name: String::new(),
                    statement_sid: None,
                    matched: false,
                    effect: None,
                    details: "Anonymous request - SCPs bypassed".to_string(),
                    breakdown: None,
                };
                all_reasoning.push(step);
            } else if context.is_management_account {
                let step = ReasoningStep {
                    policy_type: PolicyType::Scp,
                    policy_name: String::new(),
                    statement_sid: None,
                    matched: false,
                    effect: None,
                    details: "Management account - SCPs bypassed".to_string(),
                    breakdown: None,
                };
                all_reasoning.push(step);
            } else if context.is_service_linked_role {
                let step = ReasoningStep {
                    policy_type: PolicyType::Scp,
                    policy_name: String::new(),
                    statement_sid: None,
                    matched: false,
                    effect: None,
                    details: "Service-linked role - SCPs bypassed".to_string(),
                    breakdown: None,
                };
                all_reasoning.push(step);
            } else {
                let result = evaluate_scp_hierarchy(scp_hierarchy, context)?;
                all_reasoning.extend(result.reasoning);

                if result.explicit_deny {
                    return Ok(EvaluationResult::explicit_deny(
                        PolicyType::Scp,
                        result.blocking_level,
                        all_reasoning,
                    ));
                }

                if !result.allowed {
                    return Ok(EvaluationResult::implicit_deny(
                        PolicyType::Scp,
                        all_reasoning,
                    ));
                }
            }
        }

        // Step 3: Check RCP hierarchy (if present)
        if let Some(rcp_hierarchy) = &policies.rcp_hierarchy {
            let result = evaluate_rcp_hierarchy(rcp_hierarchy, context)?;
            all_reasoning.extend(result.reasoning);

            if result.explicit_deny {
                return Ok(EvaluationResult::explicit_deny(
                    PolicyType::Rcp,
                    result.blocking_level,
                    all_reasoning,
                ));
            }

            if !result.allowed {
                return Ok(EvaluationResult::implicit_deny(
                    PolicyType::Rcp,
                    all_reasoning,
                ));
            }
        }

        // Step 4: Check VPC endpoint policies (if present)
        if !policies.vpc_endpoint_policies.is_empty() {
            let (has_allow, reasoning) = check_allows(
                &policies.vpc_endpoint_policies,
                context,
                PolicyType::VpcEndpoint,
            )?;
            all_reasoning.extend(reasoning);

            if !has_allow {
                return Ok(EvaluationResult::implicit_deny(
                    PolicyType::VpcEndpoint,
                    all_reasoning,
                ));
            }
        }

        // Step 5: Check permission boundaries (if present)
        // Anonymous requests bypass permission boundaries (no principal to attach boundary to)
        if !policies.permission_boundaries.is_empty() && !is_anonymous {
            let (has_allow, reasoning) = check_allows(
                &policies.permission_boundaries,
                context,
                PolicyType::PermissionBoundary,
            )?;
            all_reasoning.extend(reasoning);

            if !has_allow {
                return Ok(EvaluationResult::implicit_deny(
                    PolicyType::PermissionBoundary,
                    all_reasoning,
                ));
            }
        }

        // Step 6: Check session policies (if present)
        // Anonymous requests bypass session policies (no session)
        if !policies.session_policies.is_empty() && !is_anonymous {
            let (has_allow, reasoning) = check_allows(
                &policies.session_policies,
                context,
                PolicyType::SessionPolicy,
            )?;
            all_reasoning.extend(reasoning);

            if !has_allow {
                return Ok(EvaluationResult::implicit_deny(
                    PolicyType::SessionPolicy,
                    all_reasoning,
                ));
            }
        }

        // Step 7: Check identity + resource policies
        // Same-account: UNION (either can allow)
        // Cross-account: INTERSECTION (both must allow)
        let identity_allow = self.check_identity_allows(context, policies, &mut all_reasoning)?;
        let resource_allow = self.check_resource_allows(context, policies, &mut all_reasoning)?;

        if context.is_cross_account {
            // Special case: sts:AssumeRole* actions - trust policy alone grants access
            // AWS allows cross-account role assumption with only the trust policy
            let is_role_assumption = context.action.to_lowercase().starts_with("sts:assumerole");

            if is_role_assumption {
                // Trust policy alone can grant cross-account role access
                if resource_allow {
                    Ok(EvaluationResult::allow(all_reasoning))
                } else {
                    Ok(EvaluationResult::implicit_deny(
                        PolicyType::ResourceBased,
                        all_reasoning,
                    ))
                }
            } else {
                // Standard cross-account: both must allow
                if identity_allow && resource_allow {
                    Ok(EvaluationResult::allow(all_reasoning))
                } else if !identity_allow {
                    Ok(EvaluationResult::implicit_deny(
                        PolicyType::IdentityBased,
                        all_reasoning,
                    ))
                } else {
                    Ok(EvaluationResult::implicit_deny(
                        PolicyType::ResourceBased,
                        all_reasoning,
                    ))
                }
            }
        } else {
            // Same-account: either can allow
            // Special case: anonymous requests (no principal) with Principal: "*"
            let is_anonymous =
                context.principal_arn.is_none() && context.principal_account.is_none();

            if is_anonymous {
                // Only resource-based policy can grant access to anonymous requests
                if resource_allow {
                    Ok(EvaluationResult::allow(all_reasoning))
                } else {
                    Ok(EvaluationResult::implicit_deny(
                        PolicyType::ResourceBased,
                        all_reasoning,
                    ))
                }
            } else if identity_allow || resource_allow {
                Ok(EvaluationResult::allow(all_reasoning))
            } else {
                // Neither allows - implicit deny
                Ok(EvaluationResult::implicit_deny(
                    PolicyType::IdentityBased,
                    all_reasoning,
                ))
            }
        }
    }

    /// Check for explicit deny across all policy types.
    /// For anonymous requests, only checks resource policies (and RCPs/VPC endpoint).
    fn check_all_explicit_denies(
        &self,
        context: &RequestContext,
        policies: &PolicySet,
        is_anonymous: bool,
    ) -> DenyCheckResult {
        // Check SCP hierarchy for denies (skip for anonymous - no principal in org)
        if !is_anonymous && let Some(hierarchy) = &policies.scp_hierarchy {
            let all_scps: Vec<_> = hierarchy
                .root_scps
                .iter()
                .chain(hierarchy.ou_scps.iter().flat_map(|ou| &ou.policies))
                .chain(&hierarchy.account_scps)
                .cloned()
                .collect();

            if let Some((policy, sid, reasoning)) =
                check_explicit_deny(&all_scps, context, PolicyType::Scp)?
            {
                return Ok(Some((PolicyType::Scp, policy, sid, reasoning)));
            }
        }

        // Check RCP hierarchy for denies (RCPs still apply to anonymous - they protect resources)
        if let Some(hierarchy) = &policies.rcp_hierarchy {
            let all_rcps: Vec<_> = hierarchy
                .root_scps
                .iter()
                .chain(hierarchy.ou_scps.iter().flat_map(|ou| &ou.policies))
                .chain(&hierarchy.account_scps)
                .cloned()
                .collect();

            if let Some((policy, sid, reasoning)) =
                check_explicit_deny(&all_rcps, context, PolicyType::Rcp)?
            {
                return Ok(Some((PolicyType::Rcp, policy, sid, reasoning)));
            }
        }

        // Check VPC endpoint policies (still apply to anonymous - network level)
        if let Some((policy, sid, reasoning)) = check_explicit_deny(
            &policies.vpc_endpoint_policies,
            context,
            PolicyType::VpcEndpoint,
        )? {
            return Ok(Some((PolicyType::VpcEndpoint, policy, sid, reasoning)));
        }

        // Check identity policies (skip for anonymous - no identity)
        if !is_anonymous
            && let Some((policy, sid, reasoning)) = check_explicit_deny(
                &policies.identity_policies,
                context,
                PolicyType::IdentityBased,
            )?
        {
            return Ok(Some((PolicyType::IdentityBased, policy, sid, reasoning)));
        }

        // Check resource policies (applies to anonymous)
        if let Some((policy, sid, reasoning)) = check_explicit_deny(
            &policies.resource_policies,
            context,
            PolicyType::ResourceBased,
        )? {
            return Ok(Some((PolicyType::ResourceBased, policy, sid, reasoning)));
        }

        // Check permission boundaries (skip for anonymous - no principal)
        if !is_anonymous
            && let Some((policy, sid, reasoning)) = check_explicit_deny(
                &policies.permission_boundaries,
                context,
                PolicyType::PermissionBoundary,
            )?
        {
            return Ok(Some((
                PolicyType::PermissionBoundary,
                policy,
                sid,
                reasoning,
            )));
        }

        // Check session policies (skip for anonymous - no session)
        if !is_anonymous
            && let Some((policy, sid, reasoning)) = check_explicit_deny(
                &policies.session_policies,
                context,
                PolicyType::SessionPolicy,
            )?
        {
            return Ok(Some((PolicyType::SessionPolicy, policy, sid, reasoning)));
        }

        Ok(None)
    }

    /// Check if identity-based policies allow the request.
    fn check_identity_allows(
        &self,
        context: &RequestContext,
        policies: &PolicySet,
        reasoning: &mut Vec<ReasoningStep>,
    ) -> Result<bool> {
        for named_policy in &policies.identity_policies {
            for statement in &named_policy.policy.statement {
                if statement.effect != Effect::Allow {
                    continue;
                }

                let match_result = statement_matches(statement, context)?;

                let step = ReasoningStep {
                    policy_type: PolicyType::IdentityBased,
                    policy_name: named_policy.name.clone(),
                    statement_sid: statement.sid.clone(),
                    matched: match_result.matches,
                    effect: Some(Effect::Allow),
                    details: match_result.details.clone(),
                    breakdown: Some(match_result.breakdown.clone()),
                };
                reasoning.push(step);

                if match_result.matches {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check if resource-based policies allow the request.
    fn check_resource_allows(
        &self,
        context: &RequestContext,
        policies: &PolicySet,
        reasoning: &mut Vec<ReasoningStep>,
    ) -> Result<bool> {
        for named_policy in &policies.resource_policies {
            for statement in &named_policy.policy.statement {
                if statement.effect != Effect::Allow {
                    continue;
                }

                let match_result = statement_matches(statement, context)?;

                let step = ReasoningStep {
                    policy_type: PolicyType::ResourceBased,
                    policy_name: named_policy.name.clone(),
                    statement_sid: statement.sid.clone(),
                    matched: match_result.matches,
                    effect: Some(Effect::Allow),
                    details: match_result.details.clone(),
                    breakdown: Some(match_result.breakdown.clone()),
                };
                reasoning.push(step);

                if match_result.matches {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

impl NamedPolicy {
    /// Create a new named policy.
    pub fn new(name: impl Into<String>, policy: Policy) -> Self {
        Self {
            name: name.into(),
            policy,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::Decision;

    fn parse_policy(name: &str, json: &str) -> NamedPolicy {
        let policy: Policy = serde_json::from_str(json).unwrap();
        NamedPolicy::new(name, policy)
    }

    fn make_context(action: &str, resource: &str) -> RequestContext {
        RequestContext::builder()
            .action(action)
            .resource(resource)
            // Add default principal to avoid being treated as anonymous
            .principal_arn("arn:aws:iam::123456789012:user/testuser")
            .principal_account("123456789012")
            .build()
            .unwrap()
    }

    fn full_access_policy() -> NamedPolicy {
        parse_policy(
            "FullAccess",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }]
            }"#,
        )
    }

    fn allow_s3_policy() -> NamedPolicy {
        parse_policy(
            "AllowS3",
            r#"{
                "Statement": [{
                    "Sid": "AllowS3",
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        )
    }

    fn deny_s3_delete_policy() -> NamedPolicy {
        parse_policy(
            "DenyS3Delete",
            r#"{
                "Statement": [{
                    "Sid": "DenyS3Delete",
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }]
            }"#,
        )
    }

    #[test]
    fn test_engine_creation() {
        let engine = EvaluationEngine::new();
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let policies = PolicySet::default();

        let result = engine.evaluate(&ctx, &policies);
        // With no policies, should be implicit deny
        assert_eq!(result.decision, Decision::ImplicitDeny);
    }

    #[test]
    fn test_identity_policy_allows() {
        let engine = EvaluationEngine::new();
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let policies = PolicySet {
            identity_policies: vec![allow_s3_policy()],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_identity_policy_no_match() {
        let engine = EvaluationEngine::new();
        let ctx = make_context(
            "ec2:RunInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/*",
        );
        let policies = PolicySet {
            identity_policies: vec![allow_s3_policy()], // Only allows S3
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        assert_eq!(result.decision, Decision::ImplicitDeny);
    }

    #[test]
    fn test_explicit_deny_overrides_allow() {
        let engine = EvaluationEngine::new();
        let ctx = make_context("s3:DeleteObject", "arn:aws:s3:::bucket/key");
        let policies = PolicySet {
            identity_policies: vec![full_access_policy(), deny_s3_delete_policy()],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        assert_eq!(result.decision, Decision::ExplicitDeny);
    }

    #[test]
    fn test_resource_policy_allows_same_account() {
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::123456789012:user/alice")
            .principal_account("123456789012")
            .resource_account("123456789012") // Same account
            .build()
            .unwrap();

        let bucket_policy = parse_policy(
            "BucketPolicy",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }]
            }"#,
        );

        let policies = PolicySet {
            resource_policies: vec![bucket_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Same-account: resource policy alone can allow
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cross_account_requires_both() {
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::111111111111:user/alice")
            .principal_account("111111111111")
            .resource_account("222222222222") // Different account
            .cross_account(true)
            .build()
            .unwrap();

        let bucket_policy = parse_policy(
            "BucketPolicy",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }]
            }"#,
        );

        // Only resource policy, no identity policy
        let policies = PolicySet {
            resource_policies: vec![bucket_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Cross-account: both must allow, but identity doesn't allow
        assert_eq!(result.decision, Decision::ImplicitDeny);
    }

    #[test]
    fn test_cross_account_both_allow() {
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::111111111111:user/alice")
            .principal_account("111111111111")
            .resource_account("222222222222")
            .cross_account(true)
            .build()
            .unwrap();

        let bucket_policy = parse_policy(
            "BucketPolicy",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }]
            }"#,
        );

        let policies = PolicySet {
            identity_policies: vec![allow_s3_policy()],
            resource_policies: vec![bucket_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Cross-account: both allow
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_scp_blocks() {
        let engine = EvaluationEngine::new();
        let ctx = make_context(
            "dynamodb:GetItem",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Users",
        );

        let scp = parse_policy(
            "AllowS3Only",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let policies = PolicySet {
            scp_hierarchy: Some(OrganizationHierarchy {
                root_scps: vec![scp],
                ou_scps: vec![],
                account_scps: vec![],
            }),
            identity_policies: vec![full_access_policy()],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // SCP doesn't allow dynamodb, even though identity allows all
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::Scp));
    }

    #[test]
    fn test_permission_boundary_blocks() {
        let engine = EvaluationEngine::new();
        let ctx = make_context("iam:CreateUser", "arn:aws:iam::123456789012:user/newuser");

        let boundary = parse_policy(
            "S3OnlyBoundary",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let policies = PolicySet {
            identity_policies: vec![full_access_policy()],
            permission_boundaries: vec![boundary],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Permission boundary doesn't allow IAM
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(
            result.deciding_policy_type,
            Some(PolicyType::PermissionBoundary)
        );
    }

    #[test]
    fn test_session_policy_blocks() {
        let engine = EvaluationEngine::new();
        let ctx = make_context(
            "ec2:RunInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/*",
        );

        let session = parse_policy(
            "S3OnlySession",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let policies = PolicySet {
            identity_policies: vec![full_access_policy()],
            session_policies: vec![session],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Session policy doesn't allow EC2
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::SessionPolicy));
    }

    #[test]
    fn test_vpc_endpoint_policy_blocks() {
        let engine = EvaluationEngine::new();
        let ctx = make_context(
            "dynamodb:GetItem",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Users",
        );

        let vpc_policy = parse_policy(
            "S3OnlyEndpoint",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let policies = PolicySet {
            identity_policies: vec![full_access_policy()],
            vpc_endpoint_policies: vec![vpc_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // VPC endpoint policy doesn't allow DynamoDB
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::VpcEndpoint));
    }

    #[test]
    fn test_all_policies_allow() {
        let engine = EvaluationEngine::new();
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");

        let full_access = full_access_policy();

        let policies = PolicySet {
            scp_hierarchy: Some(OrganizationHierarchy {
                root_scps: vec![full_access.clone()],
                ou_scps: vec![],
                account_scps: vec![],
            }),
            identity_policies: vec![full_access.clone()],
            permission_boundaries: vec![full_access.clone()],
            session_policies: vec![full_access],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_named_policy() {
        let json = r#"{
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }"#;
        let policy: Policy = serde_json::from_str(json).unwrap();
        let named = NamedPolicy::new("test-policy.json", policy);
        assert_eq!(named.name, "test-policy.json");
    }

    #[test]
    fn test_output_format() {
        let engine = EvaluationEngine::new();
        let ctx = make_context("s3:DeleteObject", "arn:aws:s3:::bucket/key");
        let policies = PolicySet {
            identity_policies: vec![full_access_policy(), deny_s3_delete_policy()],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        let output = result.to_string();

        assert!(output.contains("EXPLICIT_DENY"));
        assert!(output.contains("DenyS3Delete"));
    }

    #[test]
    fn test_cross_account_assume_role_trust_policy_only() {
        // sts:AssumeRole should succeed with only trust policy (no identity policy)
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("sts:AssumeRole")
            .resource("arn:aws:iam::222222222222:role/CrossAccountRole")
            .principal_arn("arn:aws:iam::111111111111:user/alice")
            .principal_account("111111111111")
            .resource_account("222222222222")
            .cross_account(true)
            .build()
            .unwrap();

        let trust_policy = parse_policy(
            "TrustPolicy",
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
        );

        // Only resource policy (trust policy), no identity policy
        let policies = PolicySet {
            resource_policies: vec![trust_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Cross-account role assumption should succeed with only trust policy
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cross_account_assume_role_with_web_identity() {
        // sts:AssumeRoleWithWebIdentity should also work with only trust policy
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("sts:AssumeRoleWithWebIdentity")
            .resource("arn:aws:iam::222222222222:role/WebIdentityRole")
            .principal_account("111111111111")
            .resource_account("222222222222")
            .cross_account(true)
            .build()
            .unwrap();

        let trust_policy = parse_policy(
            "TrustPolicy",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Resource": "*"
                }]
            }"#,
        );

        let policies = PolicySet {
            resource_policies: vec![trust_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_cross_account_s3_still_requires_both() {
        // s3:GetObject cross-account should still require both policies
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::111111111111:user/alice")
            .principal_account("111111111111")
            .resource_account("222222222222")
            .cross_account(true)
            .build()
            .unwrap();

        let bucket_policy = parse_policy(
            "BucketPolicy",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*"
                }]
            }"#,
        );

        // Only bucket policy, no identity policy - should fail for S3
        let policies = PolicySet {
            resource_policies: vec![bucket_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // S3 cross-account requires both policies
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::IdentityBased));
    }

    #[test]
    fn test_management_account_bypasses_scps() {
        // Management account principals bypass SCPs
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("dynamodb:GetItem")
            .resource("arn:aws:dynamodb:us-east-1:123456789012:table/Users")
            .principal_arn("arn:aws:iam::123456789012:user/admin")
            .principal_account("123456789012")
            .management_account(true)
            .build()
            .unwrap();

        let scp = parse_policy(
            "AllowS3Only",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let policies = PolicySet {
            scp_hierarchy: Some(OrganizationHierarchy {
                root_scps: vec![scp],
                ou_scps: vec![],
                account_scps: vec![],
            }),
            identity_policies: vec![full_access_policy()],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Management account bypasses SCPs, so this should be allowed
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_non_management_account_blocked_by_scp() {
        // Non-management account principals are affected by SCPs
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("dynamodb:GetItem")
            .resource("arn:aws:dynamodb:us-east-1:123456789012:table/Users")
            .principal_arn("arn:aws:iam::123456789012:user/developer")
            .principal_account("123456789012")
            .management_account(false)
            .build()
            .unwrap();

        let scp = parse_policy(
            "AllowS3Only",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let policies = PolicySet {
            scp_hierarchy: Some(OrganizationHierarchy {
                root_scps: vec![scp],
                ou_scps: vec![],
                account_scps: vec![],
            }),
            identity_policies: vec![full_access_policy()],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // SCP doesn't allow dynamodb, so this should be denied
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::Scp));
    }

    #[test]
    fn test_anonymous_request_allowed_by_resource_policy() {
        // Anonymous requests (no principal) can be allowed by resource-based policy
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::public-bucket/file.txt")
            // No principal_arn or principal_account set
            .build()
            .unwrap();

        let bucket_policy = parse_policy(
            "PublicBucketPolicy",
            r#"{
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-bucket/*"
                }]
            }"#,
        );

        let policies = PolicySet {
            resource_policies: vec![bucket_policy],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Anonymous request should be allowed by resource policy with Principal: "*"
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_anonymous_request_denied_without_resource_policy() {
        // Anonymous requests without matching resource policy should be denied
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::private-bucket/file.txt")
            // No principal_arn or principal_account set
            .build()
            .unwrap();

        // No policies at all
        let policies = PolicySet::default();

        let result = engine.evaluate(&ctx, &policies);
        // Anonymous request should be denied (resource policy type for anonymous)
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::ResourceBased));
    }

    #[test]
    fn test_anonymous_request_identity_policy_ignored() {
        // Anonymous requests should not use identity policies
        let engine = EvaluationEngine::new();
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/file.txt")
            // No principal_arn or principal_account set
            .build()
            .unwrap();

        // Only identity policy, no resource policy
        let policies = PolicySet {
            identity_policies: vec![full_access_policy()],
            ..Default::default()
        };

        let result = engine.evaluate(&ctx, &policies);
        // Identity policy should not grant access to anonymous requests
        assert_eq!(result.decision, Decision::ImplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::ResourceBased));
    }
}
