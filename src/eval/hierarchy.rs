//! SCP/RCP hierarchy evaluation.
//!
//! Implements the hierarchy evaluation logic where EVERY level must allow
//! for the request to proceed.
//!
//! Hierarchy structure:
//! ```text
//! Organization Root
//! ├── Root SCPs (must have at least one Allow)
//! │
//! ├── OU Level 1
//! │   ├── OU SCPs (must have at least one Allow)
//! │   │
//! │   └── OU Level 2
//! │       ├── OU SCPs (must have at least one Allow)
//! │       │
//! │       └── Account
//! │           └── Account SCPs (must have at least one Allow)
//! ```

use super::context::RequestContext;
use super::decision::{PolicyType, ReasoningStep};
#[cfg(test)]
use super::engine::OuPolicySet;
use super::engine::{NamedPolicy, OrganizationHierarchy};
use super::matchers::statement_matches;
use crate::error::Result;
use crate::policy::Effect;

/// Result type for checking explicit denies.
type DenyResult = Result<Option<(String, Option<String>, Vec<ReasoningStep>)>>;

/// Result of hierarchy evaluation.
#[derive(Debug)]
pub struct HierarchyResult {
    /// Whether the hierarchy allows the request.
    pub allowed: bool,
    /// Whether there was an explicit deny.
    pub explicit_deny: bool,
    /// The level that blocked or denied (if any).
    pub blocking_level: Option<String>,
    /// Reasoning steps for the evaluation.
    pub reasoning: Vec<ReasoningStep>,
}

impl HierarchyResult {
    fn allowed(reasoning: Vec<ReasoningStep>) -> Self {
        Self {
            allowed: true,
            explicit_deny: false,
            blocking_level: None,
            reasoning,
        }
    }

    fn implicit_deny(level: impl Into<String>, reasoning: Vec<ReasoningStep>) -> Self {
        Self {
            allowed: false,
            explicit_deny: false,
            blocking_level: Some(level.into()),
            reasoning,
        }
    }

    fn explicit_deny(level: impl Into<String>, reasoning: Vec<ReasoningStep>) -> Self {
        Self {
            allowed: false,
            explicit_deny: true,
            blocking_level: Some(level.into()),
            reasoning,
        }
    }
}

/// Evaluate SCP hierarchy.
///
/// Every level in the hierarchy must have at least one Allow statement
/// that matches the request. If any level lacks an Allow, the request
/// is implicitly denied.
pub fn evaluate_scp_hierarchy(
    hierarchy: &OrganizationHierarchy,
    context: &RequestContext,
) -> Result<HierarchyResult> {
    let mut reasoning = Vec::new();

    // 1. Check root SCPs
    if !hierarchy.root_policies.is_empty() {
        let (has_allow, has_deny, steps) =
            evaluate_policies_at_level(&hierarchy.root_policies, context, PolicyType::Scp, "Root")?;
        reasoning.extend(steps);

        if has_deny {
            return Ok(HierarchyResult::explicit_deny("Root SCPs", reasoning));
        }

        if !has_allow {
            return Ok(HierarchyResult::implicit_deny(
                "Root SCPs (no Allow found)",
                reasoning,
            ));
        }
    }

    // 2. Check each OU level in order (from root towards account)
    for ou in &hierarchy.ou_policies {
        if !ou.policies.is_empty() {
            let level_name = ou
                .ou_name
                .as_ref()
                .map(|n| format!("OU '{}'", n))
                .unwrap_or_else(|| format!("OU {}", ou.ou_id));

            let (has_allow, has_deny, steps) =
                evaluate_policies_at_level(&ou.policies, context, PolicyType::Scp, &level_name)?;
            reasoning.extend(steps);

            if has_deny {
                return Ok(HierarchyResult::explicit_deny(
                    format!("{} SCPs", level_name),
                    reasoning,
                ));
            }

            if !has_allow {
                return Ok(HierarchyResult::implicit_deny(
                    format!("{} SCPs (no Allow found)", level_name),
                    reasoning,
                ));
            }
        }
    }

    // 3. Check account SCPs
    if !hierarchy.account_policies.is_empty() {
        let (has_allow, has_deny, steps) = evaluate_policies_at_level(
            &hierarchy.account_policies,
            context,
            PolicyType::Scp,
            "Account",
        )?;
        reasoning.extend(steps);

        if has_deny {
            return Ok(HierarchyResult::explicit_deny("Account SCPs", reasoning));
        }

        if !has_allow {
            return Ok(HierarchyResult::implicit_deny(
                "Account SCPs (no Allow found)",
                reasoning,
            ));
        }
    }

    Ok(HierarchyResult::allowed(reasoning))
}

/// Evaluate RCP hierarchy (same logic as SCP).
pub fn evaluate_rcp_hierarchy(
    hierarchy: &OrganizationHierarchy,
    context: &RequestContext,
) -> Result<HierarchyResult> {
    let mut reasoning = Vec::new();

    // 1. Check root RCPs
    if !hierarchy.root_policies.is_empty() {
        let (has_allow, has_deny, steps) =
            evaluate_policies_at_level(&hierarchy.root_policies, context, PolicyType::Rcp, "Root")?;
        reasoning.extend(steps);

        if has_deny {
            return Ok(HierarchyResult::explicit_deny("Root RCPs", reasoning));
        }

        if !has_allow {
            return Ok(HierarchyResult::implicit_deny(
                "Root RCPs (no Allow found)",
                reasoning,
            ));
        }
    }

    // 2. Check each OU level
    for ou in &hierarchy.ou_policies {
        if !ou.policies.is_empty() {
            let level_name = ou
                .ou_name
                .as_ref()
                .map(|n| format!("OU '{}'", n))
                .unwrap_or_else(|| format!("OU {}", ou.ou_id));

            let (has_allow, has_deny, steps) =
                evaluate_policies_at_level(&ou.policies, context, PolicyType::Rcp, &level_name)?;
            reasoning.extend(steps);

            if has_deny {
                return Ok(HierarchyResult::explicit_deny(
                    format!("{} RCPs", level_name),
                    reasoning,
                ));
            }

            if !has_allow {
                return Ok(HierarchyResult::implicit_deny(
                    format!("{} RCPs (no Allow found)", level_name),
                    reasoning,
                ));
            }
        }
    }

    // 3. Check account RCPs
    if !hierarchy.account_policies.is_empty() {
        let (has_allow, has_deny, steps) = evaluate_policies_at_level(
            &hierarchy.account_policies,
            context,
            PolicyType::Rcp,
            "Account",
        )?;
        reasoning.extend(steps);

        if has_deny {
            return Ok(HierarchyResult::explicit_deny("Account RCPs", reasoning));
        }

        if !has_allow {
            return Ok(HierarchyResult::implicit_deny(
                "Account RCPs (no Allow found)",
                reasoning,
            ));
        }
    }

    Ok(HierarchyResult::allowed(reasoning))
}

/// Evaluate all policies at a single level.
///
/// Returns (has_allow, has_explicit_deny, reasoning_steps)
fn evaluate_policies_at_level(
    policies: &[NamedPolicy],
    context: &RequestContext,
    policy_type: PolicyType,
    level_name: &str,
) -> Result<(bool, bool, Vec<ReasoningStep>)> {
    let mut has_allow = false;
    let mut has_deny = false;
    let mut reasoning = Vec::new();

    for named_policy in policies {
        for statement in &named_policy.policy.statement {
            let match_result = statement_matches(statement, context)?;

            let step = ReasoningStep {
                policy_type,
                policy_name: named_policy.name.clone(),
                statement_sid: statement.sid.clone(),
                matched: match_result.matches,
                effect: if match_result.matches {
                    Some(statement.effect)
                } else {
                    None
                },
                details: format!("{} - {}", level_name, match_result.details),
                breakdown: Some(match_result.breakdown.clone()),
            };
            reasoning.push(step);

            if match_result.matches {
                match statement.effect {
                    Effect::Allow => has_allow = true,
                    Effect::Deny => has_deny = true,
                }
            }
        }
    }

    Ok((has_allow, has_deny, reasoning))
}

/// Check if any policy in a list has an explicit deny that matches.
pub fn check_explicit_deny(
    policies: &[NamedPolicy],
    context: &RequestContext,
    policy_type: PolicyType,
) -> DenyResult {
    let mut reasoning = Vec::new();

    for named_policy in policies {
        for statement in &named_policy.policy.statement {
            if statement.effect != Effect::Deny {
                continue;
            }

            let match_result = statement_matches(statement, context)?;

            let step = ReasoningStep {
                policy_type,
                policy_name: named_policy.name.clone(),
                statement_sid: statement.sid.clone(),
                matched: match_result.matches,
                effect: Some(Effect::Deny),
                details: match_result.details.clone(),
                breakdown: Some(match_result.breakdown.clone()),
            };
            reasoning.push(step);

            if match_result.matches {
                return Ok(Some((
                    named_policy.name.clone(),
                    statement.sid.clone(),
                    reasoning,
                )));
            }
        }
    }

    Ok(None)
}

/// Check if any policy in a list has an allow that matches.
pub fn check_allows(
    policies: &[NamedPolicy],
    context: &RequestContext,
    policy_type: PolicyType,
) -> Result<(bool, Vec<ReasoningStep>)> {
    let mut reasoning = Vec::new();

    for named_policy in policies {
        for statement in &named_policy.policy.statement {
            if statement.effect != Effect::Allow {
                continue;
            }

            let match_result = statement_matches(statement, context)?;

            let step = ReasoningStep {
                policy_type,
                policy_name: named_policy.name.clone(),
                statement_sid: statement.sid.clone(),
                matched: match_result.matches,
                effect: Some(Effect::Allow),
                details: match_result.details.clone(),
                breakdown: Some(match_result.breakdown.clone()),
            };
            reasoning.push(step);

            if match_result.matches {
                return Ok((true, reasoning));
            }
        }
    }

    Ok((false, reasoning))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;

    fn parse_policy(name: &str, json: &str) -> NamedPolicy {
        let policy: Policy = serde_json::from_str(json).unwrap();
        NamedPolicy::new(name, policy)
    }

    fn full_access_scp() -> NamedPolicy {
        parse_policy(
            "FullAWSAccess",
            r#"{
                "Statement": [{
                    "Sid": "FullAccess",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }]
            }"#,
        )
    }

    fn allow_s3_ec2_scp() -> NamedPolicy {
        parse_policy(
            "AllowS3AndEC2",
            r#"{
                "Statement": [{
                    "Sid": "AllowS3EC2",
                    "Effect": "Allow",
                    "Action": ["s3:*", "ec2:*"],
                    "Resource": "*"
                }]
            }"#,
        )
    }

    fn deny_delete_scp() -> NamedPolicy {
        parse_policy(
            "DenyDelete",
            r#"{
                "Statement": [{
                    "Sid": "DenyDelete",
                    "Effect": "Deny",
                    "Action": ["*:Delete*", "*:Remove*"],
                    "Resource": "*"
                }]
            }"#,
        )
    }

    fn make_context(action: &str, resource: &str) -> RequestContext {
        RequestContext::builder()
            .action(action)
            .resource(resource)
            .build()
            .unwrap()
    }

    #[test]
    fn test_scp_all_levels_allow() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![OuPolicySet {
                ou_id: "ou-1234".to_string(),
                ou_name: Some("Production".to_string()),
                policies: vec![full_access_scp()],
            }],
            account_policies: vec![full_access_scp()],
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(result.allowed);
        assert!(!result.explicit_deny);
        assert!(result.blocking_level.is_none());
    }

    #[test]
    fn test_scp_root_blocks() {
        // Root only allows S3 and EC2, but request is for DynamoDB
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![allow_s3_ec2_scp()],
            ou_policies: vec![],
            account_policies: vec![],
        };

        let ctx = make_context(
            "dynamodb:GetItem",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Users",
        );
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(!result.explicit_deny);
        assert!(result.blocking_level.as_ref().unwrap().contains("Root"));
    }

    #[test]
    fn test_scp_ou_blocks() {
        // Root allows all, but OU only allows S3/EC2
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![OuPolicySet {
                ou_id: "ou-1234".to_string(),
                ou_name: Some("Production".to_string()),
                policies: vec![allow_s3_ec2_scp()],
            }],
            account_policies: vec![],
        };

        let ctx = make_context(
            "lambda:InvokeFunction",
            "arn:aws:lambda:us-east-1:123456789012:function:MyFunc",
        );
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(!result.explicit_deny);
        assert!(
            result
                .blocking_level
                .as_ref()
                .unwrap()
                .contains("Production")
        );
    }

    #[test]
    fn test_scp_account_blocks() {
        // Root and OU allow all, but account only allows S3/EC2
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![OuPolicySet {
                ou_id: "ou-1234".to_string(),
                ou_name: Some("Production".to_string()),
                policies: vec![full_access_scp()],
            }],
            account_policies: vec![allow_s3_ec2_scp()],
        };

        let ctx = make_context("iam:CreateUser", "arn:aws:iam::123456789012:user/newuser");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(!result.explicit_deny);
        assert!(result.blocking_level.as_ref().unwrap().contains("Account"));
    }

    #[test]
    fn test_scp_explicit_deny() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![OuPolicySet {
                ou_id: "ou-1234".to_string(),
                ou_name: Some("Production".to_string()),
                policies: vec![deny_delete_scp(), full_access_scp()],
            }],
            account_policies: vec![],
        };

        let ctx = make_context("s3:DeleteObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(result.explicit_deny);
    }

    #[test]
    fn test_scp_multiple_ous() {
        // Test nested OUs where one blocks
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![
                OuPolicySet {
                    ou_id: "ou-1".to_string(),
                    ou_name: Some("Engineering".to_string()),
                    policies: vec![full_access_scp()],
                },
                OuPolicySet {
                    ou_id: "ou-2".to_string(),
                    ou_name: Some("Web-Tier".to_string()),
                    policies: vec![allow_s3_ec2_scp()], // Only S3/EC2
                },
            ],
            account_policies: vec![],
        };

        // S3 should be allowed
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();
        assert!(result.allowed);

        // DynamoDB should be blocked at Web-Tier level
        let ctx = make_context(
            "dynamodb:GetItem",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Users",
        );
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();
        assert!(!result.allowed);
        assert!(result.blocking_level.as_ref().unwrap().contains("Web-Tier"));
    }

    #[test]
    fn test_scp_empty_hierarchy() {
        // No SCPs means allow
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![],
            ou_policies: vec![],
            account_policies: vec![],
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(result.allowed);
    }

    #[test]
    fn test_check_explicit_deny() {
        let policies = vec![deny_delete_scp()];
        let ctx = make_context("s3:DeleteObject", "arn:aws:s3:::bucket/key");

        let result = check_explicit_deny(&policies, &ctx, PolicyType::Scp).unwrap();
        assert!(result.is_some());
        let (policy_name, statement_sid, _) = result.unwrap();
        assert_eq!(policy_name, "DenyDelete");
        assert_eq!(statement_sid, Some("DenyDelete".to_string()));
    }

    #[test]
    fn test_check_explicit_deny_no_match() {
        let policies = vec![deny_delete_scp()];
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");

        let result = check_explicit_deny(&policies, &ctx, PolicyType::Scp).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_check_allows() {
        let policies = vec![allow_s3_ec2_scp()];
        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");

        let (has_allow, _) = check_allows(&policies, &ctx, PolicyType::Scp).unwrap();
        assert!(has_allow);
    }

    #[test]
    fn test_check_allows_no_match() {
        let policies = vec![allow_s3_ec2_scp()];
        let ctx = make_context(
            "dynamodb:GetItem",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Users",
        );

        let (has_allow, _) = check_allows(&policies, &ctx, PolicyType::Scp).unwrap();
        assert!(!has_allow);
    }

    // ==========================================================================
    // AWS Behavior Accuracy Tests - SCP Hierarchy Logic
    // ==========================================================================

    fn deny_s3_scp() -> NamedPolicy {
        parse_policy(
            "DenyS3",
            r#"{
                "Statement": [{
                    "Sid": "DenyS3",
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }"#,
        )
    }

    fn allow_s3_only_scp() -> NamedPolicy {
        parse_policy(
            "AllowS3Only",
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

    /// Test OR logic within a level: if multiple policies at the same level,
    /// ANY policy can provide the Allow (OR logic).
    /// AWS behavior: Within a level, policies are evaluated together.
    #[test]
    fn test_scp_or_logic_within_level_allow_wins() {
        // Two SCPs at account level: one only allows EC2, one only allows S3
        // S3 request should be allowed because one of them allows it
        let ec2_only_scp = parse_policy(
            "AllowEC2Only",
            r#"{
                "Statement": [{
                    "Sid": "AllowEC2",
                    "Effect": "Allow",
                    "Action": "ec2:*",
                    "Resource": "*"
                }]
            }"#,
        );

        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![],
            account_policies: vec![ec2_only_scp, allow_s3_only_scp()], // Two policies, OR logic
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        // Should be allowed because at least one policy at account level allows S3
        assert!(result.allowed);
        assert!(!result.explicit_deny);
    }

    /// Test that explicit deny still overrides allows within same level
    /// AWS behavior: Explicit deny always wins, even with OR logic for allows
    #[test]
    fn test_scp_deny_overrides_or_logic() {
        // Two SCPs: one allows S3, one denies S3 - deny should win
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![],
            account_policies: vec![allow_s3_only_scp(), deny_s3_scp()],
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(result.explicit_deny);
    }

    /// Test deeply nested OU hierarchy (4+ levels)
    /// AWS behavior: Each level must allow, AND logic between all levels
    #[test]
    fn test_scp_deeply_nested_ous_all_allow() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![
                OuPolicySet {
                    ou_id: "ou-root".to_string(),
                    ou_name: Some("Root-OU".to_string()),
                    policies: vec![full_access_scp()],
                },
                OuPolicySet {
                    ou_id: "ou-dept".to_string(),
                    ou_name: Some("Department".to_string()),
                    policies: vec![full_access_scp()],
                },
                OuPolicySet {
                    ou_id: "ou-team".to_string(),
                    ou_name: Some("Team".to_string()),
                    policies: vec![full_access_scp()],
                },
                OuPolicySet {
                    ou_id: "ou-project".to_string(),
                    ou_name: Some("Project".to_string()),
                    policies: vec![full_access_scp()],
                },
            ],
            account_policies: vec![full_access_scp()],
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(result.allowed);
    }

    /// Test that ANY level blocking in deep hierarchy stops the request
    /// AWS behavior: AND logic - every single level must allow
    #[test]
    fn test_scp_deeply_nested_ous_middle_blocks() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![
                OuPolicySet {
                    ou_id: "ou-root".to_string(),
                    ou_name: Some("Root-OU".to_string()),
                    policies: vec![full_access_scp()],
                },
                OuPolicySet {
                    ou_id: "ou-dept".to_string(),
                    ou_name: Some("Department".to_string()),
                    policies: vec![allow_s3_ec2_scp()], // Only allows S3/EC2
                },
                OuPolicySet {
                    ou_id: "ou-team".to_string(),
                    ou_name: Some("Team".to_string()),
                    policies: vec![full_access_scp()],
                },
            ],
            account_policies: vec![full_access_scp()],
        };

        // DynamoDB should be blocked at Department level
        let ctx = make_context(
            "dynamodb:GetItem",
            "arn:aws:dynamodb:us-east-1:123456789012:table/Users",
        );
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(!result.explicit_deny);
        assert!(
            result
                .blocking_level
                .as_ref()
                .unwrap()
                .contains("Department")
        );
    }

    /// Test OU with empty policies list - should be skipped
    /// AWS behavior: OUs without SCPs are skipped, not implicit deny
    #[test]
    fn test_scp_ou_with_empty_policies_skipped() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![
                OuPolicySet {
                    ou_id: "ou-parent".to_string(),
                    ou_name: Some("Parent".to_string()),
                    policies: vec![full_access_scp()],
                },
                OuPolicySet {
                    ou_id: "ou-empty".to_string(),
                    ou_name: Some("EmptyOU".to_string()),
                    policies: vec![], // Empty - should be skipped
                },
            ],
            account_policies: vec![full_access_scp()],
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        // Should succeed because empty OU is skipped
        assert!(result.allowed);
    }

    /// Test OU without name uses ID in blocking message
    #[test]
    fn test_scp_ou_without_name_uses_id() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()],
            ou_policies: vec![OuPolicySet {
                ou_id: "ou-abc123".to_string(),
                ou_name: None, // No name
                policies: vec![allow_s3_only_scp()],
            }],
            account_policies: vec![],
        };

        let ctx = make_context(
            "ec2:RunInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/*",
        );
        let result = evaluate_scp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(
            result
                .blocking_level
                .as_ref()
                .unwrap()
                .contains("ou-abc123")
        );
    }

    // ==========================================================================
    // RCP Hierarchy Tests
    // ==========================================================================

    /// Test RCP hierarchy with all levels allowing
    #[test]
    fn test_rcp_all_levels_allow() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![full_access_scp()], // Note: uses root_policies field for RCPs too
            ou_policies: vec![OuPolicySet {
                ou_id: "ou-1234".to_string(),
                ou_name: Some("Production".to_string()),
                policies: vec![full_access_scp()],
            }],
            account_policies: vec![full_access_scp()],
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_rcp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(result.allowed);
        assert!(!result.explicit_deny);
    }

    /// Test RCP explicit deny
    #[test]
    fn test_rcp_explicit_deny() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![deny_s3_scp()],
            ou_policies: vec![],
            account_policies: vec![],
        };

        let ctx = make_context("s3:GetObject", "arn:aws:s3:::bucket/key");
        let result = evaluate_rcp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(result.explicit_deny);
        assert!(
            result
                .blocking_level
                .as_ref()
                .unwrap()
                .contains("Root RCPs")
        );
    }

    /// Test RCP implicit deny (no matching allow)
    #[test]
    fn test_rcp_implicit_deny_no_allow() {
        let hierarchy = OrganizationHierarchy {
            root_policies: vec![allow_s3_only_scp()], // Only allows S3
            ou_policies: vec![],
            account_policies: vec![],
        };

        let ctx = make_context(
            "ec2:RunInstances",
            "arn:aws:ec2:us-east-1:123456789012:instance/*",
        );
        let result = evaluate_rcp_hierarchy(&hierarchy, &ctx).unwrap();

        assert!(!result.allowed);
        assert!(!result.explicit_deny);
    }
}
