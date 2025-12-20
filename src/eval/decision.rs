//! Decision types for policy evaluation results.

use std::fmt;

use serde::Serialize;

use super::matchers::MatchBreakdown;

/// The final decision from policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Decision {
    /// Access is explicitly allowed.
    Allow,
    /// Access is explicitly denied by a Deny statement.
    ExplicitDeny,
    /// Access is implicitly denied (no Allow statement matched).
    ImplicitDeny,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::ExplicitDeny => write!(f, "EXPLICIT_DENY"),
            Decision::ImplicitDeny => write!(f, "IMPLICIT_DENY"),
        }
    }
}

/// The type of policy that was evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PolicyType {
    /// Service Control Policy
    Scp,
    /// Resource Control Policy
    Rcp,
    /// VPC Endpoint Policy
    VpcEndpoint,
    /// Identity-based Policy
    IdentityBased,
    /// Resource-based Policy
    ResourceBased,
    /// Permission Boundary
    PermissionBoundary,
    /// Session Policy
    SessionPolicy,
}

impl fmt::Display for PolicyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyType::Scp => write!(f, "SCP"),
            PolicyType::Rcp => write!(f, "RCP"),
            PolicyType::VpcEndpoint => write!(f, "VPC Endpoint Policy"),
            PolicyType::IdentityBased => write!(f, "Identity-based Policy"),
            PolicyType::ResourceBased => write!(f, "Resource-based Policy"),
            PolicyType::PermissionBoundary => write!(f, "Permission Boundary"),
            PolicyType::SessionPolicy => write!(f, "Session Policy"),
        }
    }
}

/// A single step in the evaluation reasoning chain.
#[derive(Debug, Clone, Serialize)]
pub struct ReasoningStep {
    /// The type of policy evaluated.
    pub policy_type: PolicyType,
    /// The name of the policy file or identifier.
    pub policy_name: String,
    /// The statement ID that matched (if any).
    pub statement_sid: Option<String>,
    /// Whether this step resulted in a match.
    pub matched: bool,
    /// The effect of the matched statement.
    pub effect: Option<crate::policy::Effect>,
    /// Additional details about the evaluation.
    pub details: String,
    /// Detailed breakdown of what matched or didn't match.
    pub breakdown: Option<MatchBreakdown>,
}

/// The complete result of policy evaluation.
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationResult {
    /// The final decision.
    pub decision: Decision,
    /// The reasoning steps that led to the decision.
    pub reasoning: Vec<ReasoningStep>,
    /// The policy type that determined the final decision.
    pub deciding_policy_type: Option<PolicyType>,
    /// The statement that determined the final decision.
    pub deciding_statement: Option<String>,
}

impl EvaluationResult {
    /// Create an Allow result.
    pub fn allow(reasoning: Vec<ReasoningStep>) -> Self {
        Self {
            decision: Decision::Allow,
            reasoning,
            deciding_policy_type: None,
            deciding_statement: None,
        }
    }

    /// Create an ExplicitDeny result.
    pub fn explicit_deny(
        policy_type: PolicyType,
        statement: Option<String>,
        reasoning: Vec<ReasoningStep>,
    ) -> Self {
        Self {
            decision: Decision::ExplicitDeny,
            reasoning,
            deciding_policy_type: Some(policy_type),
            deciding_statement: statement,
        }
    }

    /// Create an ImplicitDeny result.
    pub fn implicit_deny(policy_type: PolicyType, reasoning: Vec<ReasoningStep>) -> Self {
        Self {
            decision: Decision::ImplicitDeny,
            reasoning,
            deciding_policy_type: Some(policy_type),
            deciding_statement: None,
        }
    }

    /// Generate a concise summary of the evaluation result.
    pub fn summary(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("Decision: {}\n", self.decision));

        if let Some(policy_type) = &self.deciding_policy_type {
            output.push_str(&format!("Policy Type: {}\n", policy_type));
        }

        if let Some(stmt) = &self.deciding_statement {
            output.push_str(&format!("Statement: {}\n", stmt));
        }

        // Find the deciding reasoning step
        let deciding_step = self.reasoning.iter().find(|step| {
            step.matched
                && step.effect.map_or(false, |e| match self.decision {
                    Decision::Allow => e == crate::policy::Effect::Allow,
                    Decision::ExplicitDeny => e == crate::policy::Effect::Deny,
                    Decision::ImplicitDeny => false,
                })
        });

        if let Some(step) = deciding_step {
            if !step.policy_name.is_empty() {
                output.push_str(&format!("Policy: {}\n", step.policy_name));
            }
            if !step.details.is_empty() {
                output.push_str(&format!("Reason: {}\n", step.details));
            }
        } else if self.decision == Decision::ImplicitDeny {
            output.push_str("Reason: No Allow statement matched\n");
        }

        output
    }
}

impl fmt::Display for EvaluationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Decision: {}", self.decision)?;
        writeln!(f)?;
        writeln!(f, "Reasoning:")?;

        for (i, step) in self.reasoning.iter().enumerate() {
            write!(f, "  [{}] {} ", i + 1, step.policy_type)?;
            if !step.policy_name.is_empty() {
                write!(f, "({})", step.policy_name)?;
            }
            writeln!(f)?;

            if let Some(sid) = &step.statement_sid {
                write!(f, "      Statement \"{}\" ", sid)?;
            } else {
                write!(f, "      ")?;
            }

            if step.matched {
                write!(f, "matches")?;
            } else {
                write!(f, "does not match")?;
            }

            if let Some(effect) = &step.effect {
                write!(f, " - Effect: {:?}", effect)?;
            }

            writeln!(f)?;

            if !step.details.is_empty() {
                writeln!(f, "      {}", step.details)?;
            }

            // Show detailed breakdown if available
            if let Some(breakdown) = &step.breakdown {
                // Format the breakdown with proper indentation
                let breakdown_str = breakdown.to_string();
                for line in breakdown_str.lines() {
                    if !line.is_empty() {
                        writeln!(f, "        {}", line)?;
                    }
                }
            }
        }

        if let Some(policy_type) = &self.deciding_policy_type {
            writeln!(f)?;
            write!(f, "Final: {} from {}", self.decision, policy_type)?;
            if let Some(stmt) = &self.deciding_statement {
                write!(f, " statement \"{}\"", stmt)?;
            }
            writeln!(f)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_display() {
        assert_eq!(Decision::Allow.to_string(), "ALLOW");
        assert_eq!(Decision::ExplicitDeny.to_string(), "EXPLICIT_DENY");
        assert_eq!(Decision::ImplicitDeny.to_string(), "IMPLICIT_DENY");
    }

    #[test]
    fn test_policy_type_display() {
        assert_eq!(PolicyType::Scp.to_string(), "SCP");
        assert_eq!(
            PolicyType::IdentityBased.to_string(),
            "Identity-based Policy"
        );
    }

    #[test]
    fn test_evaluation_result_allow() {
        let result = EvaluationResult::allow(vec![]);
        assert_eq!(result.decision, Decision::Allow);
    }

    #[test]
    fn test_evaluation_result_explicit_deny() {
        let result = EvaluationResult::explicit_deny(
            PolicyType::ResourceBased,
            Some("DenyAll".to_string()),
            vec![],
        );
        assert_eq!(result.decision, Decision::ExplicitDeny);
        assert_eq!(result.deciding_policy_type, Some(PolicyType::ResourceBased));
        assert_eq!(result.deciding_statement, Some("DenyAll".to_string()));
    }

    #[test]
    fn test_evaluation_result_display() {
        let result = EvaluationResult {
            decision: Decision::ExplicitDeny,
            reasoning: vec![ReasoningStep {
                policy_type: PolicyType::ResourceBased,
                policy_name: "bucket-policy.json".to_string(),
                statement_sid: Some("DenyDeletes".to_string()),
                matched: true,
                effect: Some(crate::policy::Effect::Deny),
                details: "Condition aws:PrincipalArn matched".to_string(),
                breakdown: None,
            }],
            deciding_policy_type: Some(PolicyType::ResourceBased),
            deciding_statement: Some("DenyDeletes".to_string()),
        };

        let output = result.to_string();
        assert!(output.contains("EXPLICIT_DENY"));
        assert!(output.contains("DenyDeletes"));
        assert!(output.contains("Resource-based Policy"));
    }
}
