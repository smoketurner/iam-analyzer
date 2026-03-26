//! Policy evaluation engine.
//!
//! This module implements the AWS IAM policy evaluation logic:
//! - [`EvaluationEngine`] - Main evaluation orchestration
//! - [`RequestContext`] - Context for an access request
//! - [`Decision`] - The result of policy evaluation
//! - [`PolicySet`] - Collection of policies to evaluate

pub mod condition_eval;
mod context;
pub mod context_bags;
mod decision;
mod engine;
pub mod hierarchy;
pub mod matchers;
pub mod principal;
pub mod variables;

pub use condition_eval::{ConditionEvaluator, ip_in_cidr};
pub use context::{RequestContext, RequestContextBuilder};
pub use context_bags::{
    ConditionValue, ContextBag, NetworkContext, PrincipalContext, RequestBag, ResourceContext,
    SessionContext,
};
pub use decision::{Decision, EvaluationResult, PolicyType, ReasoningStep};
pub use engine::{EvaluationEngine, NamedPolicy, OrganizationHierarchy, OuPolicySet, PolicySet};
pub use hierarchy::{HierarchyResult, evaluate_rcp_hierarchy, evaluate_scp_hierarchy};
pub use matchers::{MatchResult, statement_matches};
pub use principal::{PrincipalType, infer_principal_type, is_service_linked_role};
