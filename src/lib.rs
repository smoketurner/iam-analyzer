//! # IAM Analyzer
//!
//! A Rust library and CLI tool for evaluating AWS IAM policies.
//!
//! This library implements the exact AWS IAM policy evaluation logic, supporting:
//! - Service Control Policies (SCPs)
//! - Resource Control Policies (RCPs)
//! - VPC Endpoint Policies
//! - Identity-based Policies
//! - Resource-based Policies
//! - Permission Boundaries
//! - Session Policies
//!
//! ## Example
//!
//! ```
//! use iam_analyzer::{EvaluationEngine, PolicySet, RequestContext, Decision, NamedPolicy, Policy};
//!
//! // Parse a policy from JSON
//! let policy: Policy = serde_json::from_str(r#"{
//!     "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
//! }"#).unwrap();
//!
//! // Build the request context
//! let ctx = RequestContext::builder()
//!     .action("s3:GetObject")
//!     .resource("arn:aws:s3:::my-bucket/file.txt")
//!     .principal_arn("arn:aws:iam::123456789012:user/alice")
//!     .build()
//!     .unwrap();
//!
//! // Create policy set and evaluate
//! let policies = PolicySet {
//!     identity_policies: vec![NamedPolicy::new("S3ReadPolicy", policy)],
//!     ..Default::default()
//! };
//!
//! let result = EvaluationEngine::new().evaluate(&ctx, &policies);
//!
//! match result.decision {
//!     Decision::Allow => println!("Access allowed"),
//!     Decision::ExplicitDeny => println!("Explicitly denied"),
//!     Decision::ImplicitDeny => println!("Implicitly denied"),
//! }
//! ```

pub mod arn;
pub mod error;
pub mod eval;
pub mod policy;
pub mod service;

// Re-export key types for convenience
pub use arn::{Arn, ArnPattern};
pub use error::Error;
pub use eval::{
    Decision, EvaluationEngine, EvaluationResult, NamedPolicy, OrganizationHierarchy, PolicySet,
    RequestContext,
};
pub use policy::{Effect, Policy, Statement};
pub use service::{ServiceDefinition, ServiceLoader};
