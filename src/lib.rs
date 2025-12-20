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
//! ```rust,ignore
//! use iam_analyzer::{EvaluationEngine, PolicySet, RequestContext, Decision};
//!
//! let result = EvaluationEngine::new().evaluate(
//!     &RequestContext::builder()
//!         .action("s3:GetObject")
//!         .resource("arn:aws:s3:::my-bucket/file.txt")
//!         .build()?,
//!     &policy_set,
//! );
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
