//! ARN parsing and pattern matching module.
//!
//! This module provides types and functions for working with AWS ARNs:
//! - [`Arn`] - A parsed, validated ARN
//! - [`ArnPattern`] - A pattern for matching ARNs with wildcards

mod arn;
pub mod pattern;

pub use arn::Arn;
pub use pattern::{ArnPattern, glob_match};
