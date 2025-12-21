//! ARN parsing and pattern matching module.
//!
//! This module provides types and functions for working with AWS ARNs:
//! - [`Arn`] - A parsed, validated ARN
//! - [`ArnPattern`] - A pattern for matching ARNs with wildcards

pub mod pattern;
mod types;

pub use pattern::{ArnPattern, glob_match};
pub use types::Arn;
