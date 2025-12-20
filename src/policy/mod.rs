//! Policy parsing and AST types.
//!
//! This module contains the types for representing IAM policies:
//! - [`Policy`] - A complete IAM policy document
//! - [`Statement`] - A single policy statement
//! - [`Effect`] - Allow or Deny
//! - [`validation`] - Policy validation utilities

pub mod action;
mod ast;
pub mod validation;

pub use ast::{
    ActionBlock, Condition, ConditionBlock, ConditionOperator, Effect, Policy, Principal,
    PrincipalBlock, ResourceBlock, Statement,
};
pub use validation::{
    Severity, ValidationIssue, has_errors, validate_against_service_definitions, validate_policy,
};
