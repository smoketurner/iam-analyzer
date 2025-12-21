//! IAM Analyzer CLI
//!
//! Evaluate AWS IAM policies with detailed reasoning.
//!
//! Exit codes:
//! - 0: ALLOW (or no evaluation performed, e.g., --generate-context-template)
//! - 1: Error (configuration, file read, invalid arguments)
//! - 2: EXPLICIT_DENY
//! - 3: IMPLICIT_DENY

mod cli;

use iam_analyzer::Decision;
use std::process::ExitCode;

fn main() -> ExitCode {
    match cli::run() {
        Ok(Some(decision)) => decision_to_exit_code(decision),
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Map a decision to an exit code.
fn decision_to_exit_code(decision: Decision) -> ExitCode {
    match decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::ExplicitDeny => ExitCode::from(2),
        Decision::ImplicitDeny => ExitCode::from(3),
    }
}
