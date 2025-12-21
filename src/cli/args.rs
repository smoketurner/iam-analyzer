//! CLI argument definitions.

use clap::{Parser, ValueEnum};

/// Output format options
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text output (default)
    #[default]
    Text,
    /// Concise summary - decision, policy, and reason on a few lines
    Summary,
    /// JSON output for programmatic consumption
    Json,
    /// Minimal output - just the decision (ALLOW, EXPLICIT_DENY, or IMPLICIT_DENY)
    Quiet,
}

const EXAMPLES: &str = r#"
EXAMPLES:
    # Test if an identity policy allows S3 access
    # (principal account auto-detected from ARN)
    iam-analyzer -a s3:GetObject -r arn:aws:s3:::bucket/key \
        -i policy.json \
        -p arn:aws:iam::123456789012:user/alice

    # Test with SCP/RCP using organization config file
    iam-analyzer -a ec2:RunInstances -r arn:aws:ec2:eu-west-1:123:instance/* \
        -i policy.json --organization-config org-policies.yaml \
        -p arn:aws:iam::123456789012:user/dev

    # Test with principal context from file (MFA, org, tags)
    iam-analyzer -a ec2:TerminateInstances -r arn:aws:ec2:*:*:instance/* \
        -i policy.json --principal-context principal.json

    # Test with all context files
    iam-analyzer -a s3:PutObject -r arn:aws:s3:::bucket/key \
        -i policy.json \
        --principal-context principal.json \
        --resource-context resource.json \
        --request-context request.json

    # Generate template context files
    iam-analyzer --generate-context-template

    # Get just the decision (useful for scripts)
    iam-analyzer -a s3:GetObject -r arn:aws:s3:::bucket/key -i policy.json -o quiet
"#;

/// IAM Analyzer - Evaluate AWS IAM policies
///
/// Evaluate whether an IAM action will be allowed, explicitly denied,
/// or implicitly denied based on the provided policies.
#[derive(Parser, Debug)]
#[command(name = "iam-analyzer")]
#[command(version, about, long_about = None)]
#[command(after_help = EXAMPLES)]
pub struct Args {
    // =========================================================================
    // Required Arguments
    // =========================================================================
    /// The IAM action to evaluate (e.g., s3:GetObject)
    #[arg(short, long, help_heading = "Request", required_unless_present = "generate_context_template")]
    pub action: Option<String>,

    /// The resource ARN to evaluate (e.g., arn:aws:s3:::my-bucket/file.txt)
    #[arg(short, long, help_heading = "Request", required_unless_present = "generate_context_template")]
    pub resource: Option<String>,

    // =========================================================================
    // Policy Files
    // =========================================================================
    /// Identity-based policy files (can specify multiple)
    #[arg(
        short = 'i',
        long = "identity-policy",
        value_name = "FILE",
        help_heading = "Policies"
    )]
    pub identity_policy: Vec<String>,

    /// Resource-based policy files (can specify multiple)
    #[arg(
        short = 'R',
        long = "resource-policy",
        value_name = "FILE",
        help_heading = "Policies"
    )]
    pub resource_policy: Vec<String>,

    /// Permission boundary policy files (can specify multiple)
    #[arg(
        long = "permission-boundary",
        value_name = "FILE",
        help_heading = "Policies"
    )]
    pub permission_boundary: Vec<String>,

    /// Session policy files (can specify multiple)
    #[arg(
        long = "session-policy",
        value_name = "FILE",
        help_heading = "Policies"
    )]
    pub session_policy: Vec<String>,

    /// VPC endpoint policy files (can specify multiple)
    #[arg(
        long = "vpc-endpoint-policy",
        value_name = "FILE",
        help_heading = "Policies"
    )]
    pub vpc_endpoint_policy: Vec<String>,

    // =========================================================================
    // Organization Policies (SCPs and RCPs)
    // =========================================================================
    /// Organization policies configuration file (YAML format)
    ///
    /// Load SCP and RCP hierarchies from a single YAML file instead of
    /// multiple CLI flags. See documentation for the expected format.
    #[arg(
        long = "organization-config",
        value_name = "FILE",
        help_heading = "Organization Policies"
    )]
    pub organization_config: Option<String>,

    // =========================================================================
    // Context Files
    // =========================================================================
    /// Principal ARN making the request (convenience flag)
    ///
    /// This is a shorthand for specifying the principal ARN without
    /// needing a full principal context file.
    #[arg(
        short = 'p',
        long = "principal-arn",
        value_name = "ARN",
        help_heading = "Context"
    )]
    pub principal_arn: Option<String>,

    /// Principal context file (JSON format)
    ///
    /// Load principal context from a JSON file. Includes:
    /// - ARN, account, organization info
    /// - Principal tags
    /// - Service principal details
    /// - Management account flag
    #[arg(
        long = "principal-context",
        value_name = "FILE",
        help_heading = "Context"
    )]
    pub principal_context: Option<String>,

    /// Resource context file (JSON format)
    ///
    /// Load resource context from a JSON file. Includes:
    /// - Account, organization info
    /// - Resource tags
    #[arg(
        long = "resource-context",
        value_name = "FILE",
        help_heading = "Context"
    )]
    pub resource_context: Option<String>,

    /// Request context file (JSON format)
    ///
    /// Load request context from a JSON file. Includes:
    /// - Network context (source IP, VPC, VPCE)
    /// - Session context (MFA, federation)
    /// - Request context (region, CalledVia, tags)
    /// - Custom/service-specific condition keys
    #[arg(
        long = "request-context",
        value_name = "FILE",
        help_heading = "Context"
    )]
    pub request_context: Option<String>,

    /// Generate template context files
    ///
    /// Outputs template JSON files for principal, resource, and request
    /// context with all available fields documented.
    #[arg(
        long = "generate-context-template",
        help_heading = "Context"
    )]
    pub generate_context_template: bool,

    // =========================================================================
    // Service Definition Options
    // =========================================================================
    /// Force refresh of AWS service definitions from the Service Authorization Reference
    #[arg(long = "update-definitions", help_heading = "Service Definitions")]
    pub update_definitions: bool,

    /// Disable network requests (use cached definitions or skip validation)
    #[arg(long = "offline", help_heading = "Service Definitions")]
    pub offline: bool,

    // =========================================================================
    // Output Options
    // =========================================================================
    /// Output format: text (default), json, or quiet
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text, help_heading = "Output")]
    pub output: OutputFormat,
}
