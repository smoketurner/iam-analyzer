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

    # Test cross-account S3 access
    # (cross-account auto-detected when accounts differ)
    iam-analyzer -a s3:GetObject -r arn:aws:s3:::bucket/key \
        -i identity.json -R bucket-policy.json \
        -p arn:aws:iam::111111111111:user/alice \
        --resource-account 222222222222

    # Test with SCP/RCP using organization config file
    iam-analyzer -a ec2:RunInstances -r arn:aws:ec2:eu-west-1:123:instance/* \
        -i policy.json --organization-config org-policies.yaml \
        -p arn:aws:iam::123456789012:user/dev

    # Test with MFA requirement
    iam-analyzer -a ec2:TerminateInstances -r arn:aws:ec2:*:*:instance/* \
        -i policy.json --mfa-present

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
    #[arg(short, long, help_heading = "Request")]
    pub action: String,

    /// The resource ARN to evaluate (e.g., arn:aws:s3:::my-bucket/file.txt)
    #[arg(short, long, help_heading = "Request")]
    pub resource: String,

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
    // Principal Context
    // =========================================================================
    /// Principal ARN making the request
    #[arg(
        short = 'p',
        long = "principal-arn",
        value_name = "ARN",
        help_heading = "Principal Context"
    )]
    pub principal_arn: Option<String>,

    /// Account ID of the principal
    #[arg(
        short = 'A',
        long = "principal-account",
        value_name = "ACCOUNT_ID",
        help_heading = "Principal Context"
    )]
    pub principal_account: Option<String>,

    /// The unique identifier of the principal (aws:userid)
    #[arg(
        long = "principal-userid",
        value_name = "USERID",
        help_heading = "Principal Context"
    )]
    pub principal_userid: Option<String>,

    /// Organization ID of the principal (for aws:PrincipalOrgID condition)
    #[arg(
        long = "principal-org-id",
        value_name = "ORG_ID",
        help_heading = "Principal Context"
    )]
    pub principal_org_id: Option<String>,

    /// Organization paths of the principal (aws:PrincipalOrgPaths, can specify multiple)
    #[arg(
        long = "principal-org-paths",
        value_name = "PATH",
        help_heading = "Principal Context"
    )]
    pub principal_org_paths: Vec<String>,

    /// Principal is from the organization's management account (bypasses SCPs)
    #[arg(long = "management-account", help_heading = "Principal Context")]
    pub management_account: bool,

    // =========================================================================
    // Resource Context
    // =========================================================================
    /// Account ID that owns the resource (auto-detected from resource ARN when possible)
    #[arg(
        long = "resource-account",
        value_name = "ACCOUNT_ID",
        help_heading = "Resource Context"
    )]
    pub resource_account: Option<String>,

    // =========================================================================
    // Request Context (Condition Keys)
    // =========================================================================
    /// Whether MFA was used for authentication (aws:MultiFactorAuthPresent)
    #[arg(long = "mfa-present", help_heading = "Request Context")]
    pub mfa_present: bool,

    /// The AWS region being requested (aws:RequestedRegion)
    #[arg(
        long = "requested-region",
        value_name = "REGION",
        help_heading = "Request Context"
    )]
    pub requested_region: Option<String>,

    /// Whether the request came through an AWS service (aws:ViaAWSService)
    #[arg(long = "via-aws-service", help_heading = "Request Context")]
    pub via_aws_service: bool,

    /// Services in the CalledVia chain (can specify multiple, in order)
    #[arg(
        long = "called-via",
        value_name = "SERVICE",
        help_heading = "Request Context"
    )]
    pub called_via: Vec<String>,

    /// Source ARN for service-to-service requests (aws:SourceArn)
    #[arg(
        long = "source-arn",
        value_name = "ARN",
        help_heading = "Request Context"
    )]
    pub source_arn: Option<String>,

    /// Source account for service-to-service requests (aws:SourceAccount)
    #[arg(
        long = "source-account",
        value_name = "ACCOUNT_ID",
        help_heading = "Request Context"
    )]
    pub source_account: Option<String>,

    /// Context key-value pairs (KEY=VALUE format, can specify multiple)
    #[arg(
        short,
        long = "context",
        value_name = "KEY=VALUE",
        help_heading = "Request Context"
    )]
    pub context: Vec<String>,

    /// JSON file containing additional request context
    #[arg(
        long = "context-file",
        value_name = "FILE",
        help_heading = "Request Context"
    )]
    pub context_file: Option<String>,

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
