# IAM Analyzer

[![CI](https://github.com/smoketurner/iam-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/smoketurner/iam-analyzer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Crates.io](https://img.shields.io/crates/v/iam-analyzer.svg)](https://crates.io/crates/iam-analyzer)

A Rust CLI tool and library for evaluating AWS IAM policies with detailed reasoning.

## Description

IAM Analyzer implements the exact AWS IAM policy evaluation logic, allowing you to test whether an IAM action will be allowed, explicitly denied, or implicitly denied based on your policies - without making actual AWS API calls.

## Features

- **Complete IAM Evaluation Logic** - Implements the full AWS IAM policy evaluation flow
- **All 7 Policy Types Supported**:
  - Service Control Policies (SCPs)
  - Resource Control Policies (RCPs)
  - VPC Endpoint Policies
  - Identity-based Policies
  - Resource-based Policies
  - Permission Boundaries
  - Session Policies
- **49 Global Condition Keys** - Full support for AWS global condition keys
- **Cross-Account Evaluation** - Correctly handles same-account and cross-account access scenarios
- **Organization Hierarchy** - Evaluates SCP/RCP hierarchies (root -> OUs -> account)
- **Multiple Output Formats** - Text, summary, JSON, and quiet modes
- **Detailed Reasoning** - Shows step-by-step evaluation decisions
- **Auto-Detection** - Automatically extracts account, region, and cross-account status from ARNs

## Installation

### From Source

```bash
git clone https://github.com/jplock/iam-analyzer.git
cd iam-analyzer
cargo build --release
./target/release/iam-analyzer --help
```

### Using Cargo (when published)

```bash
cargo install iam-analyzer
```

## Quick Start

### Basic Identity Policy Evaluation

Test if an identity policy allows S3 access (principal account auto-detected from ARN):

```bash
iam-analyzer -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i policy.json \
    -p arn:aws:iam::123456789012:user/alice
```

### With SCP/RCP Organization Hierarchy

Use an organization config file to define SCP/RCP hierarchies:

```bash
iam-analyzer -a ec2:RunInstances -r "arn:aws:ec2:us-east-1:123456789012:instance/*" \
    -i policy.json \
    --organization-config org-policies.yaml \
    -p arn:aws:iam::123456789012:user/dev
```

### With MFA Requirement

Create a request context file with MFA settings:

```bash
# request-context.json
{
  "session": {
    "mfa_present": true
  }
}
```

```bash
iam-analyzer -a ec2:TerminateInstances -r "arn:aws:ec2:*:*:instance/*" \
    -i policy.json \
    -p arn:aws:iam::123456789012:user/admin \
    --request-context request-context.json
```

### Cross-Account S3 Access

Cross-account access is auto-detected when principal and resource accounts differ:

```bash
iam-analyzer -a s3:GetObject -r arn:aws:s3:::their-bucket/file.txt \
    -i identity.json \
    -R bucket-policy.json \
    -p arn:aws:iam::111111111111:user/alice \
    --resource-context resource.json
```

### Script-Friendly Output

```bash
iam-analyzer -a s3:GetObject -r arn:aws:s3:::bucket/key \
    -i policy.json \
    -p arn:aws:iam::123456789012:user/alice \
    -o quiet
# Outputs: ALLOW, EXPLICIT_DENY, or IMPLICIT_DENY
```

### Generate Context Templates

Generate template context files showing all available fields:

```bash
iam-analyzer --generate-context-template
```

## CLI Reference

### Required Arguments

| Flag | Description |
|------|-------------|
| `-a, --action` | The IAM action to evaluate (e.g., `s3:GetObject`) |
| `-r, --resource` | The resource ARN to evaluate |

### Policy Files

| Flag | Description |
|------|-------------|
| `-i, --identity-policy` | Identity-based policy files (can specify multiple) |
| `-R, --resource-policy` | Resource-based policy files (can specify multiple) |
| `--permission-boundary` | Permission boundary policy files |
| `--session-policy` | Session policy files |
| `--vpc-endpoint-policy` | VPC endpoint policy files |

### Organization Policies

| Flag | Description |
|------|-------------|
| `--organization-config` | Organization policies configuration file (YAML format) |

### Context Options

| Flag | Description |
|------|-------------|
| `-p, --principal-arn` | Principal ARN making the request (convenience shorthand) |
| `--principal-context` | Principal context file (JSON format) |
| `--resource-context` | Resource context file (JSON format) |
| `--request-context` | Request context file (JSON format) |
| `--generate-context-template` | Generate template context files |

### Service Definitions

| Flag | Description |
|------|-------------|
| `--update-definitions` | Force refresh of AWS service definitions |
| `--offline` | Disable network requests (use cached definitions) |

### Output Formats

| Flag | Description |
|------|-------------|
| `-o text` | Human-readable output with full reasoning (default) |
| `-o summary` | Concise decision, policy type, and reason |
| `-o json` | Structured JSON for programmatic use |
| `-o quiet` | Just the decision word |

## Context Files

Context files allow you to specify detailed evaluation context in JSON format.

### Principal Context

```json
{
  "arn": "arn:aws:iam::123456789012:user/alice",
  "account": "123456789012",
  "org_id": "o-abc123def4",
  "org_paths": ["o-abc123def4/r-ab12/ou-ab12-11111111/"],
  "userid": "AIDAEXAMPLEUSERID",
  "username": "alice",
  "principal_type": "User",
  "is_aws_service": false,
  "is_management_account": false,
  "tags": {
    "Department": "Engineering",
    "Team": "Platform"
  }
}
```

### Resource Context

```json
{
  "account": "123456789012",
  "org_id": "o-abc123def4",
  "org_paths": ["o-abc123def4/r-ab12/ou-ab12-11111111/"],
  "tags": {
    "Environment": "Production",
    "Classification": "Confidential"
  }
}
```

### Request Context

```json
{
  "network": {
    "source_ip": "192.168.1.100",
    "source_vpc": "vpc-12345678",
    "source_vpce": "vpce-1a2b3c4d"
  },
  "session": {
    "mfa_present": true,
    "mfa_auth_age": 300,
    "source_identity": "alice@example.com"
  },
  "request": {
    "region": "us-east-1",
    "secure_transport": true,
    "via_aws_service": false,
    "called_via": ["athena.amazonaws.com"],
    "tags": {
      "CostCenter": "12345"
    }
  },
  "custom": {
    "iam:PassedToService": "lambda.amazonaws.com"
  }
}
```

All fields in context files are optional. Use `--generate-context-template` to see all available fields.

## Organization Config Format

SCP and RCP hierarchies can be loaded from a single YAML file:

```yaml
# Organization policies configuration
# Represents the path from org root to the principal's account

scp_hierarchy:
  root:                          # Policies at org root (list of paths)
    - path/to/root-scp.json
  ous:                           # OU-level policies (ordered root to account)
    - id: ou-engineering         # Required: OU identifier
      name: Engineering          # Optional: Human-readable name
      policies:                  # Required: List of policy file paths
        - path/to/ou-scp.json
  account:                       # Policies attached to the principal's account
    - path/to/account-scp.json

rcp_hierarchy:                   # Same structure for RCPs
  root: []
  ous: []
  account: []
```

Paths are relative to the config file location. AWS SCPs use AND logic between levels (every level must allow) but OR logic within a level (any policy at a level can provide the allow).

## Auto-Detection Features

The CLI automatically detects several values from ARNs to reduce required flags:

- **Principal account** - Extracted from principal ARN (e.g., `arn:aws:iam::123456789012:user/alice`)
- **Resource account** - Parsed from resource ARN when in standard format
- **Requested region** - Extracted from resource ARN (e.g., `us-west-2` from EC2 ARN)
- **Cross-account** - Detected when principal and resource accounts differ
- **Service-linked role** - Detected from principal ARN pattern

Explicit values in context files always override auto-detected ones.

## Supported Condition Keys

IAM Analyzer supports 49 AWS global condition keys:

<details>
<summary>Click to expand full list</summary>

**Principal (11 keys)**
- `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`
- `aws:PrincipalTag/*`, `aws:PrincipalType`, `aws:PrincipalIsAWSService`
- `aws:PrincipalServiceName`, `aws:PrincipalServiceNamesList`
- `aws:userid`, `aws:username`

**Resource (4 keys)**
- `aws:ResourceAccount`, `aws:ResourceOrgID`, `aws:ResourceOrgPaths`, `aws:ResourceTag/*`

**Network (8 keys)**
- `aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpcArn`, `aws:SourceVpce`
- `aws:VpcSourceIp`, `aws:VpceAccount`, `aws:VpceOrgID`, `aws:VpceOrgPaths`

**Session (9 keys)**
- `aws:MultiFactorAuthPresent`, `aws:MultiFactorAuthAge`
- `aws:TokenIssueTime`, `aws:SourceIdentity`, `aws:FederatedProvider`
- `aws:AssumedRoot`, `aws:ChatbotSourceArn`
- `aws:Ec2InstanceSourceVpc`, `aws:Ec2InstanceSourcePrivateIPv4`

**Request (17 keys)**
- `aws:RequestTag/*`, `aws:TagKeys`, `aws:RequestedRegion`
- `aws:CalledVia`, `aws:CalledViaFirst`, `aws:CalledViaLast`, `aws:ViaAWSService`
- `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID`, `aws:SourceOrgPaths`
- `aws:SecureTransport`, `aws:CurrentTime`, `aws:EpochTime`
- `aws:referer`, `aws:UserAgent`, `aws:IsMcpServiceAction`

</details>

Service-specific condition keys can be set via the `custom` section in request context files.

## Library Usage

```rust
use iam_analyzer::{EvaluationEngine, PolicySet, RequestContext, Decision};

let engine = EvaluationEngine::new();
let context = RequestContext::builder()
    .action("s3:GetObject")
    .resource("arn:aws:s3:::my-bucket/file.txt")
    .principal_arn("arn:aws:iam::123456789012:user/alice")
    .principal_account("123456789012")
    .build()?;

let policies = PolicySet {
    identity_policies: vec![/* your policies */],
    ..Default::default()
};

let result = engine.evaluate(&context, &policies);

match result.decision {
    Decision::Allow => println!("Access allowed"),
    Decision::ExplicitDeny => println!("Explicitly denied"),
    Decision::ImplicitDeny => println!("Implicitly denied"),
}
```

## How It Works

IAM Analyzer follows the [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html):

1. **Check explicit denies** in ALL policies first
2. **Evaluate SCP hierarchy** (every level must allow)
3. **Evaluate RCP hierarchy** (every level must allow)
4. **Check VPC endpoint policy**
5. **Check permission boundaries**
6. **Check session policies**
7. **Evaluate identity + resource policies**
   - Same-account: Union (either can grant access)
   - Cross-account: Intersection (both must grant access)

## Demo

Run the demo script to see various evaluation scenarios:

```bash
cargo build --release
./examples/demo.sh
```

The demo covers 14 scenarios including:
- Basic identity policy evaluation
- Explicit deny overriding allow
- Permission boundary restrictions
- SCP region restrictions
- Cross-account access
- Anonymous/public bucket access
- MFA requirements
- Session policy restrictions
- VPC endpoint policies
- HTTPS-only bucket policies
- RCP organization restrictions

## License

MIT License - see [LICENSE](LICENSE) for details.
