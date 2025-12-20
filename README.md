# IAM Analyzer

[![CI](https://github.com/jplock/iam-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/jplock/iam-analyzer/actions/workflows/ci.yml)
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

```bash
iam-analyzer -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i policy.json \
    -p arn:aws:iam::123456789012:user/alice \
    -A 123456789012
```

### Cross-Account S3 Access

```bash
iam-analyzer -a s3:GetObject -r arn:aws:s3:::their-bucket/file.txt \
    -i identity.json -R bucket-policy.json \
    -p arn:aws:iam::111111111111:user/alice \
    -A 111111111111 --resource-account 222222222222 \
    --cross-account
```

### With SCP Region Restrictions

```bash
iam-analyzer -a ec2:RunInstances -r "arn:aws:ec2:eu-west-1:123456789012:instance/*" \
    -i policy.json --scp-root scp.json \
    -p arn:aws:iam::123456789012:user/dev \
    -A 123456789012 \
    --requested-region eu-west-1
```

### With MFA Requirement

```bash
iam-analyzer -a ec2:TerminateInstances -r "arn:aws:ec2:*:*:instance/*" \
    -i policy.json \
    -p arn:aws:iam::123456789012:user/admin \
    -A 123456789012 \
    --mfa-present
```

### Script-Friendly Output

```bash
iam-analyzer -a s3:GetObject -r arn:aws:s3:::bucket/key \
    -i policy.json \
    -p arn:aws:iam::123456789012:user/alice \
    -A 123456789012 \
    -o quiet
# Outputs: ALLOW, EXPLICIT_DENY, or IMPLICIT_DENY
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
| `--scp-root` | SCP at organization root level |
| `--scp-ou` | SCP at OU level (ordered from root to account) |
| `--scp-account` | SCP at account level |
| `--rcp-root` | RCP at organization root level |
| `--rcp-ou` | RCP at OU level |
| `--rcp-account` | RCP at account level |

### Context

| Flag | Description |
|------|-------------|
| `-p, --principal-arn` | Principal ARN making the request |
| `-A, --principal-account` | Account ID of the principal |
| `--resource-account` | Account ID that owns the resource |
| `--cross-account` | Treat as cross-account request |
| `--mfa-present` | MFA was used for authentication |
| `--requested-region` | The AWS region being requested |
| `-C, --context` | Context key-value pairs (KEY=VALUE format) |

### Output Formats

| Flag | Description |
|------|-------------|
| `-o text` | Human-readable output with full reasoning (default) |
| `-o summary` | Concise decision, policy type, and reason |
| `-o json` | Structured JSON for programmatic use |
| `-o quiet` | Just the decision word |

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

Service-specific condition keys can be set via `-C KEY=VALUE` or `--context KEY=VALUE`.

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

## License

MIT License - see [LICENSE](LICENSE) for details.
