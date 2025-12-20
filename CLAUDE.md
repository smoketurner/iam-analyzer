# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IAM Analyzer is a Rust CLI tool and library for evaluating AWS IAM policies. It implements the exact AWS IAM policy evaluation logic, supporting all policy types: SCPs, RCPs, VPC endpoint policies, identity-based policies, resource-based policies, permission boundaries, and session policies.

## Build Commands

```bash
# Build (debug)
cargo build

# Build (release)
cargo build --release

# Run tests
cargo test

# Run a single test
cargo test test_name

# Run tests with output
cargo test -- --nocapture

# Run the CLI (after building release)
./target/release/iam-analyzer --help
```

## Architecture

### Core Modules

- **`src/eval/`** - Policy evaluation engine (the heart of the project)
  - `engine.rs` - Main `EvaluationEngine` implementing AWS IAM evaluation flow
  - `context.rs` - `RequestContext` builder for constructing evaluation requests
  - `context_bags.rs` - AWS-style context bags for condition key storage
  - `condition_eval.rs` - Condition operator evaluation (StringEquals, IpAddress, etc.)
  - `matchers.rs` - Statement matching logic (action, resource, principal)
  - `hierarchy.rs` - SCP/RCP hierarchy evaluation
  - `decision.rs` - `Decision` enum (Allow, ExplicitDeny, ImplicitDeny) and reasoning
  - `variables.rs` - Policy variable resolution (e.g., `${aws:username}`)

- **`src/policy/`** - IAM policy parsing and AST
  - `ast.rs` - Policy document types (Policy, Statement, Effect, PrincipalBlock, etc.)
  - `action.rs` - Action pattern matching
  - `validation.rs` - Policy validation (validates on every load)

- **`src/arn/`** - ARN parsing and pattern matching
  - `arn.rs` - `Arn` struct for parsed ARNs
  - `pattern.rs` - `ArnPattern` for wildcard matching

- **`src/cli/`** - CLI implementation
  - `args.rs` - Clap argument definitions
  - `mod.rs` - CLI execution, policy loading, context building

### Evaluation Flow

The engine follows AWS IAM evaluation order (see `engine.rs:86`):
1. Check explicit deny in ALL policies
2. Check SCP hierarchy (every level must allow)
3. Check RCP hierarchy (every level must allow)
4. Check VPC endpoint policy
5. Check permission boundaries
6. Check session policies
7. Check identity + resource policies (union for same-account, intersection for cross-account)

### Key Types

- `EvaluationEngine` - Stateless engine that evaluates requests against policies
- `PolicySet` - Collection of all policy types for evaluation
- `RequestContext` - Request details (action, resource, principal, conditions)
- `NamedPolicy` - Policy with its source name for debugging
- `OrganizationHierarchy` - SCP/RCP structure (root → OUs → account)

### Context Bags Architecture

The condition key storage follows AWS's internal "context bags" model. Each bag stores condition keys for a specific scope:

- **`PrincipalContext`** (11 keys) - `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:PrincipalTag/*`, `aws:PrincipalType`, `aws:userid`, `aws:username`, `aws:PrincipalIsAWSService`, `aws:PrincipalServiceName`, `aws:PrincipalServiceNamesList`
- **`ResourceContext`** (4 keys) - `aws:ResourceAccount`, `aws:ResourceOrgID`, `aws:ResourceOrgPaths`, `aws:ResourceTag/*`
- **`NetworkContext`** (8 keys) - `aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpcArn`, `aws:SourceVpce`, `aws:VpcSourceIp`, `aws:VpceAccount`, `aws:VpceOrgID`, `aws:VpceOrgPaths`
- **`SessionContext`** (9 keys) - `aws:MultiFactorAuthPresent`, `aws:MultiFactorAuthAge`, `aws:TokenIssueTime`, `aws:SourceIdentity`, `aws:FederatedProvider`, `aws:AssumedRoot`, `aws:ChatbotSourceArn`, `aws:Ec2InstanceSourceVpc`, `aws:Ec2InstanceSourcePrivateIPv4`
- **`RequestBag`** (17 keys) - `aws:RequestTag/*`, `aws:TagKeys`, `aws:CalledVia`, `aws:CalledViaFirst`, `aws:CalledViaLast`, `aws:ViaAWSService`, `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID`, `aws:SourceOrgPaths`, `aws:RequestedRegion`, `aws:SecureTransport`, `aws:CurrentTime`, `aws:EpochTime`, `aws:referer`, `aws:UserAgent`, `aws:IsMcpServiceAction`

The `ConditionValue` enum preserves type semantics:
- `String(String)` - Single string value
- `StringList(Vec<String>)` - Multi-valued keys like `aws:CalledVia`
- `Bool(bool)` - Boolean keys like `aws:SecureTransport`
- `Integer(i64)` - Numeric keys like `aws:MultiFactorAuthAge`
- `DateTime(String)` - ISO 8601 timestamps
- `IpAddress(String)` - IP addresses for validation

Adding a new condition key only requires calling the appropriate builder method (e.g., `.source_ip("10.0.0.1")`), which populates the correct bag. The unified lookup via `RequestContext::get_condition_value()` routes to the appropriate bag based on the key prefix.

### Auto-Detection Features

The `RequestContext` builder automatically detects:
- **Resource account** - Parsed from resource ARN when in standard format
- **Cross-account** - Detected when principal and resource accounts differ
- **Service-linked role** - Detected from principal ARN pattern (`role/aws-service-role/*`)

### Output Formats

- `--output text` (default) - Full reasoning chain with all evaluation steps
- `--output summary` - Concise output: decision, policy type, and reason
- `--output json` - Structured JSON for programmatic consumption
- `--output quiet` - Just the decision (ALLOW, EXPLICIT_DENY, IMPLICIT_DENY)

### Condition Operators

The `ConditionEvaluator` in `condition_eval.rs` implements all AWS condition operators:
- String: StringEquals, StringLike, StringNotEquals, etc.
- Numeric: NumericEquals, NumericLessThan, etc.
- Date: DateEquals, DateLessThan, etc.
- IP: IpAddress, NotIpAddress
- ARN: ArnEquals, ArnLike, ArnNotEquals, ArnNotLike
- Set operators: ForAllValues, ForAnyValue
- Modifiers: IfExists

Negated operators (StringNotEquals, NotIpAddress, etc.) use NOR logic for multiple values - all policy values must pass for the condition to match.

### Supported Global Condition Keys (49 keys)

The following AWS global condition keys are supported via `RequestContext` builder methods:

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

Service-specific condition keys (e.g., `iam:PassedToService`, `sts:ExternalId`) can be set via the generic context key mechanism (`--context KEY=VALUE`).

## Testing

Tests are in two locations:
- Unit tests in each module (e.g., `engine.rs` has inline tests)
- Integration tests in `tests/integration_tests.rs` using fixtures from `tests/fixtures/`

Fixtures are organized by policy type:
- `tests/fixtures/identity/` - Identity-based policies
- `tests/fixtures/resource/` - Resource-based policies (bucket policies, trust policies)
- `tests/fixtures/scp/` - Service Control Policies
- `tests/fixtures/rcp/` - Resource Control Policies
- `tests/fixtures/boundaries/` - Permission boundaries
- `tests/fixtures/session/` - Session policies
- `tests/fixtures/vpc-endpoint/` - VPC endpoint policies
- `tests/fixtures/conditions/` - Condition operator test cases

## Demo Script

`examples/demo.sh` demonstrates various evaluation scenarios. Requires release build first:
```bash
cargo build --release
./examples/demo.sh
```
