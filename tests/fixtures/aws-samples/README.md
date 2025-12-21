# AWS Sample Policies

This directory contains policy examples from official AWS sample repositories,
included under the Apache 2.0 license for testing IAM policy evaluation logic.

## Attribution

Policies are sourced from the following repositories:

### 1. data-perimeter-policy-examples

- **Repository**: https://github.com/aws-samples/data-perimeter-policy-examples
- **License**: Apache-2.0
- **Copyright**: Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
- **Description**: Data perimeter policy examples implementing identity, resource, and network perimeters

### 2. service-control-policy-examples

- **Repository**: https://github.com/aws-samples/service-control-policy-examples
- **License**: Apache-2.0
- **Copyright**: Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
- **Description**: Service Control Policy examples for security controls, region restrictions, and governance

### 3. resource-control-policy-examples

- **Repository**: https://github.com/aws-samples/resource-control-policy-examples
- **License**: Apache-2.0
- **Copyright**: Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
- **Description**: Resource Control Policy examples for S3, KMS, and OIDC provider restrictions

## Modifications

All policies have been modified for testing purposes:

- Simplified to focus on specific condition operators and keys
- Updated placeholder values (account IDs, org IDs, VPC IDs) with test values
- Removed unnecessary statements for focused testing
- Reduced action lists where appropriate

See individual policy files for specific modification notes in the `_attribution` field.

## Directory Structure

```
aws-samples/
├── scp/                              # Service Control Policies (10 policies)
│   ├── data-perimeter-resource.json      # ForAllValues:StringNotEquals
│   ├── data-perimeter-network-vpceorgid.json  # VpceOrgID network perimeter
│   ├── data-perimeter-network-sourcevpc.json  # SourceVpc network perimeter
│   ├── data-perimeter-governance.json    # kms:GrantIsForAWSResource, lambda:FunctionUrlAuthType
│   ├── deny-region-outside-allowed.json  # StringNotEquals, ArnNotLike
│   ├── deny-iam-from-unexpected-networks.json  # NotIpAddressIfExists, BoolIfExists
│   ├── prevent-imdsv1.json               # ec2:MetadataHttpTokens, NumericGreaterThan, NumericLessThan
│   ├── enforce-kms-deletion-window.json  # NumericLessThan (kms:ScheduleKeyDeletionPendingWindowInDays)
│   ├── require-s3-encryption.json        # Null operator (s3:x-amz-server-side-encryption)
│   └── require-mfa-for-iam.json          # BoolIfExists (aws:MultiFactorAuthPresent)
├── rcp/                              # Resource Control Policies (7 policies)
│   ├── identity-perimeter.json           # OIDC, confused deputy protection, Null operator
│   ├── enforce-s3-tls-version.json       # NumericLessThan (s3:TlsVersion)
│   ├── enforce-https-only.json           # BoolIfExists (aws:SecureTransport)
│   ├── restrict-github-oidc.json         # StringNotLikeIfExists, Null (OIDC claims)
│   ├── restrict-kms-grants.json          # kms:GrantIsForAWSResource
│   ├── enforce-s3-presigned-expiry.json  # NumericGreaterThan (s3:signatureAge)
│   └── deny-third-party-s3-access.json   # aws:PrincipalOrgID perimeter
└── vpc-endpoint/                     # VPC Endpoint Policies (1 policy)
    └── default-endpoint-policy.json      # Organization-based VPC endpoint access
```

## Condition Operators Tested

These policies test the following condition operators:

| Operator | Example Policy |
|----------|----------------|
| `StringNotEquals` | deny-region-outside-allowed.json |
| `StringNotEqualsIfExists` | data-perimeter-resource.json |
| `StringNotLikeIfExists` | restrict-github-oidc.json |
| `ArnNotLike` | deny-region-outside-allowed.json |
| `ArnNotLikeIfExists` | data-perimeter-network-vpceorgid.json |
| `ArnLike` | deny-iam-from-unexpected-networks.json |
| `NotIpAddressIfExists` | deny-iam-from-unexpected-networks.json |
| `BoolIfExists` | enforce-https-only.json, require-mfa-for-iam.json |
| `Bool` | data-perimeter-governance.json |
| `NumericLessThan` | enforce-kms-deletion-window.json, enforce-s3-tls-version.json |
| `NumericGreaterThan` | prevent-imdsv1.json, enforce-s3-presigned-expiry.json |
| `Null` | require-s3-encryption.json, restrict-github-oidc.json |
| `ForAllValues:StringNotEquals` | data-perimeter-resource.json |
| `ForAnyValue:StringLike` | data-perimeter-governance.json |

## Condition Keys Tested

| Key | Example Policy |
|-----|----------------|
| `aws:PrincipalOrgID` | identity-perimeter.json, default-endpoint-policy.json |
| `aws:ResourceOrgID` | data-perimeter-resource.json, default-endpoint-policy.json |
| `aws:VpceOrgID` | data-perimeter-network-vpceorgid.json |
| `aws:SourceVpc` | data-perimeter-network-sourcevpc.json |
| `aws:SourceIp` | deny-iam-from-unexpected-networks.json |
| `aws:ViaAWSService` | data-perimeter-network-vpceorgid.json |
| `aws:PrincipalIsAWSService` | identity-perimeter.json |
| `aws:SecureTransport` | enforce-https-only.json |
| `aws:MultiFactorAuthPresent` | require-mfa-for-iam.json |
| `aws:RequestedRegion` | deny-region-outside-allowed.json |
| `aws:PrincipalArn` | deny-iam-from-unexpected-networks.json |
| `aws:PrincipalTag/*` | data-perimeter-resource.json |
| `aws:ResourceTag/*` | identity-perimeter.json |
| `aws:CalledVia` | data-perimeter-resource.json |
| `aws:TagKeys` | data-perimeter-governance.json |
| `aws:SourceOrgID` | identity-perimeter.json |
| `aws:SourceAccount` | identity-perimeter.json |
| `s3:TlsVersion` | enforce-s3-tls-version.json |
| `s3:signatureAge` | enforce-s3-presigned-expiry.json |
| `s3:x-amz-server-side-encryption` | require-s3-encryption.json |
| `kms:ScheduleKeyDeletionPendingWindowInDays` | enforce-kms-deletion-window.json |
| `kms:GrantIsForAWSResource` | data-perimeter-governance.json, restrict-kms-grants.json |
| `ec2:MetadataHttpTokens` | prevent-imdsv1.json |
| `ec2:MetadataHttpPutResponseHopLimit` | prevent-imdsv1.json |
| `ec2:RoleDelivery` | prevent-imdsv1.json |
| `lambda:FunctionUrlAuthType` | data-perimeter-governance.json |
| `ram:RequestedAllowsExternalPrincipals` | data-perimeter-governance.json |
| `token.actions.githubusercontent.com:sub` | restrict-github-oidc.json, identity-perimeter.json |
