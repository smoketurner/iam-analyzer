#!/bin/bash
# IAM Analyzer Demo Script
# Demonstrates evaluation of all policy types using test fixtures

set -e

# Determine script location and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ANALYZER="$PROJECT_ROOT/target/release/iam-analyzer"
FIXTURES="$PROJECT_ROOT/tests/fixtures"

# Check if binary exists
if [ ! -f "$ANALYZER" ]; then
    echo "Error: iam-analyzer binary not found at $ANALYZER"
    echo "Run 'cargo build --release' first"
    exit 1
fi

echo "=== IAM Analyzer Demo ==="
echo "Demonstrating AWS IAM policy evaluation across all policy types"
echo ""

# -----------------------------------------------------------------------------
# Scenario 1: Basic identity policy
# -----------------------------------------------------------------------------
echo "--- Scenario 1: Identity Policy Allows S3 Access ---"
echo "Testing: User 'alice' with identity policy allowing s3:Get* and s3:List*"
echo "(principal account auto-detected from ARN)"
echo ""
$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$FIXTURES/identity/allow-s3-read.json" \
    -p arn:aws:iam::123456789012:user/alice
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 2: Explicit deny overrides allow
# -----------------------------------------------------------------------------
echo "--- Scenario 2: Explicit Deny Overrides Allow ---"
echo "Testing: User has s3:* allow, but explicit deny on s3:Delete*"
echo ""
$ANALYZER -a s3:DeleteObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$FIXTURES/identity/allow-s3-full.json" \
    -i "$FIXTURES/identity/deny-s3-delete.json" \
    -p arn:aws:iam::123456789012:user/alice
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 3: Permission boundary blocks out-of-scope action
# -----------------------------------------------------------------------------
echo "--- Scenario 3: Permission Boundary Restricts Access ---"
echo "Testing: User has full S3 allow, but boundary limits to S3/CloudWatch/EC2"
echo "Action: iam:CreateUser (outside boundary scope)"
echo ""
$ANALYZER -a iam:CreateUser -r arn:aws:iam::123456789012:user/newuser \
    -i "$FIXTURES/identity/allow-s3-full.json" \
    --permission-boundary "$FIXTURES/boundaries/s3-cloudwatch-ec2-only.json" \
    -p arn:aws:iam::123456789012:user/admin
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 4: SCP blocks action outside allowed region
# -----------------------------------------------------------------------------
echo "--- Scenario 4: SCP Blocks Non-US Region ---"
echo "Testing: User can run EC2, but SCP denies outside us-east-1, us-west-2"
echo "Region: ap-southeast-1 (blocked, auto-detected from resource ARN)"
echo "(using --organization-config for SCP hierarchy)"
echo ""
$ANALYZER -a ec2:RunInstances -r "arn:aws:ec2:ap-southeast-1:123456789012:instance/*" \
    -i "$FIXTURES/identity/allow-ec2-full.json" \
    --organization-config "$FIXTURES/organization/region-restriction.yaml" \
    -p arn:aws:iam::123456789012:user/developer
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 5: SCP allows action in permitted region
# -----------------------------------------------------------------------------
echo "--- Scenario 5: SCP Allows US Region ---"
echo "Testing: Same setup, but in us-east-1 (allowed, auto-detected from resource ARN)"
echo ""
$ANALYZER -a ec2:RunInstances -r "arn:aws:ec2:us-east-1:123456789012:instance/*" \
    -i "$FIXTURES/identity/allow-ec2-full.json" \
    --organization-config "$FIXTURES/organization/region-restriction.yaml" \
    -p arn:aws:iam::123456789012:user/developer
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 6: Cross-account access with both policies
# -----------------------------------------------------------------------------
echo "--- Scenario 6: Cross-Account S3 Access (Allowed) ---"
echo "Testing: User from account 111111111111 accessing bucket in 222222222222"
echo "Both identity and resource policies allow"
echo "(cross-account auto-detected when accounts differ)"
echo ""
$ANALYZER -a s3:GetObject -r arn:aws:s3:::shared-bucket/file.txt \
    -i "$FIXTURES/identity/allow-s3-read.json" \
    -R "$FIXTURES/resource/s3-bucket-cross-account.json" \
    -p arn:aws:iam::111111111111:user/external-user \
    --resource-account 222222222222
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 7: Anonymous request to public bucket
# -----------------------------------------------------------------------------
echo "--- Scenario 7: Anonymous Access to Public Bucket ---"
echo "Testing: No principal context, bucket policy allows Principal: \"*\""
echo ""
$ANALYZER -a s3:GetObject -r arn:aws:s3:::public-bucket/readme.txt \
    -R "$FIXTURES/resource/s3-bucket-public-read.json"
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 8: MFA required but not present
# -----------------------------------------------------------------------------
echo "--- Scenario 8: MFA Required for EC2 Terminate (No MFA) ---"
echo "Testing: SCP requires MFA for ec2:TerminateInstances, MFA not present"
echo "(using --organization-config for SCP hierarchy)"
echo ""
$ANALYZER -a ec2:TerminateInstances -r "arn:aws:ec2:us-east-1:123456789012:instance/i-12345" \
    -i "$FIXTURES/identity/allow-ec2-full.json" \
    --organization-config "$FIXTURES/organization/mfa-required.yaml" \
    -p arn:aws:iam::123456789012:user/admin
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 9: MFA required and present
# -----------------------------------------------------------------------------
echo "--- Scenario 9: MFA Required for EC2 Terminate (MFA Present) ---"
echo "Testing: Same setup, but with --mfa-present flag"
echo ""
$ANALYZER -a ec2:TerminateInstances -r "arn:aws:ec2:us-east-1:123456789012:instance/i-12345" \
    -i "$FIXTURES/identity/allow-ec2-full.json" \
    --organization-config "$FIXTURES/organization/mfa-required.yaml" \
    -p arn:aws:iam::123456789012:user/admin \
    --mfa-present
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 10: Session policy restricts federated user
# -----------------------------------------------------------------------------
echo "--- Scenario 10: Session Policy Restricts Access ---"
echo "Testing: Assumed role with read-only session policy blocks PutObject"
echo ""
$ANALYZER -a s3:PutObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$FIXTURES/identity/allow-s3-full.json" \
    --session-policy "$FIXTURES/session/read-only-session.json" \
    -p arn:aws:sts::123456789012:assumed-role/AdminRole/session
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 11: VPC endpoint policy blocks non-S3 services
# -----------------------------------------------------------------------------
echo "--- Scenario 11: VPC Endpoint Policy ---"
echo "Testing: VPC endpoint allows only S3 read, trying DynamoDB"
echo ""
$ANALYZER -a dynamodb:GetItem -r arn:aws:dynamodb:us-east-1:123456789012:table/Users \
    -i "$FIXTURES/identity/allow-dynamodb-read.json" \
    --vpc-endpoint-policy "$FIXTURES/vpc-endpoint/s3-read-only.json" \
    -p arn:aws:iam::123456789012:user/alice
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 12: Resource policy requires HTTPS
# -----------------------------------------------------------------------------
echo "--- Scenario 12: Resource Policy Requires HTTPS ---"
echo "Testing: Bucket policy denies non-HTTPS requests (aws:SecureTransport = false)"
echo ""
$ANALYZER -a s3:GetObject -r arn:aws:s3:::secure-bucket/file.txt \
    -i "$FIXTURES/identity/allow-s3-read.json" \
    -R "$FIXTURES/resource/s3-bucket-https-only.json" \
    -p arn:aws:iam::123456789012:user/alice \
    -c "aws:SecureTransport=false"
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 13: Resource policy requires HTTPS (compliant)
# -----------------------------------------------------------------------------
echo "--- Scenario 13: Resource Policy Requires HTTPS (Compliant) ---"
echo "Testing: Same bucket, but with aws:SecureTransport = true"
echo ""
$ANALYZER -a s3:GetObject -r arn:aws:s3:::secure-bucket/file.txt \
    -i "$FIXTURES/identity/allow-s3-read.json" \
    -R "$FIXTURES/resource/s3-bucket-https-only.json" \
    -p arn:aws:iam::123456789012:user/alice \
    -c "aws:SecureTransport=true"
echo ""
echo ""

# -----------------------------------------------------------------------------
# Scenario 14: RCP restricts S3 to organization
# -----------------------------------------------------------------------------
echo "--- Scenario 14: RCP Restricts S3 to Organization ---"
echo "Testing: RCP requires principal from org o-exampleorg"
echo "Principal without org ID (should be denied)"
echo "(using --organization-config for RCP hierarchy)"
echo ""
$ANALYZER -a s3:GetObject -r arn:aws:s3:::org-bucket/file.txt \
    -i "$FIXTURES/identity/allow-s3-read.json" \
    --organization-config "$FIXTURES/organization/rcp-org-only.yaml" \
    -p arn:aws:iam::123456789012:user/alice
echo ""
echo ""

# -----------------------------------------------------------------------------
# Quiet mode demo
# -----------------------------------------------------------------------------
echo "--- Bonus: Quiet Mode for Scripts ---"
echo "Using -o quiet for script-friendly output:"
echo ""
echo -n "Allow case: "
$ANALYZER -a s3:GetObject -r arn:aws:s3:::bucket/key \
    -i "$FIXTURES/identity/allow-s3-read.json" \
    -p arn:aws:iam::123456789012:user/alice \
    -o quiet

echo -n "Explicit deny case: "
$ANALYZER -a s3:DeleteObject -r arn:aws:s3:::bucket/key \
    -i "$FIXTURES/identity/deny-s3-delete.json" \
    -p arn:aws:iam::123456789012:user/alice \
    -o quiet

echo -n "Implicit deny case: "
$ANALYZER -a iam:CreateUser -r arn:aws:iam::123456789012:user/newuser \
    -i "$FIXTURES/identity/allow-s3-read.json" \
    -p arn:aws:iam::123456789012:user/alice \
    -o quiet
echo ""

echo "=== Demo Complete ==="
