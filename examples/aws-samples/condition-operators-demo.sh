#!/bin/bash
# AWS Condition Operators Demo
# Demonstrates advanced IAM condition operators using AWS sample policies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

ANALYZER="$PROJECT_ROOT/target/release/iam-analyzer"
FIXTURES="$PROJECT_ROOT/tests/fixtures"
AWS_SAMPLES="$FIXTURES/aws-samples"

if [ ! -f "$ANALYZER" ]; then
    echo "Error: iam-analyzer binary not found at $ANALYZER"
    echo "Run 'cargo build --release' first"
    exit 1
fi

# Create temporary directory for all temp files
TMPDIR=$(mktemp -d)
ALLOW_ALL="$TMPDIR/allow-all.json"
FULL_ACCESS_SCP="$TMPDIR/full-access-scp.json"
ORG_CONFIG="$TMPDIR/org-config.yaml"
PRINCIPAL_CTX="$TMPDIR/principal.json"
REQUEST_CTX="$TMPDIR/request.json"

trap "rm -rf $TMPDIR" EXIT

# Create allow-all identity policy
cat > "$ALLOW_ALL" << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF

# Create full access SCP (required for SCP hierarchy at each level)
cat > "$FULL_ACCESS_SCP" << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF

# Create default principal context
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/alice"}
EOF

echo "=== AWS Condition Operators Demo ==="
echo "Demonstrating advanced IAM condition operators"
echo ""

# -----------------------------------------------------------------------------
# Null Operator: S3 Encryption Required
# -----------------------------------------------------------------------------
echo "--- Null Operator: S3 Encryption Required ---"
echo "Policy: Deny s3:PutObject when encryption header is missing (Null:true)"
echo ""

cat > "$ORG_CONFIG" << EOF
scp_hierarchy:
  root:
    - $FULL_ACCESS_SCP
  ous: []
  account:
    - $FULL_ACCESS_SCP
    - $AWS_SAMPLES/scp/require-s3-encryption.json
EOF

echo "Test 1: PutObject WITHOUT encryption header (should be DENIED)"
cat > "$REQUEST_CTX" << 'EOF'
{}
EOF

$ANALYZER -a s3:PutObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 2: PutObject WITH encryption header (should be ALLOWED)"
cat > "$REQUEST_CTX" << 'EOF'
{"custom": {"s3:x-amz-server-side-encryption": "AES256"}}
EOF

$ANALYZER -a s3:PutObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""
echo ""

# -----------------------------------------------------------------------------
# NumericLessThan: KMS Deletion Window
# -----------------------------------------------------------------------------
echo "--- NumericLessThan: KMS Deletion Window ---"
echo "Policy: Deny kms:ScheduleKeyDeletion with less than 30 days window"
echo ""

cat > "$ORG_CONFIG" << EOF
scp_hierarchy:
  root:
    - $FULL_ACCESS_SCP
  ous: []
  account:
    - $FULL_ACCESS_SCP
    - $AWS_SAMPLES/scp/enforce-kms-deletion-window.json
EOF

echo "Test 1: Schedule deletion with 7-day window (should be DENIED)"
cat > "$REQUEST_CTX" << 'EOF'
{"custom": {"kms:ScheduleKeyDeletionPendingWindowInDays": "7"}}
EOF

$ANALYZER -a kms:ScheduleKeyDeletion \
    -r arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 2: Schedule deletion with 30-day window (should be ALLOWED)"
cat > "$REQUEST_CTX" << 'EOF'
{"custom": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"}}
EOF

$ANALYZER -a kms:ScheduleKeyDeletion \
    -r arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""
echo ""

# -----------------------------------------------------------------------------
# BoolIfExists: MFA Required for IAM Actions
# -----------------------------------------------------------------------------
echo "--- BoolIfExists: MFA Required for IAM Actions ---"
echo "Policy: Deny IAM write actions when aws:MultiFactorAuthPresent is false"
echo ""

cat > "$ORG_CONFIG" << EOF
scp_hierarchy:
  root:
    - $FULL_ACCESS_SCP
  ous: []
  account:
    - $FULL_ACCESS_SCP
    - $AWS_SAMPLES/scp/require-mfa-for-iam.json
EOF

echo "Test 1: CreateUser WITHOUT MFA (should be DENIED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/admin"}
EOF
cat > "$REQUEST_CTX" << 'EOF'
{"session": {"mfa_present": false}}
EOF

$ANALYZER -a iam:CreateUser -r arn:aws:iam::123456789012:user/newuser \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 2: CreateUser WITH MFA (should be ALLOWED)"
cat > "$REQUEST_CTX" << 'EOF'
{"session": {"mfa_present": true}}
EOF

$ANALYZER -a iam:CreateUser -r arn:aws:iam::123456789012:user/newuser \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""
echo ""

# -----------------------------------------------------------------------------
# EC2 IMDSv2 Requirement
# -----------------------------------------------------------------------------
echo "--- Service-Specific Conditions: EC2 IMDSv2 Required ---"
echo "Policy: Deny ec2:RunInstances unless ec2:MetadataHttpTokens is 'required'"
echo ""

cat > "$ORG_CONFIG" << EOF
scp_hierarchy:
  root:
    - $FULL_ACCESS_SCP
  ous: []
  account:
    - $FULL_ACCESS_SCP
    - $AWS_SAMPLES/scp/prevent-imdsv1.json
EOF

echo "Test 1: RunInstances with optional tokens (should be DENIED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/developer"}
EOF
cat > "$REQUEST_CTX" << 'EOF'
{"custom": {"ec2:MetadataHttpTokens": "optional"}}
EOF

$ANALYZER -a ec2:RunInstances \
    -r "arn:aws:ec2:us-east-1:123456789012:instance/*" \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 2: RunInstances with required tokens (should be ALLOWED)"
cat > "$REQUEST_CTX" << 'EOF'
{"custom": {"ec2:MetadataHttpTokens": "required"}}
EOF

$ANALYZER -a ec2:RunInstances \
    -r "arn:aws:ec2:us-east-1:123456789012:instance/*" \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""
echo ""

echo "=== Demo Complete ==="
