#!/bin/bash
# AWS Resource Control Policy (RCP) Demo
# Demonstrates RCP evaluation using AWS sample policies

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
FULL_ACCESS_RCP="$TMPDIR/full-access-rcp.json"
ORG_CONFIG="$TMPDIR/org-config.yaml"
PRINCIPAL_CTX="$TMPDIR/principal.json"
REQUEST_CTX="$TMPDIR/request.json"

trap "rm -rf $TMPDIR" EXIT

# Create allow-all identity policy
cat > "$ALLOW_ALL" << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
EOF

# Create full access RCP (required for RCP hierarchy - needs Principal for RCPs)
cat > "$FULL_ACCESS_RCP" << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}
EOF

echo "=== AWS Resource Control Policy (RCP) Demo ==="
echo "Demonstrating RCP evaluation patterns"
echo ""

# -----------------------------------------------------------------------------
# HTTPS-Only Access Enforcement
# -----------------------------------------------------------------------------
echo "--- RCP: HTTPS-Only Access Enforcement ---"
echo "Policy: Deny S3/SQS/SecretsManager/KMS when aws:SecureTransport is false"
echo ""

# Test 1: HTTP access (should be DENIED)
echo "Test 1: S3 GetObject over HTTP (should be DENIED)"
cat > "$ORG_CONFIG" << EOF
rcp_hierarchy:
  root:
    - $FULL_ACCESS_RCP
  ous: []
  account:
    - $FULL_ACCESS_RCP
    - $AWS_SAMPLES/rcp/enforce-https-only.json
EOF

cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/alice"}
EOF

cat > "$REQUEST_CTX" << 'EOF'
{"request": {"secure_transport": false}}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

# Test 2: HTTPS access (should be ALLOWED)
echo "Test 2: S3 GetObject over HTTPS (should be ALLOWED)"
cat > "$REQUEST_CTX" << 'EOF'
{"request": {"secure_transport": true}}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""
echo ""

# -----------------------------------------------------------------------------
# S3 TLS Version Enforcement
# -----------------------------------------------------------------------------
echo "--- RCP: S3 TLS Version Enforcement ---"
echo "Policy: Deny S3 access when s3:TlsVersion < 1.2"
echo ""

cat > "$ORG_CONFIG" << EOF
rcp_hierarchy:
  root:
    - $FULL_ACCESS_RCP
  ous: []
  account:
    - $FULL_ACCESS_RCP
    - $AWS_SAMPLES/rcp/enforce-s3-tls-version.json
EOF

echo "Test 1: S3 access with TLS 1.1 (should be DENIED)"
cat > "$REQUEST_CTX" << 'EOF'
{"custom": {"s3:TlsVersion": "1.1"}}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 2: S3 access with TLS 1.2 (should be ALLOWED)"
cat > "$REQUEST_CTX" << 'EOF'
{"custom": {"s3:TlsVersion": "1.2"}}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""
echo ""

# -----------------------------------------------------------------------------
# Identity Perimeter
# -----------------------------------------------------------------------------
echo "--- RCP: Identity Perimeter ---"
echo "Policy: Deny access from principals outside the organization"
echo ""

cat > "$ORG_CONFIG" << EOF
rcp_hierarchy:
  root:
    - $FULL_ACCESS_RCP
  ous: []
  account:
    - $FULL_ACCESS_RCP
    - $AWS_SAMPLES/rcp/identity-perimeter.json
EOF

echo "Test 1: Access from external org principal (should be DENIED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::999999999999:user/external", "org_id": "o-externalorg", "is_aws_service": false}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --output summary || true
echo ""

echo "Test 2: Access from org principal (should be ALLOWED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/alice", "org_id": "o-testorg123", "is_aws_service": false}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --output summary || true
echo ""

echo "Test 3: Access from AWS service principal (should be ALLOWED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:role/aws-service-role", "is_aws_service": true}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --output summary || true
echo ""
echo ""

echo "=== Demo Complete ==="
