#!/bin/bash
# AWS Data Perimeter Demo
# Demonstrates data perimeter controls using AWS sample policies

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
FULL_ACCESS_RCP="$TMPDIR/full-access-rcp.json"
ORG_CONFIG="$TMPDIR/org-config.yaml"
PRINCIPAL_CTX="$TMPDIR/principal.json"
RESOURCE_CTX="$TMPDIR/resource.json"
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

# Create full access RCP (required for RCP hierarchy - needs Principal for RCPs)
cat > "$FULL_ACCESS_RCP" << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}
EOF

echo "=== AWS Data Perimeter Demo ==="
echo "Demonstrating identity, network, and resource perimeter controls"
echo ""

# -----------------------------------------------------------------------------
# Identity Perimeter: Organization Boundary (RCP)
# -----------------------------------------------------------------------------
echo "--- Identity Perimeter: Organization Boundary ---"
echo "Policy: Deny access from principals outside the organization"
echo "(RCP: identity-perimeter.json)"
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

# -----------------------------------------------------------------------------
# Network Perimeter: IP-Based Access Control (SCP)
# -----------------------------------------------------------------------------
echo "--- Network Perimeter: IP-Based Access Control ---"
echo "Policy: Deny access from IPs outside corporate range"
echo "(SCP: data-perimeter-network-vpceorgid.json)"
echo ""

cat > "$ORG_CONFIG" << EOF
scp_hierarchy:
  root:
    - $FULL_ACCESS_SCP
  ous: []
  account:
    - $FULL_ACCESS_SCP
    - $AWS_SAMPLES/scp/data-perimeter-network-vpceorgid.json
EOF

echo "Test 1: Access from corporate IP (should be ALLOWED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/alice", "tags": {"dp:include:network": "true"}}
EOF
cat > "$REQUEST_CTX" << 'EOF'
{"network": {"source_ip": "10.1.2.3"}, "request": {"via_aws_service": false}}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 2: Access from external IP (should be DENIED)"
cat > "$REQUEST_CTX" << 'EOF'
{"network": {"source_ip": "203.0.113.50"}, "request": {"via_aws_service": false}}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 3: Access via AWS service (should be ALLOWED)"
echo "When request comes through an AWS service, network perimeter allows it"
cat > "$REQUEST_CTX" << 'EOF'
{"network": {"source_ip": "203.0.113.50"}, "request": {"via_aws_service": true}}
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
# Region Restriction
# -----------------------------------------------------------------------------
echo "--- Region Restriction ---"
echo "Policy: Deny actions outside allowed regions (us-east-1, us-west-2)"
echo "(SCP: deny-region-outside-allowed.json)"
echo ""

cat > "$ORG_CONFIG" << EOF
scp_hierarchy:
  root:
    - $FULL_ACCESS_SCP
  ous: []
  account:
    - $FULL_ACCESS_SCP
    - $AWS_SAMPLES/scp/deny-region-outside-allowed.json
EOF

cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/developer"}
EOF

echo "Test 1: EC2 in eu-west-1 (should be DENIED)"
cat > "$REQUEST_CTX" << 'EOF'
{"request": {"region": "eu-west-1"}}
EOF

$ANALYZER -a ec2:RunInstances \
    -r "arn:aws:ec2:eu-west-1:123456789012:instance/*" \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 2: EC2 in us-east-1 (should be ALLOWED)"
cat > "$REQUEST_CTX" << 'EOF'
{"request": {"region": "us-east-1"}}
EOF

$ANALYZER -a ec2:RunInstances \
    -r "arn:aws:ec2:us-east-1:123456789012:instance/*" \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""

echo "Test 3: IAM in eu-west-1 (should be ALLOWED - exempt via NotAction)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/admin"}
EOF
cat > "$REQUEST_CTX" << 'EOF'
{"request": {"region": "eu-west-1"}}
EOF

$ANALYZER -a iam:CreateRole \
    -r arn:aws:iam::123456789012:role/myrole \
    -i "$ALLOW_ALL" \
    --organization-config "$ORG_CONFIG" \
    --principal-context "$PRINCIPAL_CTX" \
    --request-context "$REQUEST_CTX" \
    --output summary || true
echo ""
echo ""

# -----------------------------------------------------------------------------
# VPC Endpoint Policy: Organization Boundary
# -----------------------------------------------------------------------------
echo "--- VPC Endpoint Policy: Organization Boundary ---"
echo "Policy: Only allow org principals to access org resources"
echo "(VPC Endpoint: default-endpoint-policy.json)"
echo ""

echo "Test 1: Org principal accessing org resource (should be ALLOWED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/alice", "org_id": "o-testorg123"}
EOF
cat > "$RESOURCE_CTX" << 'EOF'
{"org_id": "o-testorg123"}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --vpc-endpoint-policy "$AWS_SAMPLES/vpc-endpoint/default-endpoint-policy.json" \
    --principal-context "$PRINCIPAL_CTX" \
    --resource-context "$RESOURCE_CTX" \
    --output summary || true
echo ""

echo "Test 2: Org principal accessing external resource (should be DENIED)"
cat > "$RESOURCE_CTX" << 'EOF'
{"org_id": "o-externalorg"}
EOF
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:user/alice", "org_id": "o-testorg123", "is_aws_service": false}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::external-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --vpc-endpoint-policy "$AWS_SAMPLES/vpc-endpoint/default-endpoint-policy.json" \
    --principal-context "$PRINCIPAL_CTX" \
    --resource-context "$RESOURCE_CTX" \
    --output summary || true
echo ""

echo "Test 3: AWS service principal (should be ALLOWED)"
cat > "$PRINCIPAL_CTX" << 'EOF'
{"arn": "arn:aws:iam::123456789012:role/aws-service-role", "is_aws_service": true}
EOF

$ANALYZER -a s3:GetObject -r arn:aws:s3:::my-bucket/file.txt \
    -i "$ALLOW_ALL" \
    --vpc-endpoint-policy "$AWS_SAMPLES/vpc-endpoint/default-endpoint-policy.json" \
    --principal-context "$PRINCIPAL_CTX" \
    --output summary || true
echo ""
echo ""

echo "=== Demo Complete ==="
