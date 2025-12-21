# AWS Sample Policy Demos

These demo scripts showcase IAM policy evaluation using real-world policy patterns
from official AWS sample repositories.

## Prerequisites

Build the release binary first:

```bash
cargo build --release
```

## Demo Scripts

### data-perimeter-demo.sh

Demonstrates AWS data perimeter controls:
- Resource perimeter: Blocking access to resources outside the organization
- Identity perimeter: Restricting principals to organization members
- Network perimeter: Enforcing VPC endpoint and IP-based access controls

```bash
./examples/aws-samples/data-perimeter-demo.sh
```

### condition-operators-demo.sh

Demonstrates advanced IAM condition operators:
- Null operator: S3 encryption enforcement
- NumericLessThan: KMS deletion window requirements
- BoolIfExists: HTTPS-only access enforcement
- ForAnyValue/ForAllValues: Tag-based access control

```bash
./examples/aws-samples/condition-operators-demo.sh
```

### rcp-demo.sh

Demonstrates Resource Control Policies (RCPs):
- Identity perimeter RCP for organization boundaries
- TLS version enforcement
- OIDC provider restrictions

```bash
./examples/aws-samples/rcp-demo.sh
```

## Policy Sources

All policies are sourced from:
- https://github.com/aws-samples/data-perimeter-policy-examples
- https://github.com/aws-samples/service-control-policy-examples
- https://github.com/aws-samples/resource-control-policy-examples

Licensed under Apache-2.0.
