//! Context file definitions for loading request context from JSON files.
//!
//! This module provides struct definitions for loading principal, resource,
//! and request context from JSON files. The format uses human-readable field
//! names that map to AWS global condition keys.

use serde::Deserialize;
use std::collections::HashMap;

/// Principal context file format.
///
/// Maps to AWS global condition keys for principal (identity) context:
/// - `aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalOrgID`
/// - `aws:PrincipalOrgPaths`, `aws:PrincipalTag/*`
/// - `aws:PrincipalType`, `aws:PrincipalIsAWSService`
/// - `aws:PrincipalServiceName`, `aws:PrincipalServiceNamesList`
/// - `aws:userid`, `aws:username`
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct PrincipalContextFile {
    /// Principal ARN (aws:PrincipalArn)
    pub arn: Option<String>,

    /// Principal account ID (aws:PrincipalAccount)
    pub account: Option<String>,

    /// Organization ID (aws:PrincipalOrgID)
    pub org_id: Option<String>,

    /// Organization paths (aws:PrincipalOrgPaths)
    pub org_paths: Option<Vec<String>>,

    /// Principal's unique identifier (aws:userid)
    pub userid: Option<String>,

    /// Principal's username (aws:username)
    pub username: Option<String>,

    /// Principal type (aws:PrincipalType)
    /// Values: Account, User, FederatedUser, AssumedRole, Root, etc.
    pub principal_type: Option<String>,

    /// Whether principal is an AWS service (aws:PrincipalIsAWSService)
    pub is_aws_service: Option<bool>,

    /// AWS service name if principal is a service (aws:PrincipalServiceName)
    pub service_name: Option<String>,

    /// List of AWS service names (aws:PrincipalServiceNamesList)
    pub service_names_list: Option<Vec<String>>,

    /// Whether principal is from management account (bypasses SCPs)
    pub is_management_account: Option<bool>,

    /// Principal tags (aws:PrincipalTag/*)
    pub tags: Option<HashMap<String, String>>,
}

/// Resource context file format.
///
/// Maps to AWS global condition keys for resource context:
/// - `aws:ResourceAccount`, `aws:ResourceOrgID`, `aws:ResourceOrgPaths`
/// - `aws:ResourceTag/*`
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ResourceContextFile {
    /// Resource account ID (aws:ResourceAccount)
    pub account: Option<String>,

    /// Resource organization ID (aws:ResourceOrgID)
    pub org_id: Option<String>,

    /// Resource organization paths (aws:ResourceOrgPaths)
    pub org_paths: Option<Vec<String>>,

    /// Resource tags (aws:ResourceTag/*)
    pub tags: Option<HashMap<String, String>>,
}

/// Request context file format.
///
/// Contains network, session, and request context sections that map to
/// AWS global condition keys.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RequestContextFile {
    /// Network context
    pub network: Option<NetworkContext>,

    /// Session context (role session properties)
    pub session: Option<SessionContext>,

    /// Request context (request properties)
    pub request: Option<RequestContext>,

    /// Custom/service-specific condition keys
    /// Use this for keys like `iam:PassedToService`, `sts:ExternalId`, etc.
    pub custom: Option<HashMap<String, serde_json::Value>>,
}

/// Network context section.
///
/// Maps to AWS global condition keys for network properties:
/// - `aws:SourceIp`, `aws:SourceVpc`, `aws:SourceVpcArn`, `aws:SourceVpce`
/// - `aws:VpcSourceIp`, `aws:VpceAccount`, `aws:VpceOrgID`, `aws:VpceOrgPaths`
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct NetworkContext {
    /// Source IP address (aws:SourceIp)
    pub source_ip: Option<String>,

    /// Source VPC ID (aws:SourceVpc)
    pub source_vpc: Option<String>,

    /// Source VPC ARN (aws:SourceVpcArn)
    pub source_vpc_arn: Option<String>,

    /// Source VPC endpoint ID (aws:SourceVpce)
    pub source_vpce: Option<String>,

    /// VPC source IP (aws:VpcSourceIp)
    /// IP address when request comes from VPC endpoint
    pub vpc_source_ip: Option<String>,

    /// VPC endpoint account (aws:VpceAccount)
    pub vpce_account: Option<String>,

    /// VPC endpoint organization ID (aws:VpceOrgID)
    pub vpce_org_id: Option<String>,

    /// VPC endpoint organization paths (aws:VpceOrgPaths)
    pub vpce_org_paths: Option<Vec<String>>,
}

/// Session context section.
///
/// Maps to AWS global condition keys for role session properties:
/// - `aws:MultiFactorAuthPresent`, `aws:MultiFactorAuthAge`
/// - `aws:TokenIssueTime`, `aws:SourceIdentity`, `aws:FederatedProvider`
/// - `aws:AssumedRoot`, `aws:ChatbotSourceArn`
/// - `aws:Ec2InstanceSourceVpc`, `aws:Ec2InstanceSourcePrivateIPv4`
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SessionContext {
    /// Whether MFA was used (aws:MultiFactorAuthPresent)
    pub mfa_present: Option<bool>,

    /// Age of MFA in seconds (aws:MultiFactorAuthAge)
    pub mfa_auth_age: Option<i64>,

    /// Token issue time in ISO 8601 format (aws:TokenIssueTime)
    pub token_issue_time: Option<String>,

    /// Source identity (aws:SourceIdentity)
    pub source_identity: Option<String>,

    /// Federated provider ARN (aws:FederatedProvider)
    pub federated_provider: Option<String>,

    /// Whether session is from an assumed root session (aws:AssumedRoot)
    pub assumed_root: Option<bool>,

    /// Chatbot source ARN (aws:ChatbotSourceArn)
    pub chatbot_source_arn: Option<String>,

    /// EC2 instance source VPC (aws:Ec2InstanceSourceVpc)
    pub ec2_instance_source_vpc: Option<String>,

    /// EC2 instance source private IPv4 (aws:Ec2InstanceSourcePrivateIPv4)
    pub ec2_instance_source_private_ipv4: Option<String>,
}

/// Request context section.
///
/// Maps to AWS global condition keys for request properties:
/// - `aws:RequestedRegion`, `aws:SecureTransport`, `aws:ViaAWSService`
/// - `aws:CalledVia`, `aws:CalledViaFirst`, `aws:CalledViaLast`
/// - `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID`, `aws:SourceOrgPaths`
/// - `aws:CurrentTime`, `aws:EpochTime`, `aws:referer`, `aws:UserAgent`
/// - `aws:RequestTag/*`, `aws:TagKeys`, `aws:IsMcpServiceAction`
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RequestContext {
    /// Requested region (aws:RequestedRegion)
    pub region: Option<String>,

    /// Whether request uses HTTPS (aws:SecureTransport)
    pub secure_transport: Option<bool>,

    /// Whether request came via AWS service (aws:ViaAWSService)
    pub via_aws_service: Option<bool>,

    /// Services in CalledVia chain (aws:CalledVia)
    pub called_via: Option<Vec<String>>,

    /// Source ARN for service-to-service (aws:SourceArn)
    pub source_arn: Option<String>,

    /// Source account (aws:SourceAccount)
    pub source_account: Option<String>,

    /// Source organization ID (aws:SourceOrgID)
    pub source_org_id: Option<String>,

    /// Source organization paths (aws:SourceOrgPaths)
    pub source_org_paths: Option<Vec<String>>,

    /// Current time in ISO 8601 format (aws:CurrentTime)
    pub current_time: Option<String>,

    /// Epoch time in seconds (aws:EpochTime)
    pub epoch_time: Option<i64>,

    /// HTTP referer header (aws:referer)
    pub referer: Option<String>,

    /// User agent string (aws:UserAgent)
    pub user_agent: Option<String>,

    /// Whether this is an MCP service action (aws:IsMcpServiceAction)
    pub is_mcp_service_action: Option<bool>,

    /// Request tags (aws:RequestTag/*)
    pub tags: Option<HashMap<String, String>>,

    /// Tag keys being set in the request (aws:TagKeys)
    pub tag_keys: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_context_deserialize() {
        let json = r#"{
            "arn": "arn:aws:iam::123456789012:user/alice",
            "account": "123456789012",
            "org_id": "o-abc123def4",
            "org_paths": ["o-abc123def4/r-ab12/ou-ab12-11111111/"],
            "userid": "AIDAEXAMPLEUSERID",
            "username": "alice",
            "is_management_account": false,
            "tags": {
                "Department": "Engineering"
            }
        }"#;

        let ctx: PrincipalContextFile = serde_json::from_str(json).unwrap();
        assert_eq!(
            ctx.arn,
            Some("arn:aws:iam::123456789012:user/alice".to_string())
        );
        assert_eq!(ctx.account, Some("123456789012".to_string()));
        assert_eq!(ctx.org_id, Some("o-abc123def4".to_string()));
        assert_eq!(ctx.is_management_account, Some(false));
        assert!(ctx.tags.is_some());
        assert_eq!(
            ctx.tags.as_ref().unwrap().get("Department"),
            Some(&"Engineering".to_string())
        );
    }

    #[test]
    fn test_resource_context_deserialize() {
        let json = r#"{
            "account": "123456789012",
            "org_id": "o-abc123def4",
            "tags": {
                "Environment": "Production"
            }
        }"#;

        let ctx: ResourceContextFile = serde_json::from_str(json).unwrap();
        assert_eq!(ctx.account, Some("123456789012".to_string()));
        assert_eq!(ctx.org_id, Some("o-abc123def4".to_string()));
    }

    #[test]
    fn test_request_context_deserialize() {
        let json = r#"{
            "network": {
                "source_ip": "192.168.1.100",
                "source_vpc": "vpc-12345678"
            },
            "session": {
                "mfa_present": true,
                "mfa_auth_age": 300
            },
            "request": {
                "region": "us-east-1",
                "via_aws_service": false,
                "called_via": ["athena.amazonaws.com"]
            },
            "custom": {
                "iam:PassedToService": "lambda.amazonaws.com"
            }
        }"#;

        let ctx: RequestContextFile = serde_json::from_str(json).unwrap();
        assert!(ctx.network.is_some());
        assert_eq!(
            ctx.network.as_ref().unwrap().source_ip,
            Some("192.168.1.100".to_string())
        );
        assert!(ctx.session.is_some());
        assert_eq!(ctx.session.as_ref().unwrap().mfa_present, Some(true));
        assert_eq!(ctx.session.as_ref().unwrap().mfa_auth_age, Some(300));
        assert!(ctx.request.is_some());
        assert_eq!(
            ctx.request.as_ref().unwrap().region,
            Some("us-east-1".to_string())
        );
    }

    #[test]
    fn test_empty_context_files() {
        // All fields should be optional
        let empty_principal: PrincipalContextFile = serde_json::from_str("{}").unwrap();
        assert!(empty_principal.arn.is_none());

        let empty_resource: ResourceContextFile = serde_json::from_str("{}").unwrap();
        assert!(empty_resource.account.is_none());

        let empty_request: RequestContextFile = serde_json::from_str("{}").unwrap();
        assert!(empty_request.network.is_none());
    }

    #[test]
    fn test_partial_context() {
        // Test that partial context files work
        let json = r#"{
            "session": {
                "mfa_present": true
            }
        }"#;

        let ctx: RequestContextFile = serde_json::from_str(json).unwrap();
        assert!(ctx.network.is_none());
        assert!(ctx.session.is_some());
        assert_eq!(ctx.session.as_ref().unwrap().mfa_present, Some(true));
        assert!(ctx.request.is_none());
    }
}
