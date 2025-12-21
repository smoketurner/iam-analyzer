//! Request context for policy evaluation.

use std::collections::HashMap;

use super::context_bags::{
    ConditionValue, NetworkContext, PrincipalContext, RequestBag, ResourceContext, SessionContext,
};

/// Context for an IAM access request.
///
/// Contains all the information needed to evaluate whether an action
/// should be allowed or denied.
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The IAM action being requested (e.g., "s3:GetObject")
    pub action: String,
    /// The resource ARN being accessed
    pub resource: String,
    /// The principal ARN making the request
    pub principal_arn: Option<String>,
    /// The account ID of the principal
    pub principal_account: Option<String>,
    /// The account ID that owns the resource
    pub resource_account: Option<String>,
    /// Whether this is a cross-account request
    pub is_cross_account: bool,
    /// Whether the principal is from the organization's management account.
    /// Management account principals are not affected by SCPs.
    pub is_management_account: bool,
    /// Organization ID of the principal (for aws:PrincipalOrgID condition)
    pub principal_org_id: Option<String>,
    /// Organization paths of the principal (for aws:PrincipalOrgPaths condition)
    /// Format: o-xxxxx/r-xxxx/ou-xxxx-xxxxx/ou-yyyy-yyyyy/
    pub principal_org_paths: Option<Vec<String>>,
    /// Source ARN (for service-to-service calls, aws:SourceArn condition)
    pub source_arn: Option<String>,
    /// Source account (for service-to-service calls, aws:SourceAccount condition)
    pub source_account: Option<String>,
    /// Whether MFA was used for authentication (aws:MultiFactorAuthPresent condition)
    pub mfa_present: Option<bool>,
    /// The AWS region being requested (aws:RequestedRegion condition)
    pub requested_region: Option<String>,
    /// Whether the request came through an AWS service (aws:ViaAWSService condition)
    pub via_aws_service: Option<bool>,
    /// The unique identifier of the principal (aws:userid condition)
    pub principal_userid: Option<String>,
    /// Service chain for delegated requests (aws:CalledVia, aws:CalledViaFirst, aws:CalledViaLast)
    pub called_via_chain: Vec<String>,
    /// Whether the principal is a service-linked role (bypasses SCPs)
    pub is_service_linked_role: bool,

    // =========================================================================
    // Additional AWS Global Condition Keys (new fields)
    // =========================================================================
    /// Whether the call is made by an AWS service principal (aws:PrincipalIsAWSService)
    pub principal_is_aws_service: Option<bool>,
    /// Name of the AWS service principal making the request (aws:PrincipalServiceName)
    pub principal_service_name: Option<String>,
    /// When temporary security credentials were issued (aws:TokenIssueTime, ISO 8601)
    pub token_issue_time: Option<String>,
    /// Seconds since MFA was authenticated (aws:MultiFactorAuthAge)
    pub mfa_auth_age: Option<u64>,
    /// Source identity from AssumeRole (aws:SourceIdentity)
    pub source_identity: Option<String>,
    /// Identity provider for federated identity (aws:FederatedProvider)
    pub federated_provider: Option<String>,
    /// VPC ID for requests via VPC endpoint (aws:SourceVpc)
    pub source_vpc: Option<String>,
    /// VPC endpoint ID (aws:SourceVpce)
    pub source_vpce: Option<String>,
    /// Source IP inside VPC (aws:VpcSourceIp)
    pub vpc_source_ip: Option<String>,
    /// Organization ID of the resource owner (aws:ResourceOrgID)
    pub resource_org_id: Option<String>,
    /// Organization paths of the resource owner (aws:ResourceOrgPaths)
    pub resource_org_paths: Option<Vec<String>>,
    /// Source principal's organization ID (aws:SourceOrgID)
    pub source_org_id: Option<String>,
    /// Source principal's organization paths (aws:SourceOrgPaths)
    pub source_org_paths: Option<Vec<String>>,

    /// Condition context keys and values
    pub context_keys: HashMap<String, Vec<String>>,
    /// Principal tags
    pub principal_tags: HashMap<String, String>,
    /// Resource tags
    pub resource_tags: HashMap<String, String>,
    /// Request tags (for tag-on-create)
    pub request_tags: HashMap<String, String>,

    // =========================================================================
    // Context Bags (new architecture - AWS-style)
    // =========================================================================
    /// Principal context bag - who is making the request
    pub principal_ctx: PrincipalContext,
    /// Resource context bag - what is being accessed
    pub resource_ctx: ResourceContext,
    /// Request context bag - properties of the request itself
    pub request_ctx: RequestBag,
    /// Network context bag - network properties of the request
    pub network_ctx: NetworkContext,
    /// Session context bag - role session properties
    pub session_ctx: SessionContext,
}

impl RequestContext {
    /// Create a new builder for RequestContext.
    pub fn builder() -> RequestContextBuilder {
        RequestContextBuilder::default()
    }

    /// Get a context key value.
    pub fn get_context_key(&self, key: &str) -> Option<&Vec<String>> {
        // Normalize key to lowercase for lookup
        let normalized = key.to_lowercase();
        self.context_keys.get(&normalized)
    }

    /// Get a principal tag value.
    pub fn get_principal_tag(&self, key: &str) -> Option<&String> {
        self.principal_tags.get(key)
    }

    /// Get a resource tag value.
    pub fn get_resource_tag(&self, key: &str) -> Option<&String> {
        self.resource_tags.get(key)
    }

    /// Get a request tag value.
    pub fn get_request_tag(&self, key: &str) -> Option<&String> {
        self.request_tags.get(key)
    }

    /// Get condition value from context bags (new unified lookup).
    ///
    /// This routes to the appropriate context bag based on the key prefix:
    /// - Principal keys (aws:Principal*, aws:userid, aws:username) -> principal_ctx
    /// - Resource keys (aws:Resource*) -> resource_ctx
    /// - Network keys (aws:SourceIp, aws:SourceVpc*, aws:Vpce*, aws:VpcSourceIp) -> network_ctx
    /// - Session keys (aws:MultiFactorAuth*, aws:Token*, aws:Federated*, aws:SourceIdentity,
    ///   aws:AssumedRoot, aws:Chatbot*, aws:Ec2Instance*) -> session_ctx
    /// - All other keys -> request_ctx
    ///
    /// Note: Tag keys (aws:PrincipalTag/*, aws:ResourceTag/*, aws:RequestTag/*) preserve
    /// case for the tag key portion because AWS treats tag keys as case-sensitive.
    pub fn get_condition_value(&self, key: &str) -> Option<Vec<String>> {
        let lower = key.to_lowercase();

        // Handle tag keys specially - they have case-sensitive tag key portion
        // The prefix (aws:PrincipalTag/) is case-insensitive, but the tag key is case-sensitive
        if let Some(rest) = strip_prefix_case_insensitive(key, "aws:principaltag/") {
            // Lookup with the original case of the tag key
            return self
                .principal_ctx
                .get_strings(&format!("aws:principaltag/{}", rest));
        }
        if let Some(rest) = strip_prefix_case_insensitive(key, "aws:resourcetag/") {
            return self
                .resource_ctx
                .get_strings(&format!("aws:resourcetag/{}", rest));
        }
        if let Some(rest) = strip_prefix_case_insensitive(key, "aws:requesttag/") {
            return self
                .request_ctx
                .get_strings(&format!("aws:requesttag/{}", rest));
        }

        // Route to appropriate bag based on key prefix
        if lower.starts_with("aws:principal") || lower == "aws:userid" || lower == "aws:username" {
            self.principal_ctx.get_strings(&lower)
        } else if lower.starts_with("aws:resource") {
            self.resource_ctx.get_strings(&lower)
        } else if lower.starts_with("aws:sourceip")
            || lower.starts_with("aws:sourcevpc")
            || lower.starts_with("aws:vpce")
            || lower.starts_with("aws:vpcsourceip")
        {
            self.network_ctx.get_strings(&lower)
        } else if lower.starts_with("aws:multifactorauth")
            || lower.starts_with("aws:token")
            || lower.starts_with("aws:federated")
            || lower.starts_with("aws:chatbot")
            || lower.starts_with("aws:ec2instance")
            || lower == "aws:assumedroot"
            || lower == "aws:sourceidentity"
        {
            self.session_ctx.get_strings(&lower)
        } else {
            // Default to request bag
            self.request_ctx.get_strings(&lower)
        }
    }
}

/// Strip a prefix case-insensitively, returning the remainder with original case.
fn strip_prefix_case_insensitive<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let lower_s = s.to_lowercase();
    let lower_prefix = prefix.to_lowercase();
    if lower_s.starts_with(&lower_prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Builder for RequestContext.
#[derive(Debug, Default)]
pub struct RequestContextBuilder {
    action: Option<String>,
    resource: Option<String>,
    principal_arn: Option<String>,
    principal_account: Option<String>,
    resource_account: Option<String>,
    is_cross_account: bool,
    is_management_account: bool,
    principal_org_id: Option<String>,
    principal_org_paths: Option<Vec<String>>,
    source_arn: Option<String>,
    source_account: Option<String>,
    mfa_present: Option<bool>,
    requested_region: Option<String>,
    via_aws_service: Option<bool>,
    principal_userid: Option<String>,
    called_via_chain: Vec<String>,
    is_service_linked_role: bool,
    // New AWS global condition key fields
    principal_is_aws_service: Option<bool>,
    principal_service_name: Option<String>,
    token_issue_time: Option<String>,
    mfa_auth_age: Option<u64>,
    source_identity: Option<String>,
    federated_provider: Option<String>,
    source_vpc: Option<String>,
    source_vpce: Option<String>,
    vpc_source_ip: Option<String>,
    resource_org_id: Option<String>,
    resource_org_paths: Option<Vec<String>>,
    source_org_id: Option<String>,
    source_org_paths: Option<Vec<String>>,
    // Context keys and tags
    context_keys: HashMap<String, Vec<String>>,
    principal_tags: HashMap<String, String>,
    resource_tags: HashMap<String, String>,
    request_tags: HashMap<String, String>,
    // Context bags (new architecture)
    principal_ctx: PrincipalContext,
    resource_ctx: ResourceContext,
    request_ctx: RequestBag,
    network_ctx: NetworkContext,
    session_ctx: SessionContext,
}

impl RequestContextBuilder {
    /// Set the action.
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Set the resource ARN.
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Set the principal ARN.
    pub fn principal_arn(mut self, principal: impl Into<String>) -> Self {
        let arn = principal.into();
        self.principal_arn = Some(arn.clone());
        self.principal_ctx
            .set("aws:principalarn", ConditionValue::String(arn));
        self
    }

    /// Set the principal account ID.
    pub fn principal_account(mut self, account: impl Into<String>) -> Self {
        let acct = account.into();
        self.principal_account = Some(acct.clone());
        self.principal_ctx
            .set("aws:principalaccount", ConditionValue::String(acct));
        self
    }

    /// Set the resource account ID.
    pub fn resource_account(mut self, account: impl Into<String>) -> Self {
        let acct = account.into();
        self.resource_account = Some(acct.clone());
        self.resource_ctx
            .set("aws:resourceaccount", ConditionValue::String(acct));
        self
    }

    /// Set whether this is a cross-account request.
    pub fn cross_account(mut self, is_cross: bool) -> Self {
        self.is_cross_account = is_cross;
        self
    }

    /// Set whether the principal is from the organization's management account.
    /// Management account principals are not affected by SCPs.
    pub fn management_account(mut self, is_management: bool) -> Self {
        self.is_management_account = is_management;
        self
    }

    /// Set the organization ID of the principal.
    pub fn principal_org_id(mut self, org_id: impl Into<String>) -> Self {
        let id = org_id.into();
        self.principal_org_id = Some(id.clone());
        self.principal_ctx
            .set("aws:principalorgid", ConditionValue::String(id));
        self
    }

    /// Set the organization paths of the principal (aws:PrincipalOrgPaths).
    pub fn principal_org_paths(mut self, paths: Vec<String>) -> Self {
        self.principal_org_paths = Some(paths.clone());
        self.principal_ctx
            .set("aws:principalorgpaths", ConditionValue::StringList(paths));
        self
    }

    /// Set the source ARN (for service-to-service calls).
    pub fn source_arn(mut self, arn: impl Into<String>) -> Self {
        let a = arn.into();
        self.source_arn = Some(a.clone());
        self.request_ctx
            .set("aws:sourcearn", ConditionValue::String(a));
        self
    }

    /// Set the source account (for service-to-service calls).
    pub fn source_account(mut self, account: impl Into<String>) -> Self {
        let acct = account.into();
        self.source_account = Some(acct.clone());
        self.request_ctx
            .set("aws:sourceaccount", ConditionValue::String(acct));
        self
    }

    /// Set whether MFA was used for authentication.
    pub fn mfa_present(mut self, present: bool) -> Self {
        self.mfa_present = Some(present);
        self.session_ctx
            .set("aws:multifactorauthpresent", ConditionValue::Bool(present));
        self
    }

    /// Set the requested region (aws:RequestedRegion).
    pub fn requested_region(mut self, region: impl Into<String>) -> Self {
        let r = region.into();
        self.requested_region = Some(r.clone());
        self.request_ctx
            .set("aws:requestedregion", ConditionValue::String(r));
        self
    }

    /// Set whether the request came through an AWS service (aws:ViaAWSService).
    pub fn via_aws_service(mut self, via_service: bool) -> Self {
        self.via_aws_service = Some(via_service);
        self.request_ctx
            .set("aws:viaawsservice", ConditionValue::Bool(via_service));
        self
    }

    /// Set the unique identifier of the principal (aws:userid).
    pub fn principal_userid(mut self, userid: impl Into<String>) -> Self {
        let id = userid.into();
        self.principal_userid = Some(id.clone());
        self.principal_ctx
            .set("aws:userid", ConditionValue::String(id));
        self
    }

    /// Add a service to the CalledVia chain.
    pub fn called_via(mut self, service: impl Into<String>) -> Self {
        let svc = service.into();
        self.called_via_chain.push(svc.clone());
        // Update the CalledVia list and derived values
        self.request_ctx.set(
            "aws:calledvia",
            ConditionValue::StringList(self.called_via_chain.clone()),
        );
        if let Some(first) = self.called_via_chain.first() {
            self.request_ctx
                .set("aws:calledviafirst", ConditionValue::String(first.clone()));
        }
        self.request_ctx
            .set("aws:calledvialast", ConditionValue::String(svc));
        self
    }

    /// Set whether the principal is a service-linked role.
    pub fn service_linked_role(mut self, is_slr: bool) -> Self {
        self.is_service_linked_role = is_slr;
        self
    }

    // =========================================================================
    // New AWS Global Condition Key Methods
    // =========================================================================

    /// Set whether the principal is an AWS service (aws:PrincipalIsAWSService).
    pub fn principal_is_aws_service(mut self, is_service: bool) -> Self {
        self.principal_is_aws_service = Some(is_service);
        self.principal_ctx.set(
            "aws:principalisawsservice",
            ConditionValue::Bool(is_service),
        );
        self
    }

    /// Set the AWS service principal name (aws:PrincipalServiceName).
    ///
    /// This also automatically sets `aws:PrincipalIsAWSService` to `true`.
    pub fn principal_service_name(mut self, name: impl Into<String>) -> Self {
        let n = name.into();
        self.principal_service_name = Some(n.clone());
        self.principal_ctx
            .set("aws:principalservicename", ConditionValue::String(n));
        // Auto-set PrincipalIsAWSService when a service name is provided
        self.principal_is_aws_service = Some(true);
        self.principal_ctx
            .set("aws:principalisawsservice", ConditionValue::Bool(true));
        self
    }

    /// Set when temporary credentials were issued (aws:TokenIssueTime, ISO 8601).
    pub fn token_issue_time(mut self, time: impl Into<String>) -> Self {
        let t = time.into();
        self.token_issue_time = Some(t.clone());
        self.session_ctx
            .set("aws:tokenissuetime", ConditionValue::DateTime(t));
        self
    }

    /// Set seconds since MFA authentication (aws:MultiFactorAuthAge).
    pub fn mfa_auth_age(mut self, age_seconds: u64) -> Self {
        self.mfa_auth_age = Some(age_seconds);
        self.session_ctx.set(
            "aws:multifactorauthage",
            ConditionValue::Integer(age_seconds as i64),
        );
        self
    }

    /// Set the source identity from AssumeRole (aws:SourceIdentity).
    pub fn source_identity(mut self, identity: impl Into<String>) -> Self {
        let id = identity.into();
        self.source_identity = Some(id.clone());
        self.session_ctx
            .set("aws:sourceidentity", ConditionValue::String(id));
        self
    }

    /// Set the federated identity provider (aws:FederatedProvider).
    pub fn federated_provider(mut self, provider: impl Into<String>) -> Self {
        let p = provider.into();
        self.federated_provider = Some(p.clone());
        self.session_ctx
            .set("aws:federatedprovider", ConditionValue::String(p));
        self
    }

    /// Set the source VPC ID (aws:SourceVpc).
    pub fn source_vpc(mut self, vpc_id: impl Into<String>) -> Self {
        let id = vpc_id.into();
        self.source_vpc = Some(id.clone());
        self.network_ctx
            .set("aws:sourcevpc", ConditionValue::String(id));
        self
    }

    /// Set the source VPC endpoint ID (aws:SourceVpce).
    pub fn source_vpce(mut self, vpce_id: impl Into<String>) -> Self {
        let id = vpce_id.into();
        self.source_vpce = Some(id.clone());
        self.network_ctx
            .set("aws:sourcevpce", ConditionValue::String(id));
        self
    }

    /// Set the VPC source IP address (aws:VpcSourceIp).
    pub fn vpc_source_ip(mut self, ip: impl Into<String>) -> Self {
        let addr = ip.into();
        self.vpc_source_ip = Some(addr.clone());
        self.network_ctx
            .set("aws:vpcsourceip", ConditionValue::IpAddress(addr));
        self
    }

    /// Set the resource owner's organization ID (aws:ResourceOrgID).
    pub fn resource_org_id(mut self, org_id: impl Into<String>) -> Self {
        let id = org_id.into();
        self.resource_org_id = Some(id.clone());
        self.resource_ctx
            .set("aws:resourceorgid", ConditionValue::String(id));
        self
    }

    /// Set the resource owner's organization paths (aws:ResourceOrgPaths).
    pub fn resource_org_paths(mut self, paths: Vec<impl Into<String>>) -> Self {
        let p: Vec<String> = paths.into_iter().map(|p| p.into()).collect();
        self.resource_org_paths = Some(p.clone());
        self.resource_ctx
            .set("aws:resourceorgpaths", ConditionValue::StringList(p));
        self
    }

    /// Set the source principal's organization ID (aws:SourceOrgID).
    pub fn source_org_id(mut self, org_id: impl Into<String>) -> Self {
        let id = org_id.into();
        self.source_org_id = Some(id.clone());
        self.request_ctx
            .set("aws:sourceorgid", ConditionValue::String(id));
        self
    }

    /// Set the source principal's organization paths (aws:SourceOrgPaths).
    pub fn source_org_paths(mut self, paths: Vec<impl Into<String>>) -> Self {
        let p: Vec<String> = paths.into_iter().map(|p| p.into()).collect();
        self.source_org_paths = Some(p.clone());
        self.request_ctx
            .set("aws:sourceorgpaths", ConditionValue::StringList(p));
        self
    }

    // =========================================================================
    // Additional AWS Global Condition Keys (Phase 4)
    // =========================================================================

    /// Set the list of AWS service principal names (aws:PrincipalServiceNamesList).
    /// Multi-valued version of PrincipalServiceName.
    ///
    /// This also automatically sets `aws:PrincipalIsAWSService` to `true` if the list is non-empty.
    pub fn principal_service_names_list(mut self, names: Vec<impl Into<String>>) -> Self {
        let n: Vec<String> = names.into_iter().map(|s| s.into()).collect();
        // Auto-set PrincipalIsAWSService when service names are provided
        if !n.is_empty() {
            self.principal_is_aws_service = Some(true);
            self.principal_ctx
                .set("aws:principalisawsservice", ConditionValue::Bool(true));
        }
        self.principal_ctx.set(
            "aws:principalservicenameslist",
            ConditionValue::StringList(n),
        );
        self
    }

    /// Set whether this is an assumed root session (aws:AssumedRoot).
    pub fn assumed_root(mut self, is_assumed_root: bool) -> Self {
        self.session_ctx
            .set("aws:assumedroot", ConditionValue::Bool(is_assumed_root));
        self
    }

    /// Set the AWS Chatbot source ARN (aws:ChatbotSourceArn).
    pub fn chatbot_source_arn(mut self, arn: impl Into<String>) -> Self {
        self.session_ctx
            .set("aws:chatbotsourcearn", ConditionValue::String(arn.into()));
        self
    }

    /// Set the VPC where EC2 instance role credentials originated (aws:Ec2InstanceSourceVpc).
    pub fn ec2_instance_source_vpc(mut self, vpc_id: impl Into<String>) -> Self {
        self.session_ctx.set(
            "aws:ec2instancesourcevpc",
            ConditionValue::String(vpc_id.into()),
        );
        self
    }

    /// Set the private IPv4 of the EC2 instance (aws:Ec2InstanceSourcePrivateIPv4).
    pub fn ec2_instance_source_private_ipv4(mut self, ip: impl Into<String>) -> Self {
        self.session_ctx.set(
            "aws:ec2instancesourceprivateipv4",
            ConditionValue::IpAddress(ip.into()),
        );
        self
    }

    /// Set the source IP address (aws:SourceIp).
    pub fn source_ip(mut self, ip: impl Into<String>) -> Self {
        self.network_ctx
            .set("aws:sourceip", ConditionValue::IpAddress(ip.into()));
        self
    }

    /// Set the source VPC ARN (aws:SourceVpcArn).
    pub fn source_vpc_arn(mut self, arn: impl Into<String>) -> Self {
        self.network_ctx
            .set("aws:sourcevpcarn", ConditionValue::String(arn.into()));
        self
    }

    /// Set the VPC endpoint owner account (aws:VpceAccount).
    pub fn vpce_account(mut self, account: impl Into<String>) -> Self {
        self.network_ctx
            .set("aws:vpceaccount", ConditionValue::String(account.into()));
        self
    }

    /// Set the VPC endpoint owner organization ID (aws:VpceOrgID).
    pub fn vpce_org_id(mut self, org_id: impl Into<String>) -> Self {
        self.network_ctx
            .set("aws:vpceorgid", ConditionValue::String(org_id.into()));
        self
    }

    /// Set the VPC endpoint owner organization paths (aws:VpceOrgPaths).
    pub fn vpce_org_paths(mut self, paths: Vec<impl Into<String>>) -> Self {
        let p: Vec<String> = paths.into_iter().map(|s| s.into()).collect();
        self.network_ctx
            .set("aws:vpceorgpaths", ConditionValue::StringList(p));
        self
    }

    /// Set whether the request used HTTPS (aws:SecureTransport).
    pub fn secure_transport(mut self, is_secure: bool) -> Self {
        self.request_ctx
            .set("aws:securetransport", ConditionValue::Bool(is_secure));
        self
    }

    /// Set the current time (aws:CurrentTime, ISO 8601 format).
    pub fn current_time(mut self, time: impl Into<String>) -> Self {
        self.request_ctx
            .set("aws:currenttime", ConditionValue::DateTime(time.into()));
        self
    }

    /// Set the epoch time (aws:EpochTime, seconds since epoch).
    pub fn epoch_time(mut self, epoch: i64) -> Self {
        self.request_ctx
            .set("aws:epochtime", ConditionValue::Integer(epoch));
        self
    }

    /// Set the HTTP referer header (aws:referer).
    pub fn referer(mut self, referer: impl Into<String>) -> Self {
        self.request_ctx
            .set("aws:referer", ConditionValue::String(referer.into()));
        self
    }

    /// Set the HTTP user agent (aws:UserAgent).
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.request_ctx
            .set("aws:useragent", ConditionValue::String(user_agent.into()));
        self
    }

    /// Set whether this is an MCP service action (aws:IsMcpServiceAction).
    pub fn is_mcp_service_action(mut self, is_mcp: bool) -> Self {
        self.request_ctx
            .set("aws:ismcpserviceaction", ConditionValue::Bool(is_mcp));
        self
    }

    /// Add a context key with a single value.
    ///
    /// This also adds the key to the appropriate context bag based on the key prefix.
    pub fn context_key(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key_str = key.into();
        let val_str = value.into();
        let lower_key = key_str.to_lowercase();
        self.context_keys
            .entry(lower_key.clone())
            .or_default()
            .push(val_str.clone());
        // Also add to appropriate bag
        self.add_to_bag(&lower_key, ConditionValue::String(val_str));
        self
    }

    /// Add a context key with multiple values.
    pub fn context_key_multi(
        mut self,
        key: impl Into<String>,
        values: Vec<impl Into<String>>,
    ) -> Self {
        let key_str = key.into();
        let vals: Vec<String> = values.into_iter().map(|v| v.into()).collect();
        let lower_key = key_str.to_lowercase();
        let entry = self.context_keys.entry(lower_key.clone()).or_default();
        entry.extend(vals.clone());
        // Also add to appropriate bag
        self.add_to_bag(&lower_key, ConditionValue::StringList(vals));
        self
    }

    /// Add a principal tag.
    ///
    /// Note: Tag keys are case-sensitive in AWS, so "Department" != "department".
    pub fn principal_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let k = key.into();
        let v = value.into();
        self.principal_tags.insert(k.clone(), v.clone());
        // Store with original case for tag key (AWS treats tag keys as case-sensitive)
        self.principal_ctx.set(
            &format!("aws:principaltag/{}", k),
            ConditionValue::String(v),
        );
        self
    }

    /// Add a resource tag.
    ///
    /// Note: Tag keys are case-sensitive in AWS, so "Environment" != "environment".
    pub fn resource_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let k = key.into();
        let v = value.into();
        self.resource_tags.insert(k.clone(), v.clone());
        // Store with original case for tag key (AWS treats tag keys as case-sensitive)
        self.resource_ctx
            .set(&format!("aws:resourcetag/{}", k), ConditionValue::String(v));
        self
    }

    /// Add a request tag.
    ///
    /// Note: Tag keys are case-sensitive in AWS, so "CostCenter" != "costcenter".
    pub fn request_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let k = key.into();
        let v = value.into();
        self.request_tags.insert(k.clone(), v.clone());
        // Store with original case for tag key (AWS treats tag keys as case-sensitive)
        self.request_ctx
            .set(&format!("aws:requesttag/{}", k), ConditionValue::String(v));
        // Also update aws:TagKeys
        let tag_keys = self.request_ctx.get_request_tag_keys();
        self.request_ctx
            .set("aws:tagkeys", ConditionValue::StringList(tag_keys));
        self
    }

    /// Helper to add a value to the appropriate context bag based on key prefix.
    fn add_to_bag(&mut self, key: &str, value: ConditionValue) {
        if key.starts_with("aws:principal") || key == "aws:userid" || key == "aws:username" {
            self.principal_ctx.set(key, value);
        } else if key.starts_with("aws:resource") {
            self.resource_ctx.set(key, value);
        } else if key.starts_with("aws:sourceip")
            || key.starts_with("aws:sourcevpc")
            || key.starts_with("aws:vpce")
            || key.starts_with("aws:vpcsourceip")
        {
            self.network_ctx.set(key, value);
        } else if key.starts_with("aws:multifactorauth")
            || key.starts_with("aws:token")
            || key.starts_with("aws:federated")
            || key.starts_with("aws:chatbot")
            || key.starts_with("aws:ec2instance")
            || key == "aws:assumedroot"
            || key == "aws:sourceidentity"
        {
            self.session_ctx.set(key, value);
        } else {
            // Default to request bag
            self.request_ctx.set(key, value);
        }
    }

    /// Build the RequestContext.
    pub fn build(self) -> crate::error::Result<RequestContext> {
        let action = self
            .action
            .ok_or_else(|| crate::error::Error::MissingField("action".to_string()))?;
        let resource = self
            .resource
            .ok_or_else(|| crate::error::Error::MissingField("resource".to_string()))?;

        // Auto-detect principal account from principal ARN if not explicitly set
        let principal_account = self.principal_account.or_else(|| {
            self.principal_arn.as_ref().and_then(|arn| {
                if arn.starts_with("arn:") {
                    crate::arn::Arn::parse(arn)
                        .ok()
                        .and_then(|parsed| parsed.account_id().map(|s| s.to_string()))
                } else {
                    None
                }
            })
        });

        // Auto-detect resource account from resource ARN if not explicitly set
        let resource_account = self.resource_account.or_else(|| {
            // Try to parse the resource as an ARN and extract the account
            if resource.starts_with("arn:") {
                crate::arn::Arn::parse(&resource)
                    .ok()
                    .and_then(|arn| arn.account_id().map(|s| s.to_string()))
            } else {
                None
            }
        });

        // Auto-detect requested region from resource ARN if not explicitly set
        let requested_region = self.requested_region.or_else(|| {
            if resource.starts_with("arn:") {
                crate::arn::Arn::parse(&resource).ok().and_then(|arn| {
                    if arn.region.is_empty() {
                        None
                    } else {
                        Some(arn.region)
                    }
                })
            } else {
                None
            }
        });

        // Auto-detect source account from source ARN if not explicitly set
        let source_account = self.source_account.or_else(|| {
            self.source_arn.as_ref().and_then(|arn| {
                if arn.starts_with("arn:") {
                    crate::arn::Arn::parse(arn)
                        .ok()
                        .and_then(|parsed| parsed.account_id().map(|s| s.to_string()))
                } else {
                    None
                }
            })
        });

        // Determine if cross-account based on principal and resource accounts
        let is_cross_account = self.is_cross_account
            || match (&principal_account, &resource_account) {
                (Some(p), Some(r)) => p != r,
                _ => false,
            };

        // Auto-detect service-linked role from principal ARN if not explicitly set
        let is_service_linked_role = self.is_service_linked_role
            || self
                .principal_arn
                .as_ref()
                .is_some_and(|arn| super::principal::is_service_linked_role(arn));

        // Populate aws:PrincipalType based on principal ARN
        let mut principal_ctx = self.principal_ctx;
        if let Some(ref arn) = self.principal_arn {
            let principal_type = super::principal::infer_principal_type(arn);
            principal_ctx.set(
                "aws:principaltype",
                ConditionValue::String(principal_type.to_string()),
            );
        }

        // Populate aws:PrincipalAccount with auto-detected or explicit value
        if let Some(ref acct) = principal_account {
            principal_ctx.set("aws:principalaccount", ConditionValue::String(acct.clone()));
        }

        // Populate request context with auto-detected values
        let mut request_ctx = self.request_ctx;
        if let Some(ref region) = requested_region {
            request_ctx.set(
                "aws:requestedregion",
                ConditionValue::String(region.clone()),
            );
        }
        if let Some(ref acct) = source_account {
            request_ctx.set("aws:sourceaccount", ConditionValue::String(acct.clone()));
        }

        Ok(RequestContext {
            action,
            resource,
            principal_arn: self.principal_arn,
            principal_account,
            resource_account,
            is_cross_account,
            is_management_account: self.is_management_account,
            principal_org_id: self.principal_org_id,
            principal_org_paths: self.principal_org_paths,
            source_arn: self.source_arn,
            source_account,
            mfa_present: self.mfa_present,
            requested_region,
            via_aws_service: self.via_aws_service,
            principal_userid: self.principal_userid,
            called_via_chain: self.called_via_chain,
            is_service_linked_role,
            // New global condition key fields
            principal_is_aws_service: self.principal_is_aws_service,
            principal_service_name: self.principal_service_name,
            token_issue_time: self.token_issue_time,
            mfa_auth_age: self.mfa_auth_age,
            source_identity: self.source_identity,
            federated_provider: self.federated_provider,
            source_vpc: self.source_vpc,
            source_vpce: self.source_vpce,
            vpc_source_ip: self.vpc_source_ip,
            resource_org_id: self.resource_org_id,
            resource_org_paths: self.resource_org_paths,
            source_org_id: self.source_org_id,
            source_org_paths: self.source_org_paths,
            // Context keys and tags
            context_keys: self.context_keys,
            principal_tags: self.principal_tags,
            resource_tags: self.resource_tags,
            request_tags: self.request_tags,
            // Context bags (new architecture)
            principal_ctx,
            resource_ctx: self.resource_ctx,
            request_ctx,
            network_ctx: self.network_ctx,
            session_ctx: self.session_ctx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_minimal_context() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .build()
            .unwrap();

        assert_eq!(ctx.action, "s3:GetObject");
        assert_eq!(ctx.resource, "arn:aws:s3:::my-bucket/file.txt");
        assert!(!ctx.is_cross_account);
    }

    #[test]
    fn test_build_with_principal() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .principal_arn("arn:aws:iam::123456789012:user/alice")
            .principal_account("123456789012")
            .build()
            .unwrap();

        assert_eq!(
            ctx.principal_arn,
            Some("arn:aws:iam::123456789012:user/alice".to_string())
        );
        assert_eq!(ctx.principal_account, Some("123456789012".to_string()));
    }

    #[test]
    fn test_cross_account_detection() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .principal_account("111111111111")
            .resource_account("222222222222")
            .build()
            .unwrap();

        assert!(ctx.is_cross_account);
    }

    #[test]
    fn test_same_account() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .principal_account("123456789012")
            .resource_account("123456789012")
            .build()
            .unwrap();

        assert!(!ctx.is_cross_account);
    }

    #[test]
    fn test_auto_detect_resource_account() {
        // Resource ARN with account ID should auto-populate resource_account
        let ctx = RequestContext::builder()
            .action("ec2:DescribeInstances")
            .resource("arn:aws:ec2:us-east-1:222222222222:instance/i-12345")
            .principal_account("111111111111")
            .build()
            .unwrap();

        // Should auto-detect resource account from ARN
        assert_eq!(ctx.resource_account, Some("222222222222".to_string()));
        // Should auto-detect cross-account
        assert!(ctx.is_cross_account);
    }

    #[test]
    fn test_auto_detect_same_account() {
        // When accounts match, should not be cross-account
        let ctx = RequestContext::builder()
            .action("ec2:DescribeInstances")
            .resource("arn:aws:ec2:us-east-1:123456789012:instance/i-12345")
            .principal_account("123456789012")
            .build()
            .unwrap();

        assert_eq!(ctx.resource_account, Some("123456789012".to_string()));
        assert!(!ctx.is_cross_account);
    }

    #[test]
    fn test_auto_detect_service_linked_role() {
        // Service-linked role ARN should auto-set is_service_linked_role
        let ctx = RequestContext::builder()
            .action("rds:CreateDBInstance")
            .resource("arn:aws:rds:us-east-1:123456789012:db:mydb")
            .principal_arn("arn:aws:iam::123456789012:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS")
            .build()
            .unwrap();

        // Should auto-detect service-linked role
        assert!(ctx.is_service_linked_role);
    }

    #[test]
    fn test_regular_role_not_slr() {
        // Regular role should not be detected as service-linked
        let ctx = RequestContext::builder()
            .action("rds:CreateDBInstance")
            .resource("arn:aws:rds:us-east-1:123456789012:db:mydb")
            .principal_arn("arn:aws:iam::123456789012:role/MyRole")
            .build()
            .unwrap();

        assert!(!ctx.is_service_linked_role);
    }

    #[test]
    fn test_s3_bucket_no_account_in_arn() {
        // S3 bucket ARNs don't have account ID
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .principal_account("123456789012")
            .build()
            .unwrap();

        // No account in ARN, so resource_account stays None
        assert_eq!(ctx.resource_account, None);
        // Can't determine cross-account without resource account
        assert!(!ctx.is_cross_account);
    }

    #[test]
    fn test_explicit_resource_account_overrides_arn() {
        // Explicit resource_account should be used even if ARN has an account
        let ctx = RequestContext::builder()
            .action("ec2:DescribeInstances")
            .resource("arn:aws:ec2:us-east-1:222222222222:instance/i-12345")
            .principal_account("111111111111")
            .resource_account("333333333333") // Explicitly set different account
            .build()
            .unwrap();

        // Explicit account takes precedence
        assert_eq!(ctx.resource_account, Some("333333333333".to_string()));
        assert!(ctx.is_cross_account);
    }

    #[test]
    fn test_context_keys() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .context_key("aws:SourceIp", "192.168.1.100")
            .context_key("aws:SecureTransport", "true")
            .build()
            .unwrap();

        assert_eq!(
            ctx.get_context_key("aws:sourceip"),
            Some(&vec!["192.168.1.100".to_string()])
        );
    }

    #[test]
    fn test_tags() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .principal_tag("Department", "Engineering")
            .resource_tag("Environment", "Production")
            .request_tag("CostCenter", "12345")
            .build()
            .unwrap();

        assert_eq!(
            ctx.get_principal_tag("Department"),
            Some(&"Engineering".to_string())
        );
        assert_eq!(
            ctx.get_resource_tag("Environment"),
            Some(&"Production".to_string())
        );
        assert_eq!(
            ctx.get_request_tag("CostCenter"),
            Some(&"12345".to_string())
        );
    }

    #[test]
    fn test_missing_action() {
        let result = RequestContext::builder()
            .resource("arn:aws:s3:::my-bucket/file.txt")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_missing_resource() {
        let result = RequestContext::builder().action("s3:GetObject").build();

        assert!(result.is_err());
    }

    // =========================================================================
    // Phase 4 Condition Key Tests
    // =========================================================================

    #[test]
    fn test_network_context_keys() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .source_ip("192.168.1.100")
            .source_vpc("vpc-12345")
            .source_vpc_arn("arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345")
            .source_vpce("vpce-67890")
            .vpc_source_ip("10.0.0.1")
            .vpce_account("111111111111")
            .vpce_org_id("o-abc123")
            .vpce_org_paths(vec!["o-abc123/r-root/ou-123"])
            .build()
            .unwrap();

        assert_eq!(
            ctx.get_condition_value("aws:SourceIp"),
            Some(vec!["192.168.1.100".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:SourceVpc"),
            Some(vec!["vpc-12345".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:SourceVpcArn"),
            Some(vec![
                "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345".to_string()
            ])
        );
        assert_eq!(
            ctx.get_condition_value("aws:SourceVpce"),
            Some(vec!["vpce-67890".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:VpcSourceIp"),
            Some(vec!["10.0.0.1".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:VpceAccount"),
            Some(vec!["111111111111".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:VpceOrgID"),
            Some(vec!["o-abc123".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:VpceOrgPaths"),
            Some(vec!["o-abc123/r-root/ou-123".to_string()])
        );
    }

    #[test]
    fn test_session_context_keys() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .mfa_present(true)
            .mfa_auth_age(300)
            .token_issue_time("2024-01-15T10:30:00Z")
            .source_identity("john@example.com")
            .federated_provider("arn:aws:iam::123456789012:saml-provider/ADFS")
            .assumed_root(false)
            .chatbot_source_arn("arn:aws:chatbot::123456789012:chat-configuration/slack-channel")
            .ec2_instance_source_vpc("vpc-99999")
            .ec2_instance_source_private_ipv4("172.16.0.50")
            .build()
            .unwrap();

        assert_eq!(
            ctx.get_condition_value("aws:MultiFactorAuthPresent"),
            Some(vec!["true".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:MultiFactorAuthAge"),
            Some(vec!["300".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:TokenIssueTime"),
            Some(vec!["2024-01-15T10:30:00Z".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:SourceIdentity"),
            Some(vec!["john@example.com".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:FederatedProvider"),
            Some(vec![
                "arn:aws:iam::123456789012:saml-provider/ADFS".to_string()
            ])
        );
        assert_eq!(
            ctx.get_condition_value("aws:AssumedRoot"),
            Some(vec!["false".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:ChatbotSourceArn"),
            Some(vec![
                "arn:aws:chatbot::123456789012:chat-configuration/slack-channel".to_string()
            ])
        );
        assert_eq!(
            ctx.get_condition_value("aws:Ec2InstanceSourceVpc"),
            Some(vec!["vpc-99999".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:Ec2InstanceSourcePrivateIPv4"),
            Some(vec!["172.16.0.50".to_string()])
        );
    }

    #[test]
    fn test_request_context_keys() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .requested_region("us-east-1")
            .via_aws_service(true)
            .secure_transport(true)
            .referer("https://console.aws.amazon.com/")
            .user_agent("aws-cli/2.0")
            .is_mcp_service_action(false)
            .current_time("2024-01-15T12:00:00Z")
            .epoch_time(1705320000)
            .build()
            .unwrap();

        assert_eq!(
            ctx.get_condition_value("aws:RequestedRegion"),
            Some(vec!["us-east-1".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:ViaAWSService"),
            Some(vec!["true".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:SecureTransport"),
            Some(vec!["true".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:referer"),
            Some(vec!["https://console.aws.amazon.com/".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:UserAgent"),
            Some(vec!["aws-cli/2.0".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:IsMcpServiceAction"),
            Some(vec!["false".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:CurrentTime"),
            Some(vec!["2024-01-15T12:00:00Z".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:EpochTime"),
            Some(vec!["1705320000".to_string()])
        );
    }

    #[test]
    fn test_principal_service_names_list() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_service_names_list(vec!["lambda.amazonaws.com", "events.amazonaws.com"])
            .build()
            .unwrap();

        assert_eq!(
            ctx.get_condition_value("aws:PrincipalServiceNamesList"),
            Some(vec![
                "lambda.amazonaws.com".to_string(),
                "events.amazonaws.com".to_string()
            ])
        );
    }

    #[test]
    fn test_called_via_chain() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .called_via("athena.amazonaws.com")
            .called_via("glue.amazonaws.com")
            .build()
            .unwrap();

        assert_eq!(
            ctx.get_condition_value("aws:CalledVia"),
            Some(vec![
                "athena.amazonaws.com".to_string(),
                "glue.amazonaws.com".to_string()
            ])
        );
        assert_eq!(
            ctx.get_condition_value("aws:CalledViaFirst"),
            Some(vec!["athena.amazonaws.com".to_string()])
        );
        assert_eq!(
            ctx.get_condition_value("aws:CalledViaLast"),
            Some(vec!["glue.amazonaws.com".to_string()])
        );
    }

    // =========================================================================
    // Auto-Detection Feature Tests
    // =========================================================================

    #[test]
    fn test_auto_detect_principal_account_from_arn() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::123456789012:user/alice")
            .build()
            .unwrap();

        // Principal account should be auto-detected from principal ARN
        assert_eq!(ctx.principal_account, Some("123456789012".to_string()));
        // Should also be available as condition key
        assert_eq!(
            ctx.get_condition_value("aws:PrincipalAccount"),
            Some(vec!["123456789012".to_string()])
        );
    }

    #[test]
    fn test_explicit_principal_account_overrides_arn() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .principal_arn("arn:aws:iam::123456789012:user/alice")
            .principal_account("999999999999")
            .build()
            .unwrap();

        // Explicit principal account should take precedence
        assert_eq!(ctx.principal_account, Some("999999999999".to_string()));
    }

    #[test]
    fn test_auto_detect_requested_region_from_resource_arn() {
        let ctx = RequestContext::builder()
            .action("ec2:RunInstances")
            .resource("arn:aws:ec2:us-west-2:123456789012:instance/*")
            .build()
            .unwrap();

        // Region should be auto-detected from resource ARN
        assert_eq!(ctx.requested_region, Some("us-west-2".to_string()));
        // Should also be available as condition key
        assert_eq!(
            ctx.get_condition_value("aws:RequestedRegion"),
            Some(vec!["us-west-2".to_string()])
        );
    }

    #[test]
    fn test_no_region_for_global_service() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .build()
            .unwrap();

        // S3 bucket ARNs have no region
        assert_eq!(ctx.requested_region, None);
    }

    #[test]
    fn test_explicit_region_overrides_arn() {
        let ctx = RequestContext::builder()
            .action("ec2:RunInstances")
            .resource("arn:aws:ec2:us-west-2:123456789012:instance/*")
            .requested_region("eu-west-1")
            .build()
            .unwrap();

        // Explicit region should take precedence
        assert_eq!(ctx.requested_region, Some("eu-west-1".to_string()));
    }

    #[test]
    fn test_auto_detect_source_account_from_source_arn() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .source_arn("arn:aws:sns:us-east-1:111111111111:topic")
            .build()
            .unwrap();

        // Source account should be auto-detected from source ARN
        assert_eq!(ctx.source_account, Some("111111111111".to_string()));
        // Should also be available as condition key
        assert_eq!(
            ctx.get_condition_value("aws:SourceAccount"),
            Some(vec!["111111111111".to_string()])
        );
    }

    #[test]
    fn test_explicit_source_account_overrides_arn() {
        let ctx = RequestContext::builder()
            .action("s3:GetObject")
            .resource("arn:aws:s3:::bucket/key")
            .source_arn("arn:aws:sns:us-east-1:111111111111:topic")
            .source_account("222222222222")
            .build()
            .unwrap();

        // Explicit source account should take precedence
        assert_eq!(ctx.source_account, Some("222222222222".to_string()));
    }

    #[test]
    fn test_cross_account_auto_detected_from_principal_and_resource_arns() {
        let ctx = RequestContext::builder()
            .action("ec2:DescribeInstances")
            .resource("arn:aws:ec2:us-east-1:222222222222:instance/i-123")
            .principal_arn("arn:aws:iam::111111111111:user/alice")
            .build()
            .unwrap();

        // Both accounts auto-detected, cross-account should be true
        assert_eq!(ctx.principal_account, Some("111111111111".to_string()));
        assert_eq!(ctx.resource_account, Some("222222222222".to_string()));
        assert!(ctx.is_cross_account);
    }

    #[test]
    fn test_same_account_from_arns() {
        let ctx = RequestContext::builder()
            .action("ec2:DescribeInstances")
            .resource("arn:aws:ec2:us-east-1:123456789012:instance/i-123")
            .principal_arn("arn:aws:iam::123456789012:user/alice")
            .build()
            .unwrap();

        // Both accounts same, not cross-account
        assert_eq!(ctx.principal_account, Some("123456789012".to_string()));
        assert_eq!(ctx.resource_account, Some("123456789012".to_string()));
        assert!(!ctx.is_cross_account);
    }
}
