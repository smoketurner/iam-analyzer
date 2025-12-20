//! CLI implementation for the IAM analyzer.

mod args;

use args::{Args, OutputFormat};
use clap::Parser;
use iam_analyzer::error::{Error, Result};
use iam_analyzer::eval::{
    EvaluationEngine, NamedPolicy, OrganizationHierarchy, OuScpSet, PolicySet, RequestContext,
};
use iam_analyzer::policy::{
    Policy, Severity, has_errors, validate_against_service_definitions, validate_policy,
};
use iam_analyzer::service::{ServiceLoader, extract_service_name};
use std::fs;
use std::path::Path;

/// Run the CLI application.
pub fn run() -> Result<()> {
    let args = Args::parse();

    // Warn if identity policies are provided without principal context
    // This is a common mistake that leads to confusing results
    if !args.identity_policy.is_empty()
        && args.principal_arn.is_none()
        && args.principal_account.is_none()
    {
        eprintln!(
            "Warning: Identity policies provided but no principal context (--principal-arn or \
             --principal-account). The request will be treated as anonymous, and identity \
             policies will not grant access. Only resource-based policies with Principal: \"*\" \
             can grant access to anonymous requests.\n"
        );
    }

    // Create service loader based on offline mode
    let service_loader = ServiceLoader::new(args.offline);

    // If --update-definitions is specified, refresh cached service definitions
    if args.update_definitions {
        if args.offline {
            eprintln!("Warning: --update-definitions ignored in offline mode");
        } else {
            // Refresh the service definition for the action being requested
            if let Some(service_name) = extract_service_name(&args.action) {
                match service_loader.refresh(service_name) {
                    Ok(Some(_)) => {
                        eprintln!("Updated service definitions for '{}'", service_name);
                    }
                    Ok(None) => {
                        eprintln!(
                            "Warning: Could not fetch service definitions for '{}'",
                            service_name
                        );
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to update definitions: {}", e);
                    }
                }
            }
        }
    }

    // Build the policy set
    let policies = build_policy_set(&args)?;

    // Build the request context
    let context = build_request_context(&args)?;

    // Validate policies against service definitions (unless in offline mode without cache)
    validate_policies_against_services(&args, &policies, &service_loader)?;

    // Run the evaluation
    let engine = EvaluationEngine::new();
    let result = engine.evaluate(&context, &policies);

    // Output the result based on format
    match args.output {
        OutputFormat::Text => {
            println!("{}", result);
        }
        OutputFormat::Summary => {
            print!("{}", result.summary());
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)
                .map_err(|e| Error::Other(format!("Failed to serialize result: {}", e)))?;
            println!("{}", json);
        }
        OutputFormat::Quiet => {
            // Just print the decision
            println!("{}", result.decision);
        }
    }

    Ok(())
}

/// Load a policy from a JSON file with optional validation.
fn load_policy(path: &Path) -> Result<NamedPolicy> {
    load_policy_with_validation(path, true)
}

/// Load a policy from a JSON file with configurable validation.
fn load_policy_with_validation(path: &Path, show_warnings: bool) -> Result<NamedPolicy> {
    let content = fs::read_to_string(path).map_err(|e| Error::FileRead {
        path: path.display().to_string(),
        source: e,
    })?;

    let policy: Policy = serde_json::from_str(&content)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    // Validate the policy
    let issues = validate_policy(&policy);
    if !issues.is_empty() {
        for issue in &issues {
            if issue.severity == Severity::Error {
                eprintln!("Policy '{}': {}", name, issue);
            } else if show_warnings {
                eprintln!("Policy '{}': {}", name, issue);
            }
        }
        if has_errors(&issues) {
            return Err(Error::Other(format!(
                "Policy '{}' has validation errors",
                name
            )));
        }
    }

    Ok(NamedPolicy::new(name, policy))
}

/// Build the policy set from CLI arguments.
fn build_policy_set(args: &Args) -> Result<PolicySet> {
    let mut policies = PolicySet::default();

    // Load identity policies
    for path in &args.identity_policy {
        policies
            .identity_policies
            .push(load_policy(Path::new(path))?);
    }

    // Load resource policies
    for path in &args.resource_policy {
        policies
            .resource_policies
            .push(load_policy(Path::new(path))?);
    }

    // Load permission boundaries
    for path in &args.permission_boundary {
        policies
            .permission_boundaries
            .push(load_policy(Path::new(path))?);
    }

    // Load session policies
    for path in &args.session_policy {
        policies
            .session_policies
            .push(load_policy(Path::new(path))?);
    }

    // Load VPC endpoint policies
    for path in &args.vpc_endpoint_policy {
        policies
            .vpc_endpoint_policies
            .push(load_policy(Path::new(path))?);
    }

    // Build SCP hierarchy
    let scp_hierarchy = build_scp_hierarchy(args)?;
    if scp_hierarchy.root_scps.is_empty()
        && scp_hierarchy.ou_scps.is_empty()
        && scp_hierarchy.account_scps.is_empty()
    {
        // No SCPs provided
    } else {
        policies.scp_hierarchy = Some(scp_hierarchy);
    }

    // Build RCP hierarchy
    let rcp_hierarchy = build_rcp_hierarchy(args)?;
    if rcp_hierarchy.root_scps.is_empty()
        && rcp_hierarchy.ou_scps.is_empty()
        && rcp_hierarchy.account_scps.is_empty()
    {
        // No RCPs provided
    } else {
        policies.rcp_hierarchy = Some(rcp_hierarchy);
    }

    Ok(policies)
}

/// Build the SCP hierarchy from CLI arguments.
fn build_scp_hierarchy(args: &Args) -> Result<OrganizationHierarchy> {
    let mut hierarchy = OrganizationHierarchy::default();

    // Load root SCPs
    for path in &args.scp_root {
        hierarchy.root_scps.push(load_policy(Path::new(path))?);
    }

    // Load OU SCPs (each path is one OU level)
    for (i, path) in args.scp_ou.iter().enumerate() {
        let policy = load_policy(Path::new(path))?;
        hierarchy.ou_scps.push(OuScpSet {
            ou_id: format!("ou-{}", i),
            ou_name: None,
            policies: vec![policy],
        });
    }

    // Load account SCPs
    for path in &args.scp_account {
        hierarchy.account_scps.push(load_policy(Path::new(path))?);
    }

    Ok(hierarchy)
}

/// Build the RCP hierarchy from CLI arguments.
fn build_rcp_hierarchy(args: &Args) -> Result<OrganizationHierarchy> {
    let mut hierarchy = OrganizationHierarchy::default();

    // Load root RCPs
    for path in &args.rcp_root {
        hierarchy.root_scps.push(load_policy(Path::new(path))?);
    }

    // Load OU RCPs
    for (i, path) in args.rcp_ou.iter().enumerate() {
        let policy = load_policy(Path::new(path))?;
        hierarchy.ou_scps.push(OuScpSet {
            ou_id: format!("ou-{}", i),
            ou_name: None,
            policies: vec![policy],
        });
    }

    // Load account RCPs
    for path in &args.rcp_account {
        hierarchy.account_scps.push(load_policy(Path::new(path))?);
    }

    Ok(hierarchy)
}

/// Build the request context from CLI arguments.
fn build_request_context(args: &Args) -> Result<RequestContext> {
    let mut builder = RequestContext::builder()
        .action(&args.action)
        .resource(&args.resource);

    if let Some(principal) = &args.principal_arn {
        builder = builder.principal_arn(principal);
    }

    if let Some(account) = &args.principal_account {
        builder = builder.principal_account(account);
    }

    if let Some(account) = &args.resource_account {
        builder = builder.resource_account(account);
    }

    if args.cross_account {
        builder = builder.cross_account(true);
    }

    if args.management_account {
        builder = builder.management_account(true);
    }

    if let Some(org_id) = &args.principal_org_id {
        builder = builder.principal_org_id(org_id);
    }

    if let Some(source_arn) = &args.source_arn {
        builder = builder.source_arn(source_arn);
    }

    if let Some(source_account) = &args.source_account {
        builder = builder.source_account(source_account);
    }

    if args.mfa_present {
        builder = builder.mfa_present(true);
    }

    if let Some(region) = &args.requested_region {
        builder = builder.requested_region(region);
    }

    if args.via_aws_service {
        builder = builder.via_aws_service(true);
    }

    if let Some(userid) = &args.principal_userid {
        builder = builder.principal_userid(userid);
    }

    if !args.principal_org_paths.is_empty() {
        builder = builder.principal_org_paths(args.principal_org_paths.clone());
    }

    for service in &args.called_via {
        builder = builder.called_via(service);
    }

    if args.service_linked_role {
        builder = builder.service_linked_role(true);
    }

    // Load context from file if provided
    if let Some(context_file) = &args.context_file {
        let content = fs::read_to_string(context_file).map_err(|e| Error::FileRead {
            path: context_file.clone(),
            source: e,
        })?;

        let context_data: ContextFile = serde_json::from_str(&content)?;

        // Apply context data
        for (key, values) in context_data.context_keys.unwrap_or_default() {
            builder = builder.context_key_multi(&key, values);
        }

        for (key, value) in context_data.principal_tags.unwrap_or_default() {
            builder = builder.principal_tag(&key, &value);
        }

        for (key, value) in context_data.resource_tags.unwrap_or_default() {
            builder = builder.resource_tag(&key, &value);
        }

        for (key, value) in context_data.request_tags.unwrap_or_default() {
            builder = builder.request_tag(&key, &value);
        }
    }

    // Apply inline context keys
    for ctx in &args.context {
        if let Some((key, value)) = ctx.split_once('=') {
            builder = builder.context_key(key, value);
        }
    }

    builder.build()
}

/// Validate policies against AWS service definitions.
fn validate_policies_against_services(
    args: &Args,
    policies: &PolicySet,
    loader: &ServiceLoader,
) -> Result<()> {
    // Collect all policies for validation
    let mut all_policies: Vec<&Policy> = Vec::new();

    for np in &policies.identity_policies {
        all_policies.push(&np.policy);
    }
    for np in &policies.resource_policies {
        all_policies.push(&np.policy);
    }
    for np in &policies.permission_boundaries {
        all_policies.push(&np.policy);
    }
    for np in &policies.session_policies {
        all_policies.push(&np.policy);
    }
    for np in &policies.vpc_endpoint_policies {
        all_policies.push(&np.policy);
    }

    if let Some(hierarchy) = &policies.scp_hierarchy {
        for np in &hierarchy.root_scps {
            all_policies.push(&np.policy);
        }
        for ou in &hierarchy.ou_scps {
            for np in &ou.policies {
                all_policies.push(&np.policy);
            }
        }
        for np in &hierarchy.account_scps {
            all_policies.push(&np.policy);
        }
    }

    if let Some(hierarchy) = &policies.rcp_hierarchy {
        for np in &hierarchy.root_scps {
            all_policies.push(&np.policy);
        }
        for ou in &hierarchy.ou_scps {
            for np in &ou.policies {
                all_policies.push(&np.policy);
            }
        }
        for np in &hierarchy.account_scps {
            all_policies.push(&np.policy);
        }
    }

    // Validate against service definitions
    validate_against_service_definitions(&all_policies, &args.action, loader)
}

/// Structure for context file JSON.
#[derive(serde::Deserialize)]
struct ContextFile {
    #[serde(default)]
    context_keys: Option<std::collections::HashMap<String, Vec<String>>>,
    #[serde(default)]
    principal_tags: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    resource_tags: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    request_tags: Option<std::collections::HashMap<String, String>>,
}
