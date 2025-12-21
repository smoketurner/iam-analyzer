//! CLI implementation for the IAM analyzer.

mod args;
mod context_files;
mod org_config;

use args::{Args, ColorChoice, OutputFormat};
use clap::Parser;
use context_files::{PrincipalContextFile, RequestContextFile, ResourceContextFile};
use iam_analyzer::error::{Error, Result};
use iam_analyzer::eval::{
    Decision, EvaluationEngine, EvaluationResult, NamedPolicy, OrganizationHierarchy, OuScpSet,
    PolicySet, RequestContext, RequestContextBuilder,
};
use iam_analyzer::policy::{
    Policy, Severity, has_errors, validate_against_service_definitions, validate_policy,
};
use iam_analyzer::service::{ServiceLoader, extract_service_name};
use std::fs;
use std::io::IsTerminal;
use std::path::Path;

/// Print a verbose message at the specified level.
macro_rules! verbose {
    ($level:expr, $verbosity:expr, $($arg:tt)*) => {
        if $verbosity >= $level {
            eprintln!("[verbose] {}", format!($($arg)*));
        }
    };
}

/// Run the CLI application.
///
/// Returns the evaluation decision (if an evaluation was performed).
/// Returns `None` if the command was something like `--generate-context-template`
/// that doesn't perform an evaluation.
pub fn run() -> Result<Option<Decision>> {
    let args = Args::parse();
    let verbosity = args.verbose;

    // Handle --completions
    if let Some(shell) = args.completions {
        Args::print_completions(shell);
        return Ok(None);
    }

    // Handle --generate-context-template
    if args.generate_context_template {
        generate_context_templates();
        return Ok(None);
    }

    // At this point, action and resource must be present
    let action = args.action.as_ref().ok_or_else(|| {
        Error::Other("--action is required when not using --generate-context-template".to_string())
    })?;
    let resource = args.resource.as_ref().ok_or_else(|| {
        Error::Other(
            "--resource is required when not using --generate-context-template".to_string(),
        )
    })?;

    verbose!(1, verbosity, "Evaluating action: {}", action);
    verbose!(1, verbosity, "Against resource: {}", resource);

    // Warn if identity policies are provided without principal context
    // This is a common mistake that leads to confusing results
    if !args.identity_policy.is_empty()
        && args.principal_arn.is_none()
        && args.principal_context.is_none()
    {
        eprintln!(
            "Warning: Identity policies provided but no principal context (--principal-arn or \
             --principal-context). The request will be treated as anonymous, and identity \
             policies will not grant access. Only resource-based policies with Principal: \"*\" \
             can grant access to anonymous requests.\n"
        );
    }

    // Create service loader based on offline mode
    let service_loader = ServiceLoader::new(args.offline);
    verbose!(2, verbosity, "Offline mode: {}", args.offline);

    // If --update-definitions is specified, refresh cached service definitions
    if args.update_definitions {
        if args.offline {
            eprintln!("Warning: --update-definitions ignored in offline mode");
        } else {
            // Refresh the service definition for the action being requested
            if let Some(service_name) = extract_service_name(action) {
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
    verbose!(1, verbosity, "Loading policies...");
    let policies = build_policy_set(&args, verbosity)?;

    // Build the request context
    verbose!(1, verbosity, "Building request context...");
    let context = build_request_context(&args, action, resource, verbosity)?;

    // Validate policies against service definitions (unless in offline mode without cache)
    validate_policies_against_services(&args, action, &policies, &service_loader)?;

    // Run the evaluation
    verbose!(1, verbosity, "Running policy evaluation...");
    let engine = EvaluationEngine::new();
    let result = engine.evaluate(&context, &policies);
    verbose!(2, verbosity, "Evaluation complete: {:?}", result.decision);

    // Determine if we should use colors
    let use_colors = should_use_colors(args.color);

    // Output the result based on format
    match args.output {
        OutputFormat::Text => {
            print_result_text(&result, use_colors);
        }
        OutputFormat::Summary => {
            print_result_summary(&result, use_colors);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)
                .map_err(|e| Error::Other(format!("Failed to serialize result: {}", e)))?;
            println!("{}", json);
        }
        OutputFormat::Quiet => {
            // Just print the decision (with color)
            println!("{}", colorize_decision(result.decision, use_colors));
        }
    }

    Ok(Some(result.decision))
}

/// Determine if colors should be used based on the color choice.
fn should_use_colors(choice: ColorChoice) -> bool {
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => std::io::stdout().is_terminal(),
    }
}

/// Get the ANSI color code for a decision.
fn decision_color(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "\x1b[32m",        // Green
        Decision::ExplicitDeny => "\x1b[31m", // Red
        Decision::ImplicitDeny => "\x1b[33m", // Yellow
    }
}

/// Reset ANSI color.
const RESET: &str = "\x1b[0m";

/// Colorize a decision string.
fn colorize_decision(decision: Decision, use_colors: bool) -> String {
    if use_colors {
        format!("{}{}{}", decision_color(decision), decision, RESET)
    } else {
        decision.to_string()
    }
}

/// Print the full text result with optional colors.
fn print_result_text(result: &EvaluationResult, use_colors: bool) {
    println!(
        "Decision: {}",
        colorize_decision(result.decision, use_colors)
    );
    println!();
    println!("Reasoning:");

    for (i, step) in result.reasoning.iter().enumerate() {
        print!("  [{}] {} ", i + 1, step.policy_type);
        if !step.policy_name.is_empty() {
            print!("({})", step.policy_name);
        }
        println!();

        if let Some(sid) = &step.statement_sid {
            print!("      Statement \"{}\" ", sid);
        } else {
            print!("      ");
        }

        if step.matched {
            print!("matches");
        } else {
            print!("does not match");
        }

        if let Some(effect) = &step.effect {
            print!(" - Effect: {:?}", effect);
        }

        println!();

        if !step.details.is_empty() {
            println!("      {}", step.details);
        }

        // Show detailed breakdown if available
        if let Some(breakdown) = &step.breakdown {
            let breakdown_str = breakdown.to_string();
            for line in breakdown_str.lines() {
                if !line.is_empty() {
                    println!("        {}", line);
                }
            }
        }
    }

    if let Some(policy_type) = &result.deciding_policy_type {
        println!();
        print!(
            "Final: {} from {}",
            colorize_decision(result.decision, use_colors),
            policy_type
        );
        if let Some(stmt) = &result.deciding_statement {
            print!(" statement \"{}\"", stmt);
        }
        println!();
    }
}

/// Print the summary result with optional colors.
fn print_result_summary(result: &EvaluationResult, use_colors: bool) {
    println!(
        "Decision: {}",
        colorize_decision(result.decision, use_colors)
    );

    if let Some(policy_type) = &result.deciding_policy_type {
        println!("Policy Type: {}", policy_type);
    }

    if let Some(stmt) = &result.deciding_statement {
        println!("Statement: {}", stmt);
    }

    // Find the deciding reasoning step
    let deciding_step = result.reasoning.iter().find(|step| {
        step.matched
            && step.effect.is_some_and(|e| match result.decision {
                Decision::Allow => e == iam_analyzer::policy::Effect::Allow,
                Decision::ExplicitDeny => e == iam_analyzer::policy::Effect::Deny,
                Decision::ImplicitDeny => false,
            })
    });

    if let Some(step) = deciding_step {
        if !step.policy_name.is_empty() {
            println!("Policy: {}", step.policy_name);
        }
        if !step.details.is_empty() {
            println!("Reason: {}", step.details);
        }
    } else if result.decision == Decision::ImplicitDeny {
        println!("Reason: No Allow statement matched");
    }
}

/// Load a policy from a JSON file with optional validation.
fn load_policy(path: &Path, verbosity: u8) -> Result<NamedPolicy> {
    load_policy_with_validation(path, true, verbosity)
}

/// Load a policy from a JSON file with configurable validation.
fn load_policy_with_validation(
    path: &Path,
    show_warnings: bool,
    verbosity: u8,
) -> Result<NamedPolicy> {
    let content = fs::read_to_string(path).map_err(|e| Error::FileRead {
        path: path.display().to_string(),
        source: e,
    })?;

    let policy: Policy = serde_json::from_str(&content)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string());

    verbose!(
        2,
        verbosity,
        "Parsed policy '{}' with {} statements",
        name,
        policy.statement.len()
    );

    // Validate the policy
    let issues = validate_policy(&policy);
    if !issues.is_empty() {
        for issue in &issues {
            if issue.severity == Severity::Error || show_warnings {
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
fn build_policy_set(args: &Args, verbosity: u8) -> Result<PolicySet> {
    let mut policies = PolicySet::default();

    // Load identity policies
    for path in &args.identity_policy {
        verbose!(1, verbosity, "Loading identity policy: {}", path);
        policies
            .identity_policies
            .push(load_policy(Path::new(path), verbosity)?);
    }

    // Load resource policies
    for path in &args.resource_policy {
        verbose!(1, verbosity, "Loading resource policy: {}", path);
        policies
            .resource_policies
            .push(load_policy(Path::new(path), verbosity)?);
    }

    // Load permission boundaries
    for path in &args.permission_boundary {
        verbose!(1, verbosity, "Loading permission boundary: {}", path);
        policies
            .permission_boundaries
            .push(load_policy(Path::new(path), verbosity)?);
    }

    // Load session policies
    for path in &args.session_policy {
        verbose!(1, verbosity, "Loading session policy: {}", path);
        policies
            .session_policies
            .push(load_policy(Path::new(path), verbosity)?);
    }

    // Load VPC endpoint policies
    for path in &args.vpc_endpoint_policy {
        verbose!(1, verbosity, "Loading VPC endpoint policy: {}", path);
        policies
            .vpc_endpoint_policies
            .push(load_policy(Path::new(path), verbosity)?);
    }

    // Load organization config if provided
    if let Some(config_path) = &args.organization_config {
        verbose!(1, verbosity, "Loading organization config: {}", config_path);
        let (scp_hierarchy, rcp_hierarchy) = load_organization_config(config_path, verbosity)?;

        if let Some(hierarchy) = scp_hierarchy
            && (!hierarchy.root_scps.is_empty()
                || !hierarchy.ou_scps.is_empty()
                || !hierarchy.account_scps.is_empty())
        {
            let count = hierarchy.root_scps.len()
                + hierarchy
                    .ou_scps
                    .iter()
                    .map(|ou| ou.policies.len())
                    .sum::<usize>()
                + hierarchy.account_scps.len();
            verbose!(2, verbosity, "Loaded {} SCP policies in hierarchy", count);
            policies.scp_hierarchy = Some(hierarchy);
        }

        if let Some(hierarchy) = rcp_hierarchy
            && (!hierarchy.root_scps.is_empty()
                || !hierarchy.ou_scps.is_empty()
                || !hierarchy.account_scps.is_empty())
        {
            let count = hierarchy.root_scps.len()
                + hierarchy
                    .ou_scps
                    .iter()
                    .map(|ou| ou.policies.len())
                    .sum::<usize>()
                + hierarchy.account_scps.len();
            verbose!(2, verbosity, "Loaded {} RCP policies in hierarchy", count);
            policies.rcp_hierarchy = Some(hierarchy);
        }
    }

    let total = policies.identity_policies.len()
        + policies.resource_policies.len()
        + policies.permission_boundaries.len()
        + policies.session_policies.len()
        + policies.vpc_endpoint_policies.len();
    verbose!(1, verbosity, "Loaded {} direct policies", total);

    Ok(policies)
}

/// Load organization config from YAML file.
///
/// Returns (SCP hierarchy, RCP hierarchy) - each is Option since they may not be present.
fn load_organization_config(
    config_path: &str,
    verbosity: u8,
) -> Result<(Option<OrganizationHierarchy>, Option<OrganizationHierarchy>)> {
    let content = fs::read_to_string(config_path).map_err(|e| Error::FileRead {
        path: config_path.to_string(),
        source: e,
    })?;

    let config: org_config::OrganizationConfig = serde_yml::from_str(&content).map_err(|e| {
        Error::Other(format!(
            "Failed to parse organization config '{}': {}",
            config_path, e
        ))
    })?;

    // Get the base directory for resolving relative paths
    let base_dir = Path::new(config_path).parent().unwrap_or(Path::new("."));

    let scp_hierarchy = if let Some(scp_config) = config.scp_hierarchy {
        verbose!(2, verbosity, "Loading SCP hierarchy from config");
        Some(build_hierarchy_from_config(
            &scp_config,
            base_dir,
            verbosity,
        )?)
    } else {
        None
    };

    let rcp_hierarchy = if let Some(rcp_config) = config.rcp_hierarchy {
        verbose!(2, verbosity, "Loading RCP hierarchy from config");
        Some(build_hierarchy_from_config(
            &rcp_config,
            base_dir,
            verbosity,
        )?)
    } else {
        None
    };

    Ok((scp_hierarchy, rcp_hierarchy))
}

/// Build organization hierarchy from config.
fn build_hierarchy_from_config(
    config: &org_config::HierarchyConfig,
    base_dir: &Path,
    verbosity: u8,
) -> Result<OrganizationHierarchy> {
    let mut hierarchy = OrganizationHierarchy::default();

    // Load root policies
    for path in &config.root {
        let full_path = resolve_path(path, base_dir);
        verbose!(2, verbosity, "Loading root policy: {}", full_path.display());
        hierarchy
            .root_scps
            .push(load_policy(&full_path, verbosity)?);
    }

    // Load OU policies
    for ou in &config.ous {
        verbose!(2, verbosity, "Loading OU '{}' policies", ou.id);
        let mut ou_policies = Vec::new();
        for path in &ou.policies {
            let full_path = resolve_path(path, base_dir);
            verbose!(3, verbosity, "  Loading: {}", full_path.display());
            ou_policies.push(load_policy(&full_path, verbosity)?);
        }
        hierarchy.ou_scps.push(OuScpSet {
            ou_id: ou.id.clone(),
            ou_name: ou.name.clone(),
            policies: ou_policies,
        });
    }

    // Load account policies
    for path in &config.account {
        let full_path = resolve_path(path, base_dir);
        verbose!(
            2,
            verbosity,
            "Loading account policy: {}",
            full_path.display()
        );
        hierarchy
            .account_scps
            .push(load_policy(&full_path, verbosity)?);
    }

    Ok(hierarchy)
}

/// Resolve a path relative to a base directory.
fn resolve_path(path: &str, base_dir: &Path) -> std::path::PathBuf {
    let p = Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

/// Load principal context from JSON file.
fn load_principal_context(path: &str) -> Result<PrincipalContextFile> {
    let content = fs::read_to_string(path).map_err(|e| Error::FileRead {
        path: path.to_string(),
        source: e,
    })?;

    serde_json::from_str(&content).map_err(|e| {
        Error::Other(format!(
            "Failed to parse principal context '{}': {}",
            path, e
        ))
    })
}

/// Load resource context from JSON file.
fn load_resource_context(path: &str) -> Result<ResourceContextFile> {
    let content = fs::read_to_string(path).map_err(|e| Error::FileRead {
        path: path.to_string(),
        source: e,
    })?;

    serde_json::from_str(&content).map_err(|e| {
        Error::Other(format!(
            "Failed to parse resource context '{}': {}",
            path, e
        ))
    })
}

/// Load request context from JSON file.
fn load_request_context_file(path: &str) -> Result<RequestContextFile> {
    let content = fs::read_to_string(path).map_err(|e| Error::FileRead {
        path: path.to_string(),
        source: e,
    })?;

    serde_json::from_str(&content)
        .map_err(|e| Error::Other(format!("Failed to parse request context '{}': {}", path, e)))
}

/// Build the request context from CLI arguments.
fn build_request_context(
    args: &Args,
    action: &str,
    resource: &str,
    verbosity: u8,
) -> Result<RequestContext> {
    let mut builder = RequestContext::builder().action(action).resource(resource);

    // Load principal context from file if provided
    if let Some(path) = &args.principal_context {
        verbose!(2, verbosity, "Loading principal context from: {}", path);
        let ctx = load_principal_context(path)?;
        builder = apply_principal_context(builder, &ctx);
    }

    // CLI --principal-arn overrides file (highest priority)
    if let Some(principal) = &args.principal_arn {
        verbose!(2, verbosity, "Using principal ARN: {}", principal);
        builder = builder.principal_arn(principal);
    }

    // Load resource context from file if provided
    if let Some(path) = &args.resource_context {
        verbose!(2, verbosity, "Loading resource context from: {}", path);
        let ctx = load_resource_context(path)?;
        builder = apply_resource_context(builder, &ctx);
    }

    // Load request context from file if provided
    if let Some(path) = &args.request_context {
        verbose!(2, verbosity, "Loading request context from: {}", path);
        let ctx = load_request_context_file(path)?;
        builder = apply_request_context(builder, &ctx);
    }

    let context = builder.build()?;
    verbose!(2, verbosity, "Request context built successfully");
    verbose!(3, verbosity, "  Action: {}", context.action);
    verbose!(3, verbosity, "  Resource: {}", context.resource);
    if let Some(principal) = &context.principal_arn {
        verbose!(3, verbosity, "  Principal: {}", principal);
    }
    verbose!(
        3,
        verbosity,
        "  Cross-account: {}",
        context.is_cross_account
    );

    Ok(context)
}

/// Apply principal context file to builder.
fn apply_principal_context(
    mut builder: RequestContextBuilder,
    ctx: &PrincipalContextFile,
) -> RequestContextBuilder {
    if let Some(arn) = &ctx.arn {
        builder = builder.principal_arn(arn);
    }
    if let Some(account) = &ctx.account {
        builder = builder.principal_account(account);
    }
    if let Some(org_id) = &ctx.org_id {
        builder = builder.principal_org_id(org_id);
    }
    if let Some(paths) = &ctx.org_paths {
        builder = builder.principal_org_paths(paths.clone());
    }
    if let Some(userid) = &ctx.userid {
        builder = builder.principal_userid(userid);
    }
    if let Some(username) = &ctx.username {
        builder = builder.context_key("aws:username", username);
    }
    if let Some(principal_type) = &ctx.principal_type {
        builder = builder.context_key("aws:PrincipalType", principal_type);
    }
    if let Some(is_aws_service) = ctx.is_aws_service {
        builder = builder.principal_is_aws_service(is_aws_service);
    }
    if let Some(service_name) = &ctx.service_name {
        builder = builder.principal_service_name(service_name);
    }
    if let Some(service_names) = &ctx.service_names_list {
        builder = builder.principal_service_names_list(service_names.clone());
    }
    if let Some(is_mgmt) = ctx.is_management_account {
        builder = builder.management_account(is_mgmt);
    }
    if let Some(tags) = &ctx.tags {
        for (key, value) in tags {
            builder = builder.principal_tag(key, value);
        }
    }
    builder
}

/// Apply resource context file to builder.
fn apply_resource_context(
    mut builder: RequestContextBuilder,
    ctx: &ResourceContextFile,
) -> RequestContextBuilder {
    if let Some(account) = &ctx.account {
        builder = builder.resource_account(account);
    }
    if let Some(org_id) = &ctx.org_id {
        builder = builder.resource_org_id(org_id);
    }
    if let Some(paths) = &ctx.org_paths {
        builder = builder.resource_org_paths(paths.clone());
    }
    if let Some(tags) = &ctx.tags {
        for (key, value) in tags {
            builder = builder.resource_tag(key, value);
        }
    }
    builder
}

/// Apply request context file to builder.
fn apply_request_context(
    mut builder: RequestContextBuilder,
    ctx: &RequestContextFile,
) -> RequestContextBuilder {
    // Apply network context
    if let Some(network) = &ctx.network {
        if let Some(ip) = &network.source_ip {
            builder = builder.source_ip(ip);
        }
        if let Some(vpc) = &network.source_vpc {
            builder = builder.source_vpc(vpc);
        }
        if let Some(vpc_arn) = &network.source_vpc_arn {
            builder = builder.source_vpc_arn(vpc_arn);
        }
        if let Some(vpce) = &network.source_vpce {
            builder = builder.source_vpce(vpce);
        }
        if let Some(ip) = &network.vpc_source_ip {
            builder = builder.vpc_source_ip(ip);
        }
        if let Some(account) = &network.vpce_account {
            builder = builder.vpce_account(account);
        }
        if let Some(org_id) = &network.vpce_org_id {
            builder = builder.vpce_org_id(org_id);
        }
        if let Some(paths) = &network.vpce_org_paths {
            builder = builder.vpce_org_paths(paths.clone());
        }
    }

    // Apply session context
    if let Some(session) = &ctx.session {
        if let Some(mfa) = session.mfa_present {
            builder = builder.mfa_present(mfa);
        }
        if let Some(age) = session.mfa_auth_age {
            builder = builder.mfa_auth_age(age as u64);
        }
        if let Some(time) = &session.token_issue_time {
            builder = builder.token_issue_time(time);
        }
        if let Some(identity) = &session.source_identity {
            builder = builder.source_identity(identity);
        }
        if let Some(provider) = &session.federated_provider {
            builder = builder.federated_provider(provider);
        }
        if let Some(assumed_root) = session.assumed_root {
            builder = builder.assumed_root(assumed_root);
        }
        if let Some(arn) = &session.chatbot_source_arn {
            builder = builder.chatbot_source_arn(arn);
        }
        if let Some(vpc) = &session.ec2_instance_source_vpc {
            builder = builder.ec2_instance_source_vpc(vpc);
        }
        if let Some(ip) = &session.ec2_instance_source_private_ipv4 {
            builder = builder.ec2_instance_source_private_ipv4(ip);
        }
    }

    // Apply request context
    if let Some(request) = &ctx.request {
        if let Some(region) = &request.region {
            builder = builder.requested_region(region);
        }
        if let Some(secure) = request.secure_transport {
            builder = builder.secure_transport(secure);
        }
        if let Some(via) = request.via_aws_service {
            builder = builder.via_aws_service(via);
        }
        if let Some(called_via) = &request.called_via {
            for service in called_via {
                builder = builder.called_via(service);
            }
        }
        if let Some(arn) = &request.source_arn {
            builder = builder.source_arn(arn);
        }
        if let Some(account) = &request.source_account {
            builder = builder.source_account(account);
        }
        if let Some(org_id) = &request.source_org_id {
            builder = builder.source_org_id(org_id);
        }
        if let Some(paths) = &request.source_org_paths {
            builder = builder.source_org_paths(paths.clone());
        }
        if let Some(time) = &request.current_time {
            builder = builder.current_time(time);
        }
        if let Some(epoch) = request.epoch_time {
            builder = builder.epoch_time(epoch);
        }
        if let Some(referer) = &request.referer {
            builder = builder.referer(referer);
        }
        if let Some(ua) = &request.user_agent {
            builder = builder.user_agent(ua);
        }
        if let Some(is_mcp) = request.is_mcp_service_action {
            builder = builder.is_mcp_service_action(is_mcp);
        }
        if let Some(tags) = &request.tags {
            for (key, value) in tags {
                builder = builder.request_tag(key, value);
            }
        }
        // Note: tag_keys is automatically populated from request tags
    }

    // Apply custom/service-specific condition keys
    if let Some(custom) = &ctx.custom {
        for (key, value) in custom {
            match value {
                serde_json::Value::String(s) => {
                    builder = builder.context_key(key, s);
                }
                serde_json::Value::Bool(b) => {
                    builder = builder.context_key(key, b.to_string());
                }
                serde_json::Value::Number(n) => {
                    builder = builder.context_key(key, n.to_string());
                }
                serde_json::Value::Array(arr) => {
                    let strings: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    if !strings.is_empty() {
                        builder = builder.context_key_multi(key, strings);
                    }
                }
                _ => {} // Ignore null and object values
            }
        }
    }

    builder
}

/// Validate policies against AWS service definitions.
fn validate_policies_against_services(
    _args: &Args,
    action: &str,
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
    validate_against_service_definitions(&all_policies, action, loader)
}

/// Generate template context files to stdout.
fn generate_context_templates() {
    println!("=== principal-context.json ===");
    println!(
        r#"{{
  "arn": "arn:aws:iam::123456789012:user/alice",
  "account": "123456789012",
  "org_id": "o-abc123def4",
  "org_paths": ["o-abc123def4/r-ab12/ou-ab12-11111111/"],
  "userid": "AIDAEXAMPLEUSERID",
  "username": "alice",
  "principal_type": "User",
  "is_aws_service": false,
  "service_name": null,
  "service_names_list": [],
  "is_management_account": false,
  "tags": {{
    "Department": "Engineering",
    "Team": "Platform"
  }}
}}"#
    );

    println!("\n=== resource-context.json ===");
    println!(
        r#"{{
  "account": "123456789012",
  "org_id": "o-abc123def4",
  "org_paths": ["o-abc123def4/r-ab12/ou-ab12-11111111/"],
  "tags": {{
    "Environment": "Production",
    "Classification": "Confidential"
  }}
}}"#
    );

    println!("\n=== request-context.json ===");
    println!(
        r#"{{
  "network": {{
    "source_ip": "192.168.1.100",
    "source_vpc": "vpc-12345678",
    "source_vpc_arn": "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-12345678",
    "source_vpce": "vpce-1a2b3c4d",
    "vpc_source_ip": "10.0.0.1",
    "vpce_account": "123456789012",
    "vpce_org_id": "o-abc123def4",
    "vpce_org_paths": []
  }},
  "session": {{
    "mfa_present": true,
    "mfa_auth_age": 300,
    "token_issue_time": "2024-01-15T10:30:00Z",
    "source_identity": "alice@example.com",
    "federated_provider": "arn:aws:iam::123456789012:saml-provider/MyProvider",
    "assumed_root": false,
    "chatbot_source_arn": null,
    "ec2_instance_source_vpc": null,
    "ec2_instance_source_private_ipv4": null
  }},
  "request": {{
    "region": "us-east-1",
    "secure_transport": true,
    "via_aws_service": false,
    "called_via": ["athena.amazonaws.com"],
    "source_arn": "arn:aws:sns:us-east-1:123456789012:my-topic",
    "source_account": "123456789012",
    "source_org_id": "o-abc123def4",
    "source_org_paths": [],
    "current_time": null,
    "epoch_time": null,
    "referer": "https://console.aws.amazon.com",
    "user_agent": "aws-cli/2.0",
    "is_mcp_service_action": false,
    "tags": {{
      "CostCenter": "12345"
    }},
    "tag_keys": ["CostCenter", "Project"]
  }},
  "custom": {{
    "iam:PassedToService": "lambda.amazonaws.com",
    "sts:ExternalId": "my-external-id"
  }}
}}"#
    );

    println!("\n---");
    println!("Copy the sections above into separate files.");
    println!("All fields are optional - only include what you need.");
}
