//! Principal type inference from ARN.
//!
//! Determines the principal type (User, Role, Root, FederatedUser, Service, AssumedRole)
//! from the principal ARN format.

/// Types of IAM principals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalType {
    /// IAM user (arn:aws:iam::ACCOUNT:user/NAME)
    User,
    /// IAM role (arn:aws:iam::ACCOUNT:role/NAME)
    Role,
    /// Root account (arn:aws:iam::ACCOUNT:root)
    Root,
    /// Assumed role session (arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION)
    AssumedRole,
    /// Federated user (arn:aws:sts::ACCOUNT:federated-user/NAME)
    FederatedUser,
    /// Service principal (e.g., s3.amazonaws.com)
    Service,
    /// Web identity session (OIDC-based principals)
    WebIdentityUser,
    /// Anonymous/unknown principal
    Anonymous,
}

impl std::fmt::Display for PrincipalType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrincipalType::User => write!(f, "User"),
            PrincipalType::Role => write!(f, "Role"),
            PrincipalType::Root => write!(f, "Root"),
            PrincipalType::AssumedRole => write!(f, "AssumedRole"),
            PrincipalType::FederatedUser => write!(f, "FederatedUser"),
            PrincipalType::Service => write!(f, "Service"),
            PrincipalType::WebIdentityUser => write!(f, "WebIdentityUser"),
            PrincipalType::Anonymous => write!(f, "Anonymous"),
        }
    }
}

/// Infer the principal type from an ARN or principal identifier.
pub fn infer_principal_type(principal: &str) -> PrincipalType {
    // Check if it's a service principal (e.g., s3.amazonaws.com)
    if principal.ends_with(".amazonaws.com") || principal.ends_with(".amazonaws.com.cn") {
        return PrincipalType::Service;
    }

    // Check if it's an ARN
    if !principal.starts_with("arn:") {
        return PrincipalType::Anonymous;
    }

    let parts: Vec<&str> = principal.split(':').collect();
    if parts.len() < 6 {
        return PrincipalType::Anonymous;
    }

    let service = parts[2];
    let resource = parts[5];

    match service {
        "iam" => {
            // IAM resources: user/*, role/*, root
            if resource == "root" {
                PrincipalType::Root
            } else if resource.starts_with("user/") {
                PrincipalType::User
            } else if resource.starts_with("role/") {
                PrincipalType::Role
            } else {
                PrincipalType::Anonymous
            }
        }
        "sts" => {
            // STS resources: assumed-role/*, federated-user/*
            if resource.starts_with("assumed-role/") {
                PrincipalType::AssumedRole
            } else if resource.starts_with("federated-user/") {
                PrincipalType::FederatedUser
            } else {
                PrincipalType::Anonymous
            }
        }
        _ => PrincipalType::Anonymous,
    }
}

/// Check if an ARN represents a service-linked role.
/// Service-linked roles have paths starting with /aws-service-role/
pub fn is_service_linked_role(principal_arn: &str) -> bool {
    if !principal_arn.starts_with("arn:") {
        return false;
    }

    let parts: Vec<&str> = principal_arn.split(':').collect();
    if parts.len() < 6 {
        return false;
    }

    let service = parts[2];
    let resource = parts[5];

    // Service-linked roles are IAM roles with path /aws-service-role/
    service == "iam" && resource.starts_with("role/aws-service-role/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_iam_user() {
        assert_eq!(
            infer_principal_type("arn:aws:iam::123456789012:user/johndoe"),
            PrincipalType::User
        );
    }

    #[test]
    fn test_infer_iam_role() {
        assert_eq!(
            infer_principal_type("arn:aws:iam::123456789012:role/MyRole"),
            PrincipalType::Role
        );
    }

    #[test]
    fn test_infer_root() {
        assert_eq!(
            infer_principal_type("arn:aws:iam::123456789012:root"),
            PrincipalType::Root
        );
    }

    #[test]
    fn test_infer_assumed_role() {
        assert_eq!(
            infer_principal_type("arn:aws:sts::123456789012:assumed-role/MyRole/session-name"),
            PrincipalType::AssumedRole
        );
    }

    #[test]
    fn test_infer_federated_user() {
        assert_eq!(
            infer_principal_type("arn:aws:sts::123456789012:federated-user/johndoe"),
            PrincipalType::FederatedUser
        );
    }

    #[test]
    fn test_infer_service_principal() {
        assert_eq!(
            infer_principal_type("s3.amazonaws.com"),
            PrincipalType::Service
        );
        assert_eq!(
            infer_principal_type("lambda.amazonaws.com"),
            PrincipalType::Service
        );
    }

    #[test]
    fn test_is_service_linked_role() {
        assert!(is_service_linked_role(
            "arn:aws:iam::123456789012:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS"
        ));
        assert!(!is_service_linked_role(
            "arn:aws:iam::123456789012:role/MyRole"
        ));
        assert!(!is_service_linked_role(
            "arn:aws:iam::123456789012:user/johndoe"
        ));
    }

    #[test]
    fn test_principal_type_display() {
        assert_eq!(PrincipalType::User.to_string(), "User");
        assert_eq!(PrincipalType::AssumedRole.to_string(), "AssumedRole");
    }
}
