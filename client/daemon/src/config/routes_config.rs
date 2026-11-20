//! Standalone configuration for subnet-router advertisements.
//!
//! The subnet settings live in their own JSON document, separate from the main
//! node config. `Config::save_to_file` rewrites the whole main file from the
//! typed struct, so any extra key placed there would be dropped on the next
//! save. A sidecar document avoids that and keeps this feature out of
//! `types.rs`.
//!
//! This module is pure: it parses the document text it is given and validates
//! it against the mesh CIDR. The caller reads the file and handles absence.

use serde::Deserialize;

use super::routes::{validate_advertised_routes, Ipv4Cidr, RouteError};

/// Subnet-router settings document.
///
/// Unknown keys are rejected so a misspelled field fails loudly instead of
/// being silently ignored.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubnetRouterConfig {
    /// Subnets this node forwards for, as canonical IPv4 CIDRs.
    #[serde(default)]
    pub advertise_routes: Vec<String>,
}

/// Failure while loading or validating the subnet-router document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubnetConfigError {
    /// The document is not valid JSON or has an unknown or mistyped field.
    Parse(String),
    /// An advertised route was rejected by route validation.
    Route(RouteError),
}

impl std::fmt::Display for SubnetConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(message) => write!(f, "invalid subnet router config: {message}"),
            Self::Route(error) => write!(f, "invalid subnet router config: {error}"),
        }
    }
}

impl std::error::Error for SubnetConfigError {}

impl From<RouteError> for SubnetConfigError {
    fn from(error: RouteError) -> Self {
        Self::Route(error)
    }
}

/// Parse a subnet-router JSON document and validate its routes.
///
/// An empty object or an empty `advertise_routes` list is valid and means this
/// node advertises no subnet. Any rejected route fails the whole document, so a
/// typo never partially applies.
pub fn parse_subnet_router_config(
    document: &str,
    mesh_cidr: &str,
) -> Result<Vec<Ipv4Cidr>, SubnetConfigError> {
    let config: SubnetRouterConfig =
        serde_json::from_str(document).map_err(|e| SubnetConfigError::Parse(e.to_string()))?;
    let mesh = Ipv4Cidr::parse(mesh_cidr)?;
    Ok(validate_advertised_routes(&config.advertise_routes, mesh)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESH: &str = "10.20.0.0/16";

    #[test]
    fn empty_object_is_valid() {
        let routes = parse_subnet_router_config("{}", MESH).expect("empty ok");
        assert!(routes.is_empty());
    }

    #[test]
    fn accepts_disjoint_subnet() {
        let doc = r#"{"advertise_routes": ["192.168.1.0/24"]}"#;
        let routes = parse_subnet_router_config(doc, MESH).expect("disjoint ok");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn rejects_whole_list_on_one_bad_entry() {
        let doc = r#"{"advertise_routes": ["192.168.1.0/24", "10.20.5.0/24"]}"#;
        let result = parse_subnet_router_config(doc, MESH);
        assert!(matches!(
            result,
            Err(SubnetConfigError::Route(RouteError::OverlapsMesh { .. }))
        ));
    }

    #[test]
    fn rejects_unknown_field() {
        let doc = r#"{"advertise_route": ["192.168.1.0/24"]}"#;
        assert!(matches!(
            parse_subnet_router_config(doc, MESH),
            Err(SubnetConfigError::Parse(_))
        ));
    }

    #[test]
    fn rejects_invalid_mesh_cidr() {
        let doc = r#"{"advertise_routes": ["192.168.1.0/24"]}"#;
        assert!(matches!(
            parse_subnet_router_config(doc, "nonsense"),
            Err(SubnetConfigError::Route(RouteError::Malformed(_)))
        ));
    }
}
