//! Configuration entry point for subnet-router advertisements.
//!
//! Turns the operator's `advertise_routes` strings into validated, canonical
//! routes checked against the mesh network. Pure logic: no I/O, no config
//! file access. The config loader calls `parse_advertise_routes` once and the
//! daemon keeps the typed result.

use super::routes::{validate_advertised_routes, Ipv4Cidr, RouteError};

/// Parse and validate an operator's advertised subnets against the mesh CIDR.
///
/// An empty list is valid and means this node advertises no subnet. Any
/// rejected entry fails the whole list, so a typo never partially applies.
pub fn parse_advertise_routes(
    texts: &[String],
    mesh_cidr: &str,
) -> Result<Vec<Ipv4Cidr>, RouteError> {
    let mesh = Ipv4Cidr::parse(mesh_cidr)?;
    validate_advertised_routes(texts, mesh)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn empty_list_is_valid() {
        let routes = parse_advertise_routes(&[], "10.20.0.0/16").expect("empty ok");
        assert!(routes.is_empty());
    }

    #[test]
    fn accepts_disjoint_subnet() {
        let routes = parse_advertise_routes(&texts(&["192.168.1.0/24"]), "10.20.0.0/16")
            .expect("disjoint ok");
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].to_string(), "192.168.1.0/24");
    }

    #[test]
    fn rejects_whole_list_on_one_bad_entry() {
        let result = parse_advertise_routes(
            &texts(&["192.168.1.0/24", "10.20.5.0/24"]),
            "10.20.0.0/16",
        );
        assert!(matches!(result, Err(RouteError::OverlapsMesh { .. })));
    }

    #[test]
    fn rejects_invalid_mesh_cidr() {
        let result = parse_advertise_routes(&texts(&["192.168.1.0/24"]), "nonsense");
        assert!(matches!(result, Err(RouteError::Malformed(_))));
    }
}
