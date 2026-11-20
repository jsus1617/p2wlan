//! Subnet-router route validation and longest-prefix-match routing table.
//!
//! This module is pure decision logic: it parses IPv4 CIDRs, rejects unsafe
//! advertisements (malformed, non-canonical, default route, overlap with the
//! mesh network, duplicates, oversize lists) and answers "which peer forwards
//! this destination?". It performs no socket, TUN, or other I/O. The daemon
//! owns the live state and calls into this module to validate and apply it.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Maximum number of subnet routes a single node may advertise.
pub const MAX_ADVERTISED_ROUTES: usize = 64;

/// Maximum number of entries across all owners in one routing table.
pub const MAX_ROUTE_TABLE_ENTRIES: usize = 4096;

/// A canonical IPv4 network with a prefix length between 1 and 32.
///
/// Host bits must be zero; `10.20.1.5/24` is rejected instead of silently
/// normalized, so operators notice typos in their configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Cidr {
    network: u32,
    prefix: u8,
}

/// Typed reason a route or route set was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// Text is not an `a.b.c.d/n` IPv4 CIDR.
    Malformed(String),
    /// Prefix length is greater than 32.
    PrefixOutOfRange(String),
    /// Host bits are set (for example `10.20.1.5/24`).
    NotCanonical(String),
    /// `/0` would capture all traffic and is never allowed.
    DefaultRouteRejected(String),
    /// The route overlaps the mesh network, which would shadow mesh peers.
    OverlapsMesh { route: String, mesh: String },
    /// The same route appears twice in one advertisement.
    Duplicate(String),
    /// More routes than `MAX_ADVERTISED_ROUTES` in one advertisement.
    TooManyRoutes { limit: usize },
    /// The exact prefix is already forwarded by a different peer.
    ExactRouteOwnedByOtherPeer { route: String, owner: String },
    /// Applying the change would exceed `MAX_ROUTE_TABLE_ENTRIES`.
    TableFull { limit: usize },
}

impl std::fmt::Display for RouteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(value) => write!(f, "invalid IPv4 CIDR: {value}"),
            Self::PrefixOutOfRange(value) => write!(f, "prefix length must be 1-32: {value}"),
            Self::NotCanonical(value) => write!(f, "CIDR has host bits set: {value}"),
            Self::DefaultRouteRejected(value) => write!(f, "default route is not allowed: {value}"),
            Self::OverlapsMesh { route, mesh } => {
                write!(f, "route {route} overlaps mesh network {mesh}")
            }
            Self::Duplicate(value) => write!(f, "duplicate route: {value}"),
            Self::TooManyRoutes { limit } => write!(f, "too many routes (limit {limit})"),
            Self::ExactRouteOwnedByOtherPeer { route, owner } => {
                write!(f, "route {route} is already advertised by {owner}")
            }
            Self::TableFull { limit } => write!(f, "route table is full (limit {limit})"),
        }
    }
}

impl std::error::Error for RouteError {}

impl Ipv4Cidr {
    /// Parse and validate a canonical IPv4 CIDR such as `192.168.1.0/24`.
    pub fn parse(text: &str) -> Result<Self, RouteError> {
        let trimmed = text.trim();
        let malformed = || RouteError::Malformed(trimmed.to_string());
        let (addr_text, prefix_text) = trimmed.split_once('/').ok_or_else(malformed)?;
        let addr = Ipv4Addr::from_str(addr_text).map_err(|_| malformed())?;
        let prefix: u8 = prefix_text.parse().map_err(|_| malformed())?;
        if prefix > 32 {
            return Err(RouteError::PrefixOutOfRange(trimmed.to_string()));
        }
        if prefix == 0 {
            return Err(RouteError::DefaultRouteRejected(trimmed.to_string()));
        }
        let raw = u32::from(addr);
        if raw & !mask_for(prefix) != 0 {
            return Err(RouteError::NotCanonical(trimmed.to_string()));
        }
        Ok(Self {
            network: raw,
            prefix,
        })
    }

    /// Network address of this CIDR.
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.network)
    }

    /// Prefix length in bits (1-32).
    pub fn prefix_len(&self) -> u8 {
        self.prefix
    }

    /// Whether `addr` falls inside this network.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        u32::from(addr) & mask_for(self.prefix) == self.network
    }

    /// Whether two networks share at least one address.
    pub fn overlaps(&self, other: &Ipv4Cidr) -> bool {
        let shorter = self.prefix.min(other.prefix);
        let mask = mask_for(shorter);
        self.network & mask == other.network & mask
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network(), self.prefix)
    }
}

fn mask_for(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

/// Validate a node's advertised subnet list against the mesh network.
///
/// Returns the parsed routes in input order. Every entry must be a canonical,
/// non-default IPv4 CIDR that does not overlap `mesh`, must not repeat, and
/// the list must not exceed `MAX_ADVERTISED_ROUTES`.
pub fn validate_advertised_routes(
    texts: &[String],
    mesh: Ipv4Cidr,
) -> Result<Vec<Ipv4Cidr>, RouteError> {
    if texts.len() > MAX_ADVERTISED_ROUTES {
        return Err(RouteError::TooManyRoutes {
            limit: MAX_ADVERTISED_ROUTES,
        });
    }
    let mut routes = Vec::with_capacity(texts.len());
    for text in texts {
        let route = Ipv4Cidr::parse(text)?;
        if routes.contains(&route) {
            return Err(RouteError::Duplicate(route.to_string()));
        }
        if route.overlaps(&mesh) {
            return Err(RouteError::OverlapsMesh {
                route: route.to_string(),
                mesh: mesh.to_string(),
            });
        }
        routes.push(route);
    }
    Ok(routes)
}

/// Routing table from subnet to the peer that forwards it.
///
/// Lookups use longest-prefix match. Each exact prefix has at most one owner,
/// so two peers cannot both claim `192.168.1.0/24`. Overlapping prefixes of
/// different lengths are allowed and resolved by specificity.
#[derive(Debug, Default)]
pub struct RouteTable {
    routes: BTreeMap<Ipv4Cidr, String>,
}

impl RouteTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of routes in the table across all owners.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the table has no routes.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Atomically replace every route owned by `owner` with `routes`.
    ///
    /// Validation runs before any mutation. On error the table is unchanged.
    /// A route is rejected if a different owner already holds that exact prefix.
    pub fn replace_owner_routes(
        &mut self,
        owner: &str,
        routes: &[Ipv4Cidr],
    ) -> Result<(), RouteError> {
        if routes.len() > MAX_ADVERTISED_ROUTES {
            return Err(RouteError::TooManyRoutes {
                limit: MAX_ADVERTISED_ROUTES,
            });
        }
        for route in routes {
            if let Some(current) = self.routes.get(route) {
                if current.as_str() != owner {
                    return Err(RouteError::ExactRouteOwnedByOtherPeer {
                        route: route.to_string(),
                        owner: current.clone(),
                    });
                }
            }
        }
        let retained = self
            .routes
            .values()
            .filter(|current| current.as_str() != owner)
            .count();
        let mut unique = routes.to_vec();
        unique.sort();
        unique.dedup();
        if retained + unique.len() > MAX_ROUTE_TABLE_ENTRIES {
            return Err(RouteError::TableFull {
                limit: MAX_ROUTE_TABLE_ENTRIES,
            });
        }
        self.routes.retain(|_, current| current.as_str() != owner);
        for route in unique {
            self.routes.insert(route, owner.to_string());
        }
        Ok(())
    }

    /// Remove every route owned by `owner`, for example when the peer leaves.
    pub fn remove_owner(&mut self, owner: &str) {
        self.routes.retain(|_, current| current.as_str() != owner);
    }

    /// Return the owner of the most specific route containing `destination`.
    pub fn lookup(&self, destination: Ipv4Addr) -> Option<&str> {
        let raw = u32::from(destination);
        for prefix in (1..=32u8).rev() {
            let key = Ipv4Cidr {
                network: raw & mask_for(prefix),
                prefix,
            };
            if let Some(owner) = self.routes.get(&key) {
                return Some(owner.as_str());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Ipv4Cidr {
        Ipv4Cidr::parse(text).expect("valid test CIDR")
    }

    fn mesh() -> Ipv4Cidr {
        cidr("10.20.0.0/16")
    }

    fn texts(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parse_accepts_canonical_cidr() {
        let route = cidr("192.168.1.0/24");
        assert_eq!(route.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(route.prefix_len(), 24);
        assert_eq!(route.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn parse_rejects_invalid_forms() {
        assert!(matches!(
            Ipv4Cidr::parse("192.168.1.0"),
            Err(RouteError::Malformed(_))
        ));
        assert!(matches!(
            Ipv4Cidr::parse("not-an-ip/24"),
            Err(RouteError::Malformed(_))
        ));
        assert!(matches!(
            Ipv4Cidr::parse("192.168.1.0/33"),
            Err(RouteError::PrefixOutOfRange(_))
        ));
        assert!(matches!(
            Ipv4Cidr::parse("192.168.1.5/24"),
            Err(RouteError::NotCanonical(_))
        ));
        assert!(matches!(
            Ipv4Cidr::parse("0.0.0.0/0"),
            Err(RouteError::DefaultRouteRejected(_))
        ));
    }

    #[test]
    fn contains_checks_network_membership() {
        let route = cidr("192.168.1.0/24");
        assert!(route.contains(Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!route.contains(Ipv4Addr::new(192, 168, 2, 1)));
    }

    #[test]
    fn overlaps_detects_nested_and_disjoint_networks() {
        assert!(cidr("10.0.0.0/8").overlaps(&cidr("10.20.0.0/16")));
        assert!(cidr("10.20.0.0/16").overlaps(&cidr("10.0.0.0/8")));
        assert!(!cidr("192.168.0.0/24").overlaps(&cidr("192.168.1.0/24")));
    }

    #[test]
    fn validate_rejects_mesh_overlap() {
        let inside = validate_advertised_routes(&texts(&["10.20.5.0/24"]), mesh());
        assert!(matches!(inside, Err(RouteError::OverlapsMesh { .. })));
        let covering = validate_advertised_routes(&texts(&["10.0.0.0/8"]), mesh());
        assert!(matches!(covering, Err(RouteError::OverlapsMesh { .. })));
    }

    #[test]
    fn validate_accepts_disjoint_routes() {
        let routes = validate_advertised_routes(&texts(&["192.168.1.0/24"]), mesh())
            .expect("disjoint route accepted");
        assert_eq!(routes, vec![cidr("192.168.1.0/24")]);
    }

    #[test]
    fn validate_rejects_duplicates_and_oversize_lists() {
        let duplicate = validate_advertised_routes(
            &texts(&["192.168.1.0/24", "192.168.1.0/24"]),
            mesh(),
        );
        assert!(matches!(duplicate, Err(RouteError::Duplicate(_))));

        let many: Vec<String> = (0..=MAX_ADVERTISED_ROUTES)
            .map(|index| format!("192.168.0.{index}/32"))
            .collect();
        assert!(matches!(
            validate_advertised_routes(&many, mesh()),
            Err(RouteError::TooManyRoutes { .. })
        ));
    }

    #[test]
    fn lookup_prefers_longest_prefix() {
        let mut table = RouteTable::new();
        table
            .replace_owner_routes("peer-a", &[cidr("192.168.0.0/16")])
            .expect("peer-a accepted");
        table
            .replace_owner_routes("peer-b", &[cidr("192.168.1.0/24")])
            .expect("peer-b accepted");
        assert_eq!(table.lookup(Ipv4Addr::new(192, 168, 1, 5)), Some("peer-b"));
        assert_eq!(table.lookup(Ipv4Addr::new(192, 168, 2, 5)), Some("peer-a"));
        assert_eq!(table.lookup(Ipv4Addr::new(10, 0, 0, 1)), None);
    }

    #[test]
    fn exact_prefix_cannot_be_claimed_by_second_peer() {
        let mut table = RouteTable::new();
        table
            .replace_owner_routes("peer-a", &[cidr("192.168.1.0/24")])
            .expect("peer-a accepted");
        let result = table.replace_owner_routes("peer-b", &[cidr("192.168.1.0/24")]);
        assert!(matches!(
            result,
            Err(RouteError::ExactRouteOwnedByOtherPeer { .. })
        ));
        assert_eq!(table.lookup(Ipv4Addr::new(192, 168, 1, 9)), Some("peer-a"));
    }

    #[test]
    fn replace_is_owner_scoped_and_atomic() {
        let mut table = RouteTable::new();
        table
            .replace_owner_routes("peer-a", &[cidr("192.168.1.0/24")])
            .expect("initial accepted");
        table
            .replace_owner_routes("peer-a", &[cidr("172.16.0.0/16")])
            .expect("replacement accepted");
        assert_eq!(table.lookup(Ipv4Addr::new(192, 168, 1, 9)), None);
        assert_eq!(table.lookup(Ipv4Addr::new(172, 16, 3, 4)), Some("peer-a"));

        table
            .replace_owner_routes("peer-b", &[cidr("172.16.0.0/16")])
            .expect_err("conflict rejected");
        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup(Ipv4Addr::new(172, 16, 3, 4)), Some("peer-a"));
    }

    #[test]
    fn remove_owner_drops_only_that_owner() {
        let mut table = RouteTable::new();
        table
            .replace_owner_routes("peer-a", &[cidr("192.168.1.0/24")])
            .expect("peer-a accepted");
        table
            .replace_owner_routes("peer-b", &[cidr("172.16.0.0/16")])
            .expect("peer-b accepted");
        table.remove_owner("peer-a");
        assert_eq!(table.lookup(Ipv4Addr::new(192, 168, 1, 9)), None);
        assert_eq!(table.lookup(Ipv4Addr::new(172, 16, 3, 4)), Some("peer-b"));
        assert!(!table.is_empty());
    }

    #[test]
    fn table_rejects_growth_past_limit() {
        let mut table = RouteTable::new();
        for owner in 0..(MAX_ROUTE_TABLE_ENTRIES / MAX_ADVERTISED_ROUTES) {
            let routes: Vec<Ipv4Cidr> = (0..MAX_ADVERTISED_ROUTES)
                .map(|index| {
                    let n = (owner * MAX_ADVERTISED_ROUTES + index) as u32;
                    Ipv4Cidr {
                        network: (1u32 << 24) | (n << 8),
                        prefix: 24,
                    }
                })
                .collect();
            table
                .replace_owner_routes(&format!("peer-{owner}"), &routes)
                .expect("within limit");
        }
        assert_eq!(table.len(), MAX_ROUTE_TABLE_ENTRIES);
        let extra = [cidr("2.0.0.0/24")];
        assert!(matches!(
            table.replace_owner_routes("extra", &extra),
            Err(RouteError::TableFull { .. })
        ));
        assert_eq!(table.len(), MAX_ROUTE_TABLE_ENTRIES);
    }
}
