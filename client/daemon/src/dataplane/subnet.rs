//! Subnet-router forwarding decisions for the data plane.
//!
//! Pure decision logic. Given a destination and the live state the caller
//! already holds, this module answers two questions: which peer forwards a
//! routed destination, and whether that forward may proceed. It never sends
//! packets, touches sockets or TUN, or stores session state. The caller owns
//! the live tables and passes in whether the owner has a live session.

use std::net::Ipv4Addr;

use crate::config::routes::RouteTable;

/// Why a subnet-routed packet was not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetDropReason {
    /// No advertised subnet covers the destination.
    NoRoute,
    /// A route covers the destination but its owner has no live session.
    OwnerNotLive,
    /// The packet would loop back to the peer it came from.
    SourceIsOwner,
}

impl SubnetDropReason {
    /// Stable label for metrics and structured logs.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::NoRoute => "subnet_no_route",
            Self::OwnerNotLive => "subnet_owner_not_live",
            Self::SourceIsOwner => "subnet_source_is_owner",
        }
    }
}

/// Outcome of a subnet forwarding decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubnetDecision<'a> {
    /// Forward the packet to this owner peer.
    Forward { owner: &'a str },
    /// Do not forward. The reason is recorded by the caller.
    Drop(SubnetDropReason),
}

/// Decide where a subnet-routed packet goes.
///
/// `owner_is_live` reports whether the caller has a live session to a peer.
/// `source_peer` is the peer the packet arrived from, if any, so a packet is
/// never sent back to its origin.
pub fn decide_subnet_forward<'a, F>(
    table: &'a RouteTable,
    destination: Ipv4Addr,
    source_peer: Option<&str>,
    owner_is_live: F,
) -> SubnetDecision<'a>
where
    F: Fn(&str) -> bool,
{
    let Some(owner) = table.lookup(destination) else {
        return SubnetDecision::Drop(SubnetDropReason::NoRoute);
    };
    if source_peer == Some(owner) {
        return SubnetDecision::Drop(SubnetDropReason::SourceIsOwner);
    }
    if !owner_is_live(owner) {
        return SubnetDecision::Drop(SubnetDropReason::OwnerNotLive);
    }
    SubnetDecision::Forward { owner }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::routes::Ipv4Cidr;

    fn table_with(owner: &str, cidr: &str) -> RouteTable {
        let mut table = RouteTable::new();
        let route = Ipv4Cidr::parse(cidr).expect("valid CIDR");
        table
            .replace_owner_routes(owner, &[route])
            .expect("route accepted");
        table
    }

    #[test]
    fn forwards_to_live_owner() {
        let table = table_with("peer-a", "192.168.1.0/24");
        let decision = decide_subnet_forward(
            &table,
            Ipv4Addr::new(192, 168, 1, 9),
            None,
            |_| true,
        );
        assert_eq!(decision, SubnetDecision::Forward { owner: "peer-a" });
    }

    #[test]
    fn drops_when_no_route_covers_destination() {
        let table = table_with("peer-a", "192.168.1.0/24");
        let decision =
            decide_subnet_forward(&table, Ipv4Addr::new(10, 0, 0, 1), None, |_| true);
        assert_eq!(decision, SubnetDecision::Drop(SubnetDropReason::NoRoute));
    }

    #[test]
    fn drops_when_owner_has_no_live_session() {
        let table = table_with("peer-a", "192.168.1.0/24");
        let decision = decide_subnet_forward(
            &table,
            Ipv4Addr::new(192, 168, 1, 9),
            None,
            |_| false,
        );
        assert_eq!(decision, SubnetDecision::Drop(SubnetDropReason::OwnerNotLive));
    }

    #[test]
    fn never_returns_packet_to_its_source() {
        let table = table_with("peer-a", "192.168.1.0/24");
        let decision = decide_subnet_forward(
            &table,
            Ipv4Addr::new(192, 168, 1, 9),
            Some("peer-a"),
            |_| true,
        );
        assert_eq!(decision, SubnetDecision::Drop(SubnetDropReason::SourceIsOwner));
    }

    #[test]
    fn drop_labels_are_stable() {
        assert_eq!(SubnetDropReason::NoRoute.as_label(), "subnet_no_route");
        assert_eq!(SubnetDropReason::OwnerNotLive.as_label(), "subnet_owner_not_live");
        assert_eq!(SubnetDropReason::SourceIsOwner.as_label(), "subnet_source_is_owner");
    }
}
