//! Node configuration management.
//!
//! Handles loading/saving node configuration including:
//! - Node identity (key pair, node ID)
//! - Network settings (virtual IP, MTU, CIDR)
//! - Control server endpoint
//! - Relay servers
//! - Port mappings

use serde::{de::Deserializer, Deserialize, Serialize};
#[cfg(not(unix))]
use std::io::Write;
use std::path::Path;

use crate::error::{DaemonError, Result};

include!("config/types.rs");
#[cfg(unix)]
#[path = "config/private_file.rs"]
mod private_file;
include!("config/persistence.rs");
include!("config/hostname.rs");
// Subnet-route validation and LPM table. Not yet wired into NetworkConfig;
// that needs the full types.rs, which has not been edited in this change.
#[allow(dead_code)]
mod routes;
#[allow(dead_code)]
mod routes_config;
#[cfg(test)]
include!("config/tests.rs");
#[cfg(all(test, unix))]
#[path = "config/persistence_tests.rs"]
mod persistence_tests;
