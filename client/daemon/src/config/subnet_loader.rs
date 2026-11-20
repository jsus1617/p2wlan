//! Loader for the subnet-router sidecar document.
//!
//! Reads the standalone subnet-router JSON file and returns its validated
//! routes. A missing file is not an error: it means this node advertises no
//! subnet. Any other read failure, or an invalid document, is reported so the
//! caller can refuse to start with a bad subnet config.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::routes::Ipv4Cidr;
use super::routes_config::{parse_subnet_router_config, SubnetConfigError};

/// File name of the subnet-router sidecar, stored next to the main config.
pub const SUBNET_ROUTER_FILE_NAME: &str = "subnet_router.json";

/// Path of the sidecar document for a given config directory.
pub fn subnet_router_path(config_dir: &Path) -> PathBuf {
    config_dir.join(SUBNET_ROUTER_FILE_NAME)
}

/// Failure while loading the subnet-router sidecar document.
#[derive(Debug)]
pub enum SubnetLoadError {
    /// The file exists but could not be read.
    Read(String),
    /// The file was read but its contents are not a valid subnet config.
    Config(SubnetConfigError),
}

impl std::fmt::Display for SubnetLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(message) => write!(f, "failed to read subnet router config: {message}"),
            Self::Config(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SubnetLoadError {}

/// Load the advertised subnet routes from the sidecar at `path`.
///
/// Returns an empty list when the file does not exist. Otherwise the document
/// is parsed and validated against `mesh_cidr` by `parse_subnet_router_config`.
pub fn load_subnet_routes(path: &Path, mesh_cidr: &str) -> Result<Vec<Ipv4Cidr>, SubnetLoadError> {
    let document = match std::fs::read_to_string(path) {
        Ok(document) => document,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(SubnetLoadError::Read(format!("{}: {error}", path.display())));
        }
    };
    parse_subnet_router_config(&document, mesh_cidr).map_err(SubnetLoadError::Config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESH: &str = "10.20.0.0/16";

    fn temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("p2wlan-subnet-{name}-{}-{nanos}.json", std::process::id()))
    }

    #[test]
    fn missing_file_yields_no_routes() {
        let path = temp_path("missing");
        let routes = load_subnet_routes(&path, MESH).expect("missing file is not an error");
        assert!(routes.is_empty());
    }

    #[test]
    fn loads_valid_document() {
        let path = temp_path("valid");
        std::fs::write(&path, r#"{"advertise_routes": ["192.168.1.0/24"]}"#).expect("write");
        let routes = load_subnet_routes(&path, MESH).expect("valid document loads");
        std::fs::remove_file(&path).ok();
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn rejects_invalid_document() {
        let path = temp_path("invalid");
        std::fs::write(&path, "not json").expect("write");
        let result = load_subnet_routes(&path, MESH);
        std::fs::remove_file(&path).ok();
        assert!(matches!(result, Err(SubnetLoadError::Config(_))));
    }

    #[test]
    fn sidecar_path_uses_fixed_name() {
        let path = subnet_router_path(Path::new("/etc/p2wlan"));
        assert!(path.ends_with(SUBNET_ROUTER_FILE_NAME));
    }
}
