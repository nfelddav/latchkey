//! Node configuration, loaded from `config.toml` in the data directory.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Default TCP port for peer connections.
pub const DEFAULT_PORT: u16 = 47470;
/// Default UDP port for multicast discovery.
pub const DEFAULT_DISCOVERY_PORT: u16 = 47471;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Directory holding the identity key, trust file and control socket.
    pub data_dir: PathBuf,
    /// Address to accept peer connections on.
    pub listen: SocketAddr,
    /// Peers to connect to directly, as `host:port`. Use these for nodes that multicast
    /// cannot reach, such as ones on another subnet or across a VPN.
    pub peers: Vec<String>,
    pub discovery: DiscoveryConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoveryConfig {
    /// Announce this node and connect to nodes found on the local network.
    pub enabled: bool,
    /// UDP port shared by all nodes on the network for announcements.
    pub port: u16,
    /// Also announce over IPv6 link-local multicast.
    pub ipv6: bool,
    /// Seconds between announcements.
    pub interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            listen: SocketAddr::from(([0, 0, 0, 0], DEFAULT_PORT)),
            peers: Vec::new(),
            discovery: DiscoveryConfig::default(),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: DEFAULT_DISCOVERY_PORT,
            ipv6: true,
            interval_secs: 5,
        }
    }
}

impl Config {
    /// Load `path` if it exists, otherwise return defaults. `data_dir` defaults to the
    /// directory holding the config file.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            let mut config = Self::default();
            if let Some(dir) = path.parent() {
                config.data_dir = dir.to_path_buf();
            }
            return Ok(config);
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
        let table: toml::Table = text.parse()?;
        if !table.contains_key("data_dir")
            && let Some(dir) = path.parent()
        {
            config.data_dir = dir.to_path_buf();
        }
        Ok(config)
    }

    pub fn identity_path(&self) -> PathBuf {
        self.data_dir.join("identity.key")
    }

    pub fn trust_path(&self) -> PathBuf {
        self.data_dir.join("trusted")
    }

    pub fn control_path(&self) -> PathBuf {
        self.data_dir.join("control.sock")
    }
}

/// The platform data directory, such as `~/.local/share/latchkey` on Linux.
pub fn default_data_dir() -> PathBuf {
    directories::ProjectDirs::from("", "", "latchkey")
        .map(|d| d.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".latchkey"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_config() {
        let config: Config = toml::from_str(
            r#"
            listen = "127.0.0.1:9000"
            peers = ["10.0.0.2:47470"]
            [discovery]
            enabled = false
            port = 9001
            "#,
        )
        .unwrap();
        assert_eq!(config.listen.port(), 9000);
        assert_eq!(config.peers, vec!["10.0.0.2:47470"]);
        assert!(!config.discovery.enabled);
        assert_eq!(config.discovery.port, 9001);
        assert!(config.discovery.ipv6, "unset fields keep their defaults");
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(toml::from_str::<Config>("listn = \"127.0.0.1:1\"").is_err());
    }
}
