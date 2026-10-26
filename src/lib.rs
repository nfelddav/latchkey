//! Latchkey: a peer-to-peer mesh network secured with post-quantum cryptography.
//!
//! Nodes find each other on the local network with UDP multicast, connect over TCP, and
//! secure every link with a hybrid X25519 + ML-KEM-768 key exchange authenticated by
//! ML-DSA-65 identity keys. Anyone may connect; trust is a separate, explicit allowlist.
//! Messages to nodes that aren't directly connected are routed only through trusted relays and
//! sealed end to end.
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! use latchkey::{Config, Event, Node};
//!
//! let node = Node::start(Config::default()).await?;
//! let mut events = node.subscribe();
//! while let Ok(event) = events.recv().await {
//!     if let Event::Message { from, trusted, data, .. } = event {
//!         println!("{} (trusted: {trusted}): {}", from.short(), String::from_utf8_lossy(&data));
//!         node.send(&from, b"got it".to_vec()).await?;
//!     }
//! }
//! # Ok(()) }
//! ```

pub mod config;
#[cfg(unix)]
pub mod control;
pub mod discovery;
pub mod display;
pub mod handshake;
pub mod identity;
pub mod node;
pub mod routing;
pub mod trust;
pub mod wire;

pub use config::Config;
pub use identity::{Identity, NodeId};
pub use node::{Event, Node, PeerInfo};
