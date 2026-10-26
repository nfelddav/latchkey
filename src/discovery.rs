//! Local network discovery over UDP multicast.
//!
//! Every node periodically announces its node ID and TCP port to a well-known multicast group.
//! Announcements are unauthenticated hints: they only tell a node where to try a handshake,
//! and the handshake is what proves who is on the other end.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};

use crate::config::DiscoveryConfig;
use crate::identity::NodeId;

/// Administratively scoped IPv4 group (RFC 2365), so announcements stay on the local site.
pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 76, 75);
/// Link-local IPv6 group.
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x6c6b, 0x7931);

const ANNOUNCE_MAGIC: &[u8; 4] = b"LKA1";
const ANNOUNCE_LEN: usize = 4 + 32 + 2;

/// A node seen on the local network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sighting {
    pub id: NodeId,
    pub addr: SocketAddr,
}

pub fn encode_announce(id: &NodeId, tcp_port: u16) -> Vec<u8> {
    [&ANNOUNCE_MAGIC[..], &id.0, &tcp_port.to_be_bytes()].concat()
}

pub fn decode_announce(packet: &[u8]) -> Option<(NodeId, u16)> {
    if packet.len() != ANNOUNCE_LEN || &packet[..4] != ANNOUNCE_MAGIC {
        return None;
    }
    let id = NodeId(packet[4..36].try_into().ok()?);
    let port = u16::from_be_bytes([packet[36], packet[37]]);
    Some((id, port))
}

/// Start announcing `id` and reporting other nodes' announcements on `found`.
///
/// Runs until `shutdown` flips to true. Failing to set up one address family is logged and
/// skipped, so a host without IPv6 multicast still discovers over IPv4.
pub fn spawn(
    config: &DiscoveryConfig,
    id: NodeId,
    tcp_port: u16,
    found: mpsc::Sender<Sighting>,
    shutdown: watch::Receiver<bool>,
) {
    let interval = Duration::from_secs(config.interval_secs.max(1));
    let port = config.port;
    match bind_v4(port) {
        Ok(socket) => {
            let target = SocketAddr::from((GROUP_V4, port));
            tokio::spawn(run(
                socket,
                target,
                id,
                tcp_port,
                interval,
                found.clone(),
                shutdown.clone(),
            ));
        }
        Err(e) => tracing::warn!("IPv4 multicast discovery unavailable: {e:#}"),
    }
    if config.ipv6 {
        match bind_v6(port) {
            Ok(socket) => {
                let target = SocketAddr::from((GROUP_V6, port));
                tokio::spawn(run(socket, target, id, tcp_port, interval, found, shutdown));
            }
            Err(e) => tracing::debug!("IPv6 multicast discovery unavailable: {e:#}"),
        }
    }
}

async fn run(
    socket: UdpSocket,
    target: SocketAddr,
    id: NodeId,
    tcp_port: u16,
    interval: Duration,
    found: mpsc::Sender<Sighting>,
    mut shutdown: watch::Receiver<bool>,
) {
    let announcement = encode_announce(&id, tcp_port);
    let mut ticker = tokio::time::interval(interval);
    let mut buf = [0u8; 64];
    let mut warned = false;
    loop {
        tokio::select! {
            _ = shutdown.changed() => return,
            _ = ticker.tick() => {
                if let Err(e) = socket.send_to(&announcement, target).await
                    && !warned {
                        tracing::warn!("multicast announce to {target} failed: {e}");
                        warned = true;
                    }
            }
            received = socket.recv_from(&mut buf) => {
                let Ok((len, from)) = received else { continue };
                let Some((peer, port)) = decode_announce(&buf[..len]) else { continue };
                if peer == id {
                    continue;
                }
                let addr = SocketAddr::new(from.ip(), port);
                let addr = match (addr, from) {
                    (SocketAddr::V6(mut v6), SocketAddr::V6(src)) => {
                        v6.set_scope_id(src.scope_id());
                        SocketAddr::V6(v6)
                    }
                    _ => addr,
                };
                if found.send(Sighting { id: peer, addr }).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn shared_socket(domain: Domain) -> Result<Socket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn bind_v4(port: u16) -> Result<UdpSocket> {
    let socket = shared_socket(Domain::IPV4)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)).into())?;
    socket.join_multicast_v4(&GROUP_V4, &Ipv4Addr::UNSPECIFIED)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_multicast_ttl_v4(1)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

fn bind_v6(port: u16) -> Result<UdpSocket> {
    let socket = shared_socket(Domain::IPV6)?;
    socket.set_only_v6(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    socket.join_multicast_v6(&GROUP_V6, 0)?;
    socket.set_multicast_loop_v6(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// True for addresses discovery should dial. Filters out unspecified and multicast sources.
pub fn dialable(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announce_round_trips() {
        let id = NodeId([5; 32]);
        assert_eq!(
            decode_announce(&encode_announce(&id, 47470)),
            Some((id, 47470))
        );
    }

    #[test]
    fn rejects_foreign_packets() {
        assert_eq!(decode_announce(b"hello"), None);
        let mut packet = encode_announce(&NodeId([1; 32]), 1);
        packet[0] = b'X';
        assert_eq!(decode_announce(&packet), None);
    }
}
