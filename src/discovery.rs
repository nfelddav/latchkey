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
        Ok((listen, send)) => {
            let target = SocketAddr::from((GROUP_V4, port));
            tokio::spawn(run(
                listen,
                send,
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
            Ok((listen, send)) => {
                let target = SocketAddr::from((GROUP_V6, port));
                tokio::spawn(run(
                    listen, send, target, id, tcp_port, interval, found, shutdown,
                ));
            }
            Err(e) => tracing::debug!("IPv6 multicast discovery unavailable: {e:#}"),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    listen: UdpSocket,
    send: UdpSocket,
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
                if let Err(e) = send.send_to(&announcement, target).await
                    && !warned {
                        tracing::warn!("multicast announce to {target} failed: {e}");
                        warned = true;
                    }
            }
            received = listen.recv_from(&mut buf) => {
                let Ok((len, from)) = received else { continue };
                let Some((peer, port)) = decode_announce(&buf[..len]) else { continue };
                if peer == id || !on_link_source(&from.ip()) {
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

/// The address the IPv4 listening socket binds to. On Unix, binding to the group address
/// itself means the kernel only delivers datagrams sent to the group, so a host that can merely
/// reach the port with unicast (from anywhere, with a spoofed source) cannot inject
/// announcements.
fn listen_addr_v4(port: u16) -> SocketAddr {
    if cfg!(unix) {
        SocketAddr::from((GROUP_V4, port))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
    }
}

/// True if an announcement from `source` may have come from the local network.
///
/// IPv4 relies on the socket being bound to the group. IPv6 announcements go to a link-local
/// group and so carry a link-local source, which routers never forward; requiring one rejects
/// anything from off the link.
pub fn on_link_source(source: &IpAddr) -> bool {
    match source {
        IpAddr::V4(_) => true,
        IpAddr::V6(ip) => (ip.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Returns (listening socket, sending socket).
fn bind_v4(port: u16) -> Result<(UdpSocket, UdpSocket)> {
    let listen = shared_socket(Domain::IPV4)?;
    listen.bind(&listen_addr_v4(port).into())?;
    listen.join_multicast_v4(&GROUP_V4, &Ipv4Addr::UNSPECIFIED)?;

    let send = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    send.set_nonblocking(true)?;
    send.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;
    send.set_multicast_loop_v4(true)?;
    send.set_multicast_ttl_v4(1)?;
    Ok((
        UdpSocket::from_std(listen.into())?,
        UdpSocket::from_std(send.into())?,
    ))
}

/// Returns (listening socket, sending socket).
fn bind_v6(port: u16) -> Result<(UdpSocket, UdpSocket)> {
    let listen = shared_socket(Domain::IPV6)?;
    listen.set_only_v6(true)?;
    listen.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    listen.join_multicast_v6(&GROUP_V6, 0)?;

    let send = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    send.set_nonblocking(true)?;
    send.set_only_v6(true)?;
    send.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
    send.set_multicast_loop_v6(true)?;
    send.set_multicast_hops_v6(1)?;
    Ok((
        UdpSocket::from_std(listen.into())?,
        UdpSocket::from_std(send.into())?,
    ))
}

/// True for announced addresses discovery should dial: a unicast source and an unprivileged
/// port. The port check stops forged announcements from pointing nodes at services such as
/// SSH; Latchkey's own port is always 1024 or above.
pub fn dialable(addr: &SocketAddr) -> bool {
    let ip_ok = match addr.ip() {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
    };
    ip_ok && addr.port() >= 1024
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
    fn dials_only_unicast_unprivileged_addresses() {
        assert!(dialable(&"192.168.1.5:47470".parse().unwrap()));
        assert!(dialable(&"[fe80::1]:47470".parse().unwrap()));
        assert!(!dialable(&"192.168.1.5:22".parse().unwrap()));
        assert!(!dialable(&"0.0.0.0:47470".parse().unwrap()));
        assert!(!dialable(&"239.255.76.75:47470".parse().unwrap()));
    }

    /// A datagram sent straight to the host (not to the group) must not reach discovery.
    #[cfg(unix)]
    #[tokio::test]
    async fn ignores_unicast_announcements() {
        let port = 30000 + (std::process::id() % 20000) as u16;
        let (listen, _send) = bind_v4(port).unwrap();
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(
                &encode_announce(&NodeId([1; 32]), 5000),
                ("127.0.0.1", port),
            )
            .unwrap();
        let mut buf = [0u8; 64];
        let got =
            tokio::time::timeout(Duration::from_millis(300), listen.recv_from(&mut buf)).await;
        assert!(got.is_err(), "unicast datagram was delivered: {got:?}");
    }

    #[test]
    fn ipv6_announcements_must_come_from_link_local_addresses() {
        assert!(on_link_source(&"fe80::1".parse().unwrap()));
        assert!(!on_link_source(&"2001:db8::1".parse().unwrap()));
        assert!(!on_link_source(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn rejects_foreign_packets() {
        assert_eq!(decode_announce(b"hello"), None);
        let mut packet = encode_announce(&NodeId([1; 32]), 1);
        packet[0] = b'X';
        assert_eq!(decode_announce(&packet), None);
    }
}
