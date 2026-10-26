//! End-to-end tests with real nodes talking over loopback TCP.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use latchkey::config::{DiscoveryConfig, RelayPolicy};
use latchkey::{Config, Event, Node, NodeId};
use tokio::sync::broadcast;

fn temp_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "latchkey-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn config() -> Config {
    Config {
        data_dir: temp_dir(),
        listen: "127.0.0.1:0".parse().unwrap(),
        peers: vec![],
        discovery: DiscoveryConfig {
            enabled: false,
            ..Default::default()
        },
        routing: Default::default(),
    }
}

async fn wait_for<F: Fn() -> bool>(what: &str, check: F) {
    for _ in 0..200 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn next_message(events: &mut broadcast::Receiver<Event>) -> (NodeId, bool, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Event::Message {
                from,
                trusted,
                data,
                ..
            } = events.recv().await.unwrap()
            {
                return (from, trusted, data);
            }
        }
    })
    .await
    .expect("no message arrived")
}

#[tokio::test]
async fn connect_send_ping_and_trust() {
    let a = Node::start(config()).await.unwrap();
    let b = Node::start(config()).await.unwrap();
    let mut a_events = a.subscribe();

    assert_eq!(b.connect(a.local_addr()).await.unwrap(), a.id());
    wait_for("a to see b", || a.peers().iter().any(|p| p.id == b.id())).await;

    // Anyone can connect and talk, but connecting does not make a node trusted.
    b.send(&a.id(), b"hello".to_vec()).await.unwrap();
    assert_eq!(
        next_message(&mut a_events).await,
        (b.id(), false, b"hello".to_vec())
    );
    assert!(!a.peers()[0].trusted);

    a.trust(b.id()).unwrap();
    b.send(&a.id(), b"again".to_vec()).await.unwrap();
    assert_eq!(
        next_message(&mut a_events).await,
        (b.id(), true, b"again".to_vec())
    );
    assert!(a.peers()[0].trusted);

    let rtt = b.ping(&a.id()).await.unwrap();
    assert!(rtt < Duration::from_secs(5));
    assert!(a.ping(&b.id()).await.is_ok());

    a.shutdown();
    wait_for("b to notice a left", || b.peers().is_empty()).await;
    b.shutdown();
}

#[tokio::test]
async fn static_peers_connect_automatically() {
    let a = Node::start(config()).await.unwrap();
    let mut cfg = config();
    cfg.peers = vec![a.local_addr().to_string()];
    let b = Node::start(cfg).await.unwrap();

    wait_for("static connection", || {
        b.peers().iter().any(|p| p.id == a.id())
    })
    .await;
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn simultaneous_connects_settle_on_one_link() {
    let a = Node::start(config()).await.unwrap();
    let b = Node::start(config()).await.unwrap();
    let mut b_events = b.subscribe();

    let (ra, rb) = tokio::join!(a.connect(b.local_addr()), b.connect(a.local_addr()));
    assert_eq!(ra.unwrap(), b.id());
    assert_eq!(rb.unwrap(), a.id());

    wait_for("one link each", || {
        a.peers().len() == 1 && b.peers().len() == 1
    })
    .await;
    // Both sides must keep the same connection, so the link still carries traffic.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(a.peers()[0].outbound, !b.peers()[0].outbound);
    a.send(&b.id(), b"still here".to_vec()).await.unwrap();
    assert_eq!(next_message(&mut b_events).await.2, b"still here");

    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn reconnects_after_a_restart() {
    let a = Node::start(config()).await.unwrap();
    let b_config = config();
    let b = Node::start(b_config.clone()).await.unwrap();
    b.connect(a.local_addr()).await.unwrap();
    wait_for("a to register b", || a.peers().len() == 1).await;
    b.shutdown();
    wait_for("a to drop the old link", || a.peers().is_empty()).await;

    // Same identity, new process.
    let b = Node::start(b_config).await.unwrap();
    let mut a_events = a.subscribe();
    b.connect(a.local_addr()).await.unwrap();
    b.send(&a.id(), b"back".to_vec()).await.unwrap();
    assert_eq!(next_message(&mut a_events).await.2, b"back");

    a.shutdown();
    b.shutdown();
}

/// One node dialing the same peer twice at once (say, over IPv4 and IPv6) must leave both
/// sides holding the same link, not each a different one.
#[tokio::test]
async fn duplicate_dials_from_one_side_settle_on_one_link() {
    for _ in 0..3 {
        let a = Node::start(config()).await.unwrap();
        let b = Node::start(config()).await.unwrap();
        let mut b_events = b.subscribe();

        let (r1, r2, r3) = tokio::join!(
            a.connect(b.local_addr()),
            a.connect(b.local_addr()),
            a.connect(b.local_addr()),
        );
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();

        wait_for("one link each", || {
            a.peers().len() == 1 && b.peers().len() == 1
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(a.peers().len(), 1);
        assert_eq!(b.peers().len(), 1);
        a.send(&b.id(), b"one link".to_vec()).await.unwrap();
        assert_eq!(next_message(&mut b_events).await.2, b"one link");

        a.shutdown();
        b.shutdown();
    }
}

#[tokio::test]
async fn refuses_to_connect_to_itself() {
    let a = Node::start(config()).await.unwrap();
    assert!(a.connect(a.local_addr()).await.is_err());
    assert!(a.peers().is_empty());
    a.shutdown();
}

#[tokio::test]
async fn sending_to_an_unknown_peer_fails() {
    let a = Node::start(config()).await.unwrap();
    assert!(a.send(&NodeId([0; 32]), b"x".to_vec()).await.is_err());
    assert!(a.ping(&NodeId([0; 32])).await.is_err());
    a.shutdown();
}

#[tokio::test]
async fn resolve_accepts_unique_prefixes() {
    let a = Node::start(config()).await.unwrap();
    let b = Node::start(config()).await.unwrap();
    b.connect(a.local_addr()).await.unwrap();
    let prefix = &a.id().to_string()[..10];
    assert_eq!(b.resolve(prefix).unwrap(), a.id());
    assert!(b.resolve("zz").is_err());
    a.shutdown();
    b.shutdown();
}

/// Two nodes with nothing configured but a shared discovery port find each other over
/// multicast. Needs a network interface that loops multicast back to the host.
#[tokio::test]
async fn multicast_discovery_connects_nodes() {
    // Discovery depends on the host's network setup; log it so a CI failure explains itself.
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("latchkey=trace")
        .try_init();
    let port = 40000 + (std::process::id() % 20000) as u16;
    let discovery = DiscoveryConfig {
        enabled: true,
        port,
        ipv6: false,
        interval_secs: 1,
    };
    let any: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let a = Node::start(Config {
        listen: any,
        discovery: discovery.clone(),
        ..config()
    })
    .await
    .unwrap();
    let b = Node::start(Config {
        listen: any,
        discovery,
        ..config()
    })
    .await
    .unwrap();

    wait_for("discovery", || {
        a.peers().iter().any(|p| p.id == b.id()) && b.peers().iter().any(|p| p.id == a.id())
    })
    .await;
    a.shutdown();
    b.shutdown();
}

/// A peer that completes the handshake and then never reads must not make `send` hang.
#[tokio::test]
async fn send_fails_instead_of_hanging_when_the_peer_stops_reading() {
    use latchkey::Identity;
    use latchkey::handshake::{Role, handshake};

    let a = Node::start(config()).await.unwrap();
    let mut stalled = tokio::net::TcpStream::connect(a.local_addr())
        .await
        .unwrap();
    let mallory = Identity::generate().unwrap();
    handshake(&mut stalled, &mallory, Role::Initiator)
        .await
        .unwrap();
    wait_for("a to register the peer", || a.peers().len() == 1).await;

    let payload = vec![0u8; latchkey::node::MAX_MESSAGE];
    let outcome = tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            if let Err(e) = a.send(&mallory.id(), payload.clone()).await {
                return e;
            }
        }
    })
    .await
    .expect("send hung");
    println!("send failed as expected: {outcome:#}");
    drop(stalled);
    a.shutdown();
}

async fn next_routed(events: &mut broadcast::Receiver<Event>) -> (NodeId, Vec<u8>, Vec<NodeId>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Event::Message {
                from, data, via, ..
            } = events.recv().await.unwrap()
            {
                return (from, data, via);
            }
        }
    })
    .await
    .expect("no message arrived")
}

/// Connect `nodes` in a line, each to the next.
async fn chain(nodes: &[&Node]) {
    for pair in nodes.windows(2) {
        pair[1].connect(pair[0].local_addr()).await.unwrap();
    }
}

/// A and B are not connected to each other, only to R. Once A trusts R, A can reach B through
/// it, and B learns which relay carried the message.
#[tokio::test]
async fn messages_route_through_a_trusted_relay() {
    let a = Node::start(config()).await.unwrap();
    let r = Node::start(config()).await.unwrap();
    let b = Node::start(config()).await.unwrap();
    let mut b_events = b.subscribe();
    chain(&[&a, &r, &b]).await;

    wait_for("a to learn about b", || {
        a.routes().iter().any(|route| route.id == b.id())
    })
    .await;
    // A doesn't trust R yet, so there is no route it may use.
    assert_eq!(a.route(&b.id()), None);
    assert!(a.send(&b.id(), b"too soon".to_vec()).await.is_err());

    a.trust(r.id()).unwrap();
    wait_for("a to find a route to b", || a.route(&b.id()).is_some()).await;
    assert_eq!(a.route(&b.id()), Some(vec![r.id()]));
    assert_eq!(
        a.send(&b.id(), b"hi b".to_vec()).await.unwrap(),
        vec![r.id()]
    );
    assert_eq!(
        next_routed(&mut b_events).await,
        (a.id(), b"hi b".to_vec(), vec![r.id()])
    );

    // B doesn't trust R, so it cannot answer the same way.
    assert!(b.send(&a.id(), b"reply".to_vec()).await.is_err());

    for n in [a, r, b] {
        n.shutdown();
    }
}

#[tokio::test]
async fn messages_cross_several_relays() {
    let nodes = start_nodes(4).await;
    let [a, r1, r2, b] = &nodes[..] else {
        unreachable!()
    };
    let mut b_events = b.subscribe();
    chain(&[a, r1, r2, b]).await;
    a.trust(r1.id()).unwrap();
    a.trust(r2.id()).unwrap();

    wait_for("a to find a route to b", || a.route(&b.id()).is_some()).await;
    assert_eq!(a.route(&b.id()), Some(vec![r1.id(), r2.id()]));
    a.send(&b.id(), b"far".to_vec()).await.unwrap();
    assert_eq!(
        next_routed(&mut b_events).await,
        (a.id(), b"far".to_vec(), vec![r1.id(), r2.id()])
    );
    for n in &nodes {
        n.shutdown();
    }
}

async fn start_nodes(n: usize) -> Vec<Node> {
    let mut nodes = Vec::new();
    for _ in 0..n {
        nodes.push(Node::start(config()).await.unwrap());
    }
    nodes
}

/// A relay set to relay only for trusted peers drops messages handed over by anyone else.
#[tokio::test]
async fn relays_can_refuse_untrusted_senders() {
    let a = Node::start(config()).await.unwrap();
    let r = Node::start(Config {
        routing: latchkey::config::RoutingConfig {
            relay_for: RelayPolicy::Trusted,
        },
        ..config()
    })
    .await
    .unwrap();
    let b = Node::start(config()).await.unwrap();
    let mut b_events = b.subscribe();
    chain(&[&a, &r, &b]).await;
    a.trust(r.id()).unwrap();
    wait_for("a to find a route to b", || a.route(&b.id()).is_some()).await;

    a.send(&b.id(), b"dropped".to_vec()).await.unwrap();
    let got = tokio::time::timeout(Duration::from_millis(500), next_routed(&mut b_events)).await;
    assert!(got.is_err(), "relay forwarded for an untrusted sender");

    r.trust(a.id()).unwrap();
    a.send(&b.id(), b"allowed".to_vec()).await.unwrap();
    assert_eq!(next_routed(&mut b_events).await.1, b"allowed");

    for n in [a, r, b] {
        n.shutdown();
    }
}

/// When a relay leaves, routes through it disappear once its neighbors re-advertise.
#[tokio::test]
async fn routes_follow_topology_changes() {
    let a = Node::start(config()).await.unwrap();
    let r = Node::start(config()).await.unwrap();
    let b = Node::start(config()).await.unwrap();
    chain(&[&a, &r, &b]).await;
    a.trust(r.id()).unwrap();
    wait_for("a to find a route to b", || a.route(&b.id()).is_some()).await;

    r.shutdown();
    wait_for("the route to b to go away", || a.route(&b.id()).is_none()).await;
    a.shutdown();
    b.shutdown();
}
