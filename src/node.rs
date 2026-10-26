//! A running Latchkey node: listener, discovery, peer table, and the library API.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::config::Config;
use crate::discovery::{self, Sighting};
use crate::handshake::{Established, Role, handshake};
use crate::identity::{Identity, NodeId};
use crate::trust::TrustStore;
use crate::wire::{MAX_FRAME, Message, read_frame, write_frame};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// A link with no incoming frames for this long is considered dead.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const STATIC_PEER_RETRY: Duration = Duration::from_secs(15);
/// Largest payload `send` accepts: a frame minus the AEAD tag and message tag.
pub const MAX_MESSAGE: usize = MAX_FRAME - 16 - 1;

/// Something that happened on the node.
#[derive(Debug, Clone)]
pub enum Event {
    PeerConnected {
        id: NodeId,
        addr: SocketAddr,
        trusted: bool,
    },
    PeerDisconnected {
        id: NodeId,
    },
    /// A direct message from a connected peer. `trusted` says whether the sender is on the
    /// allowlist; the sender's identity is always authenticated either way.
    Message {
        from: NodeId,
        trusted: bool,
        data: Vec<u8>,
    },
}

/// A snapshot of one connected peer.
#[derive(Debug, Clone, Serialize)]
pub struct PeerInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub trusted: bool,
    /// True if this node opened the connection.
    pub outbound: bool,
    pub connected_secs: u64,
}

/// A handle to a running node. Cloning it gives another handle to the same node.
#[derive(Clone)]
pub struct Node {
    inner: Arc<Inner>,
}

struct Inner {
    identity: Identity,
    local_addr: SocketAddr,
    trust: Mutex<TrustStore>,
    peers: Mutex<HashMap<NodeId, Peer>>,
    dialing: Mutex<HashSet<SocketAddr>>,
    /// Discovered nodes we are dialing, so IPv4 and IPv6 sightings don't race each other.
    dialing_ids: Mutex<HashSet<NodeId>>,
    pings: Mutex<HashMap<u64, oneshot::Sender<()>>>,
    /// Node ID last seen at each static peer address, so we do not redial a connected peer.
    static_ids: Mutex<HashMap<SocketAddr, NodeId>>,
    events: broadcast::Sender<Event>,
    shutdown: watch::Sender<bool>,
    next_conn: AtomicU64,
}

struct Peer {
    addr: SocketAddr,
    initiator: NodeId,
    conn: u64,
    tx: mpsc::Sender<Message>,
    since: Instant,
    /// Dropped when this entry is replaced or removed, which closes the connection.
    _close: oneshot::Sender<()>,
}

impl Node {
    /// Load the identity and trust list from `config.data_dir`, bind the listener, and start
    /// discovery and static peer connections.
    pub async fn start(config: Config) -> Result<Self> {
        let identity = Identity::load_or_create(&config.identity_path())?;
        let trust = TrustStore::load(&config.trust_path())?;
        let listener = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("binding {}", config.listen))?;
        let local_addr = listener.local_addr()?;
        let (shutdown, _) = watch::channel(false);
        let node = Node {
            inner: Arc::new(Inner {
                identity,
                local_addr,
                trust: Mutex::new(trust),
                peers: Mutex::default(),
                dialing: Mutex::default(),
                dialing_ids: Mutex::default(),
                pings: Mutex::default(),
                static_ids: Mutex::default(),
                events: broadcast::channel(256).0,
                shutdown,
                next_conn: AtomicU64::new(0),
            }),
        };
        tracing::info!("node {} listening on {local_addr}", node.id());

        tokio::spawn(node.clone().accept_loop(listener));

        if config.discovery.enabled {
            if local_addr.ip().is_loopback() {
                tracing::warn!(
                    "listening on loopback {local_addr}: other hosts will discover this node but cannot connect"
                );
            }
            let (found_tx, found_rx) = mpsc::channel(64);
            discovery::spawn(
                &config.discovery,
                node.id(),
                local_addr.port(),
                found_tx,
                node.inner.shutdown.subscribe(),
            );
            tokio::spawn(node.clone().discovery_loop(found_rx));
        }
        if !config.peers.is_empty() {
            tokio::spawn(node.clone().static_peer_loop(config.peers.clone()));
        }
        Ok(node)
    }

    pub fn id(&self) -> NodeId {
        self.inner.identity.id()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr
    }

    /// Receive node events. Slow receivers miss events rather than block the node.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.inner.events.subscribe()
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        let me = self.id();
        let trust = self.inner.trust.lock().unwrap();
        let mut peers: Vec<PeerInfo> = self
            .inner
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|(id, p)| PeerInfo {
                id: *id,
                addr: p.addr,
                trusted: trust.is_trusted(id),
                outbound: p.initiator == me,
                connected_secs: p.since.elapsed().as_secs(),
            })
            .collect();
        peers.sort_by_key(|p| p.id);
        peers
    }

    pub fn is_trusted(&self, id: &NodeId) -> bool {
        self.inner.trust.lock().unwrap().is_trusted(id)
    }

    pub fn trusted(&self) -> Vec<NodeId> {
        self.inner.trust.lock().unwrap().list().copied().collect()
    }

    /// Add `id` to the allowlist. Returns false if it was already trusted.
    pub fn trust(&self, id: NodeId) -> Result<bool> {
        self.inner.trust.lock().unwrap().trust(id)
    }

    /// Remove `id` from the allowlist. Returns false if it was not trusted.
    pub fn untrust(&self, id: &NodeId) -> Result<bool> {
        self.inner.trust.lock().unwrap().untrust(id)
    }

    /// Resolve a full node ID or a unique hex prefix of a connected or trusted node.
    pub fn resolve(&self, query: &str) -> Result<NodeId> {
        let query = query.trim().to_ascii_lowercase();
        if let Ok(id) = query.parse() {
            return Ok(id);
        }
        if query.is_empty() {
            bail!("empty node ID");
        }
        let mut known: HashSet<NodeId> = self.inner.peers.lock().unwrap().keys().copied().collect();
        known.extend(self.trusted());
        let matches: Vec<NodeId> = known
            .into_iter()
            .filter(|id| id.to_string().starts_with(&query))
            .collect();
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => bail!("no connected or trusted node matches {query:?}"),
            _ => bail!(
                "{query:?} matches {} nodes; use a longer prefix",
                matches.len()
            ),
        }
    }

    /// Connect to a node at `addr` and return its authenticated node ID.
    pub async fn connect(&self, addr: SocketAddr) -> Result<NodeId> {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .context("connect timed out")?
            .with_context(|| format!("connecting to {addr}"))?;
        self.clone().establish(stream, addr, Role::Initiator).await
    }

    /// Send a direct message to a connected peer.
    pub async fn send(&self, peer: &NodeId, data: Vec<u8>) -> Result<()> {
        if data.len() > MAX_MESSAGE {
            bail!(
                "message is {} bytes; the limit is {MAX_MESSAGE}",
                data.len()
            );
        }
        let tx = self.sender(peer)?;
        tx.send(Message::Data(data))
            .await
            .map_err(|_| anyhow::anyhow!("peer disconnected"))
    }

    /// Measure the round-trip time to a connected peer.
    pub async fn ping(&self, peer: &NodeId) -> Result<Duration> {
        let tx = self.sender(peer)?;
        let nonce = loop {
            let n = getrandom::u64().map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
            if n != 0 {
                break n;
            }
        };
        let (done_tx, done_rx) = oneshot::channel();
        self.inner.pings.lock().unwrap().insert(nonce, done_tx);
        let start = Instant::now();
        let result = async {
            tx.send(Message::Ping(nonce))
                .await
                .map_err(|_| anyhow::anyhow!("peer disconnected"))?;
            tokio::time::timeout(PING_TIMEOUT, done_rx)
                .await
                .context("ping timed out")?
                .context("peer disconnected")
        }
        .await;
        self.inner.pings.lock().unwrap().remove(&nonce);
        result.map(|()| start.elapsed())
    }

    /// Stop all background tasks and close every connection.
    pub fn shutdown(&self) {
        self.inner.shutdown.send_replace(true);
    }

    fn sender(&self, peer: &NodeId) -> Result<mpsc::Sender<Message>> {
        match self.inner.peers.lock().unwrap().get(peer) {
            Some(p) => Ok(p.tx.clone()),
            None => bail!("not connected to {}", peer.short()),
        }
    }

    fn emit(&self, event: Event) {
        let _ = self.inner.events.send(event);
    }

    async fn accept_loop(self, listener: TcpListener) {
        let mut shutdown = self.inner.shutdown.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                accepted = listener.accept() => match accepted {
                    Ok((stream, addr)) => {
                        let node = self.clone();
                        tokio::spawn(async move {
                            if let Err(e) = node.establish(stream, addr, Role::Responder).await {
                                tracing::debug!("inbound connection from {addr} failed: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
            }
        }
    }

    async fn discovery_loop(self, mut found: mpsc::Receiver<Sighting>) {
        while let Some(Sighting { id, addr }) = found.recv().await {
            if !discovery::dialable(&addr) || self.inner.peers.lock().unwrap().contains_key(&id) {
                continue;
            }
            if !self.inner.dialing_ids.lock().unwrap().insert(id) {
                continue;
            }
            tracing::debug!("discovered {} at {addr}", id.short());
            self.spawn_dial(addr, Some(id));
        }
    }

    async fn static_peer_loop(self, peers: Vec<String>) {
        let mut shutdown = self.inner.shutdown.subscribe();
        let mut ticker = tokio::time::interval(STATIC_PEER_RETRY);
        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = ticker.tick() => {}
            }
            for spec in &peers {
                let addrs = match tokio::net::lookup_host(spec.as_str()).await {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        tracing::warn!("cannot resolve static peer {spec}: {e}");
                        continue;
                    }
                };
                for addr in addrs {
                    let known = self.inner.static_ids.lock().unwrap().get(&addr).copied();
                    let connected =
                        known.is_some_and(|id| self.inner.peers.lock().unwrap().contains_key(&id));
                    if !connected {
                        self.spawn_dial(addr, None);
                    }
                }
            }
        }
    }

    /// Dial `addr` in the background. `discovered` is the node ID a multicast announcement
    /// claimed, released from `dialing_ids` once the attempt ends.
    fn spawn_dial(&self, addr: SocketAddr, discovered: Option<NodeId>) {
        if !self.inner.dialing.lock().unwrap().insert(addr) {
            if let Some(id) = discovered {
                self.inner.dialing_ids.lock().unwrap().remove(&id);
            }
            return;
        }
        let node = self.clone();
        tokio::spawn(async move {
            match node.connect(addr).await {
                Ok(id) => {
                    node.inner.static_ids.lock().unwrap().insert(addr, id);
                }
                Err(e) => tracing::debug!("dial {addr} failed: {e:#}"),
            }
            node.inner.dialing.lock().unwrap().remove(&addr);
            if let Some(id) = discovered {
                node.inner.dialing_ids.lock().unwrap().remove(&id);
            }
        });
    }

    /// Run the handshake, register the peer, and spawn the connection's I/O task.
    async fn establish(
        self,
        mut stream: TcpStream,
        addr: SocketAddr,
        role: Role,
    ) -> Result<NodeId> {
        stream.set_nodelay(true)?;
        let Established { peer, send, recv } = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake(&mut stream, &self.inner.identity, role),
        )
        .await
        .context("handshake timed out")??;
        if peer == self.id() {
            bail!("connected to ourselves");
        }
        let initiator = if role == Role::Initiator {
            self.id()
        } else {
            peer
        };
        let (tx, rx) = mpsc::channel(64);
        let conn = self.inner.next_conn.fetch_add(1, Ordering::Relaxed);
        let (close_tx, close_rx) = oneshot::channel();
        if !self.register(
            peer,
            Peer {
                addr,
                initiator,
                conn,
                tx: tx.clone(),
                since: Instant::now(),
                _close: close_tx,
            },
        ) {
            // Keeping the existing duplicate. Report success: the peer is connected.
            return Ok(peer);
        }
        let trusted = self.is_trusted(&peer);
        tracing::info!(
            "connected to {} at {addr} ({})",
            peer.short(),
            if trusted { "trusted" } else { "untrusted" }
        );
        self.emit(Event::PeerConnected {
            id: peer,
            addr,
            trusted,
        });
        tokio::spawn(self.run_connection(stream, peer, conn, send, recv, tx, rx, close_rx));
        Ok(peer)
    }

    /// Add the peer to the table. When two connections to the same peer race, both nodes keep
    /// the one opened by the node with the lower ID, so they agree without coordinating.
    /// A newer connection opened by the same side replaces the old one, which is likely stale.
    fn register(&self, id: NodeId, new: Peer) -> bool {
        let mut peers = self.inner.peers.lock().unwrap();
        if let Some(existing) = peers.get(&id) {
            let preferred = self.id().min(id);
            let keep_new = existing.initiator == new.initiator || new.initiator == preferred;
            if !keep_new {
                return false;
            }
        }
        peers.insert(id, new);
        true
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_connection(
        self,
        stream: TcpStream,
        peer: NodeId,
        conn: u64,
        mut send: crate::handshake::SendCipher,
        mut recv: crate::handshake::RecvCipher,
        tx: mpsc::Sender<Message>,
        mut rx: mpsc::Receiver<Message>,
        mut close: oneshot::Receiver<()>,
    ) {
        let (mut reader, mut writer) = stream.into_split();
        let mut shutdown = self.inner.shutdown.subscribe();

        let write_loop = async {
            let mut keepalive = tokio::time::interval(KEEPALIVE_INTERVAL);
            keepalive.tick().await;
            loop {
                let msg = tokio::select! {
                    msg = rx.recv() => match msg {
                        Some(msg) => msg,
                        None => return Ok(()),
                    },
                    _ = keepalive.tick() => Message::Ping(0),
                };
                write_frame(&mut writer, &send.seal(&msg.encode())?).await?;
            }
        };

        let read_loop = async {
            loop {
                let frame = tokio::time::timeout(IDLE_TIMEOUT, read_frame(&mut reader))
                    .await
                    .context("peer went silent")??;
                match Message::decode(&recv.open(&frame)?)? {
                    Message::Ping(n) => {
                        // A full queue means the peer is flooding us; drop the pong.
                        let _ = tx.try_send(Message::Pong(n));
                    }
                    Message::Pong(0) => {}
                    Message::Pong(n) => {
                        if let Some(done) = self.inner.pings.lock().unwrap().remove(&n) {
                            let _ = done.send(());
                        }
                    }
                    Message::Data(data) => {
                        let trusted = self.is_trusted(&peer);
                        self.emit(Event::Message {
                            from: peer,
                            trusted,
                            data,
                        });
                    }
                    Message::Auth { .. } => bail!("unexpected auth message"),
                }
            }
        };

        let outcome: Result<()> = tokio::select! {
            r = write_loop => r,
            r = read_loop => r,
            _ = shutdown.changed() => Ok(()),
            _ = &mut close => Ok(()),
        };
        if let Err(e) = outcome {
            tracing::debug!("connection to {} closed: {e:#}", peer.short());
        }

        let removed = {
            let mut peers = self.inner.peers.lock().unwrap();
            if peers.get(&peer).is_some_and(|p| p.conn == conn) {
                peers.remove(&peer);
                true
            } else {
                false
            }
        };
        if removed {
            tracing::info!("disconnected from {}", peer.short());
            self.emit(Event::PeerDisconnected { id: peer });
        }
    }
}
