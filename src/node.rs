//! A running Latchkey node: listener, discovery, peer table, and the library API.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, broadcast, mpsc, oneshot, watch};

use crate::config::{Config, RelayPolicy};
use crate::discovery::{self, Sighting};
use crate::handshake::{Established, Role, handshake};
use crate::identity::{Identity, NodeId};
use crate::routing::{
    self, ENVELOPE_OVERHEAD, Envelope, KeyRing, LSA_MIN_INTERVAL, LSA_REFRESH, LinkState,
    ReplayGuard, Topology,
};
use crate::trust::TrustStore;
use crate::wire::{MAX_FRAME, Message, read_frame, write_frame};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// A link with no incoming frames for this long is considered dead.
const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
const STATIC_PEER_RETRY: Duration = Duration::from_secs(15);
/// How long `send` waits for room in a peer's queue before giving up.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// A link whose peer stops reading for this long is closed.
const WRITE_TIMEOUT: Duration = Duration::from_secs(20);
/// Two links to the same peer that both formed within this window are treated as a race;
/// outside it, the newer link replaces the older, which is likely stale.
const RACE_WINDOW: Duration = Duration::from_secs(10);
/// Background dials (discovery and static peers) in flight at once.
const MAX_DIALS: usize = 16;
/// Inbound handshakes in progress at once. Extra connections are closed immediately.
const MAX_INBOUND_HANDSHAKES: usize = 32;
/// Connected peers. New peers beyond this are refused.
pub const MAX_PEERS: usize = 256;
/// Largest payload `send` accepts: a frame minus the link's AEAD tag, the message tag, and
/// the overhead of a routed envelope, so the same limit holds whether or not a message is
/// routed.
pub const MAX_MESSAGE: usize = MAX_FRAME - 16 - 1 - ENVELOPE_OVERHEAD;
/// Delay before re-advertising after the neighbor set changes, so a burst of changes produces
/// one advertisement.
const LSA_DEBOUNCE: Duration = Duration::from_millis(200);
/// How long a new peer's topology sync may wait on its queue before it is abandoned.
const SYNC_TIMEOUT: Duration = Duration::from_secs(30);

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
    /// A message for this node. `trusted` says whether the sender is on the allowlist; the
    /// sender's identity is always authenticated either way, end to end when routed. `via`
    /// lists the relays it came through, and is empty for a direct message.
    Message {
        from: NodeId,
        trusted: bool,
        data: Vec<u8>,
        via: Vec<NodeId>,
    },
}

/// A node known from the mesh's link-state advertisements.
#[derive(Debug, Clone, Serialize)]
pub struct RouteInfo {
    pub id: NodeId,
    pub trusted: bool,
    /// The relays a message to this node would go through right now: empty for a direct
    /// peer, `None` if there is no route through trusted relays.
    pub via: Option<Vec<NodeId>>,
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
    dial_slots: Arc<Semaphore>,
    handshake_slots: Arc<Semaphore>,
    pings: Mutex<HashMap<u64, oneshot::Sender<()>>>,
    /// Node ID last seen at each static peer address, so we do not redial a connected peer.
    static_ids: Mutex<HashMap<SocketAddr, NodeId>>,
    events: broadcast::Sender<Event>,
    shutdown: watch::Sender<bool>,
    next_conn: AtomicU64,
    relay_policy: RelayPolicy,
    topology: Mutex<Topology>,
    keys: Mutex<KeyRing>,
    replay: Mutex<ReplayGuard>,
    /// Our latest signed advertisement, sent to each new peer.
    own_lsa: Mutex<Option<Vec<u8>>>,
    lsa_seq: AtomicU64,
    /// Signalled when our neighbor set changes and we should re-advertise.
    neighbors_changed: Notify,
}

/// Whether a new link to a peer should replace the existing one. Links are described by
/// (initiator, session hash), which both ends know, so both ends reach the same answer.
fn prefer_new_link(
    lower_id: NodeId,
    existing: (NodeId, [u8; 32]),
    new: (NodeId, [u8; 32]),
    existing_age: Duration,
) -> bool {
    if existing_age >= RACE_WINDOW {
        true
    } else if existing.0 != new.0 {
        new.0 == lower_id
    } else {
        new.1 < existing.1
    }
}

enum Registration {
    New,
    /// Replaced an existing link to the same peer; the peer was already connected.
    Replaced,
    /// An existing link to the same peer wins; the new one is dropped.
    Duplicate,
    Full,
}

struct Peer {
    addr: SocketAddr,
    initiator: NodeId,
    /// The handshake transcript hash, which both ends of the link agree on.
    session: [u8; 32],
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
                dial_slots: Arc::new(Semaphore::new(MAX_DIALS)),
                handshake_slots: Arc::new(Semaphore::new(MAX_INBOUND_HANDSHAKES)),
                pings: Mutex::default(),
                static_ids: Mutex::default(),
                events: broadcast::channel(256).0,
                shutdown,
                next_conn: AtomicU64::new(0),
                relay_policy: config.routing.relay_for,
                topology: Mutex::default(),
                keys: Mutex::default(),
                replay: Mutex::default(),
                own_lsa: Mutex::default(),
                // Start from the clock so advertisements after a restart still count as newer.
                lsa_seq: AtomicU64::new(routing::unix_millis()),
                neighbors_changed: Notify::new(),
            }),
        };
        tracing::info!("node {} listening on {local_addr}", node.id());

        tokio::spawn(node.clone().accept_loop(listener));
        tokio::spawn(node.clone().advertise_loop());

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
        known.extend(self.inner.topology.lock().unwrap().ids().copied());
        known.remove(&self.id());
        let matches: Vec<NodeId> = known
            .into_iter()
            .filter(|id| id.to_string().starts_with(&query))
            .collect();
        match matches.as_slice() {
            [id] => Ok(*id),
            [] => bail!("no known node matches {query:?}"),
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

    /// Send a message to `peer`: directly if connected, otherwise along the shortest route
    /// whose relays are all trusted. Returns the relays used (empty for a direct send).
    pub async fn send(&self, peer: &NodeId, data: Vec<u8>) -> Result<Vec<NodeId>> {
        if data.len() > MAX_MESSAGE {
            bail!(
                "message is {} bytes; the limit is {MAX_MESSAGE}",
                data.len()
            );
        }
        if let Ok(tx) = self.sender(peer) {
            self.push(&tx, Message::Data(data)).await?;
            return Ok(Vec::new());
        }

        let path = self
            .route(peer)
            .with_context(|| format!("no route to {} through trusted relays", peer.short()))?;
        let dst = self
            .inner
            .topology
            .lock()
            .unwrap()
            .get(peer)
            .cloned()
            .context("destination left the topology")?;
        let envelope = Envelope::seal(&self.inner.identity, &dst, path.clone(), &data)?;
        let tx = self.sender(&envelope.next_hop())?;
        self.push(&tx, Message::Routed(envelope.encode())).await?;
        Ok(path)
    }

    /// The relays a message to `peer` would use now: empty if directly connected, `None` if
    /// no route passes only through trusted relays.
    pub fn route(&self, peer: &NodeId) -> Option<Vec<NodeId>> {
        let direct: HashSet<NodeId> = self.inner.peers.lock().unwrap().keys().copied().collect();
        let trusted: HashSet<NodeId> = self.trusted().into_iter().collect();
        self.inner
            .topology
            .lock()
            .unwrap()
            .route(self.id(), &direct, *peer, |n| trusted.contains(n))
    }

    /// Every node known from the mesh, with how a message would reach it.
    pub fn routes(&self) -> Vec<RouteInfo> {
        let ids: Vec<NodeId> = self.inner.topology.lock().unwrap().ids().copied().collect();
        let mut routes: Vec<RouteInfo> = ids
            .into_iter()
            .filter(|id| *id != self.id())
            .map(|id| RouteInfo {
                id,
                trusted: self.is_trusted(&id),
                via: self.route(&id),
            })
            .collect();
        routes.sort_by_key(|r| r.id);
        routes
    }

    async fn push(&self, tx: &mpsc::Sender<Message>, msg: Message) -> Result<()> {
        tokio::time::timeout(SEND_TIMEOUT, tx.send(msg))
            .await
            .context("peer is not reading; send timed out")?
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
        let result = tokio::time::timeout(PING_TIMEOUT, async {
            tx.send(Message::Ping(nonce))
                .await
                .map_err(|_| anyhow::anyhow!("peer disconnected"))?;
            done_rx.await.context("peer disconnected")
        })
        .await
        .context("ping timed out")
        .and_then(|r| r);
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
                        let Ok(permit) = self.inner.handshake_slots.clone().try_acquire_owned() else {
                            tracing::debug!("too many handshakes in progress; dropping {addr}");
                            continue;
                        };
                        let node = self.clone();
                        tokio::spawn(async move {
                            let result = node.establish(stream, addr, Role::Responder).await;
                            drop(permit);
                            if let Err(e) = result {
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

    /// Dial `addr` in the background, at most once per address at a time. `announced` is the
    /// node ID a multicast announcement claimed, which is only a hint: the handshake decides
    /// who is really there.
    fn spawn_dial(&self, addr: SocketAddr, announced: Option<NodeId>) {
        let Ok(permit) = self.inner.dial_slots.clone().try_acquire_owned() else {
            tracing::debug!("too many dials in flight; skipping {addr}");
            return;
        };
        if !self.inner.dialing.lock().unwrap().insert(addr) {
            return;
        }
        let node = self.clone();
        tokio::spawn(async move {
            match node.connect(addr).await {
                Ok(id) => {
                    if announced.is_some_and(|claimed| claimed != id) {
                        tracing::warn!(
                            "{addr} announced itself as {} but authenticated as {}",
                            announced.unwrap().short(),
                            id.short()
                        );
                    }
                    if announced.is_none() {
                        node.inner.static_ids.lock().unwrap().insert(addr, id);
                    }
                }
                Err(e) => tracing::debug!("dial {addr} failed: {e:#}"),
            }
            node.inner.dialing.lock().unwrap().remove(&addr);
            drop(permit);
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
        let Established {
            peer,
            session,
            send,
            recv,
        } = tokio::time::timeout(
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
        let new = Peer {
            addr,
            initiator,
            session,
            conn,
            tx: tx.clone(),
            since: Instant::now(),
            _close: close_tx,
        };
        match self.register(peer, new) {
            Registration::New => {
                self.inner.neighbors_changed.notify_one();
                tokio::spawn(self.clone().sync_topology(tx.clone()));
            }
            Registration::Replaced => {
                tracing::debug!("replaced link to {} with one from {addr}", peer.short());
                tokio::spawn(self.run_connection(stream, peer, conn, send, recv, tx, rx, close_rx));
                return Ok(peer);
            }
            // Keeping the existing link. Report success: the peer is connected.
            Registration::Duplicate => return Ok(peer),
            Registration::Full => bail!("peer limit of {MAX_PEERS} reached"),
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

    /// Add the peer to the table, deciding which link wins when one already exists.
    ///
    /// Both ends must pick the same link without talking to each other, so the rule uses only
    /// facts both share. If the existing link is older than [`RACE_WINDOW`], the new one
    /// replaces it (the old one is probably dead, e.g. the peer restarted). Otherwise the two
    /// links raced: keep the one opened by the node with the lower ID, and if the same node
    /// opened both, the one with the lower session hash.
    fn register(&self, id: NodeId, new: Peer) -> Registration {
        let mut peers = self.inner.peers.lock().unwrap();
        let outcome = match peers.get(&id) {
            None if peers.len() >= MAX_PEERS => return Registration::Full,
            None => Registration::New,
            Some(existing) => {
                let keep_new = prefer_new_link(
                    self.id().min(id),
                    (existing.initiator, existing.session),
                    (new.initiator, new.session),
                    existing.since.elapsed(),
                );
                if !keep_new {
                    return Registration::Duplicate;
                }
                Registration::Replaced
            }
        };
        peers.insert(id, new);
        outcome
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
                let frame = send.seal(&msg.encode())?;
                tokio::time::timeout(WRITE_TIMEOUT, write_frame(&mut writer, &frame))
                    .await
                    .context("peer stopped reading")??;
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
                            via: Vec::new(),
                        });
                    }
                    Message::LinkState(bytes) => self.handle_link_state(peer, bytes),
                    Message::Routed(bytes) => {
                        if let Err(e) = self.handle_routed(peer, &bytes) {
                            tracing::debug!("dropped routed message from {}: {e:#}", peer.short());
                        }
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
            self.inner.neighbors_changed.notify_one();
            tracing::info!("disconnected from {}", peer.short());
            self.emit(Event::PeerDisconnected { id: peer });
        }
    }

    /// Advertise our link state: on start, whenever our neighbors change, and every
    /// [`LSA_REFRESH`] so others don't expire us.
    async fn advertise_loop(self) {
        let mut shutdown = self.inner.shutdown.subscribe();
        let mut last = Instant::now() - LSA_MIN_INTERVAL;
        loop {
            let wait = LSA_MIN_INTERVAL.saturating_sub(last.elapsed());
            tokio::time::sleep(wait).await;
            last = Instant::now();
            if let Err(e) = self.advertise() {
                tracing::warn!("cannot sign link state: {e:#}");
            }
            self.inner.topology.lock().unwrap().expire();
            tokio::select! {
                _ = shutdown.changed() => return,
                _ = tokio::time::sleep(LSA_REFRESH) => {}
                _ = self.inner.neighbors_changed.notified() => {
                    tokio::time::sleep(LSA_DEBOUNCE).await;
                }
            }
        }
    }

    /// Sign a fresh advertisement of our current neighbors and send it to all of them.
    fn advertise(&self) -> Result<()> {
        let (neighbors, senders): (Vec<NodeId>, Vec<mpsc::Sender<Message>>) = self
            .inner
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|(id, p)| (*id, p.tx.clone()))
            .unzip();
        // Sequence numbers come from the clock so they keep increasing across restarts.
        let seq = routing::unix_millis().max(self.inner.lsa_seq.load(Ordering::Relaxed) + 1);
        self.inner.lsa_seq.store(seq, Ordering::Relaxed);
        let state = {
            let mut keys = self.inner.keys.lock().unwrap();
            LinkState::sign(&self.inner.identity, seq, keys.current(), &neighbors)?
        };
        *self.inner.own_lsa.lock().unwrap() = Some(state.encoded.clone());
        for tx in senders {
            let _ = tx.try_send(Message::LinkState(state.encoded.clone()));
        }
        Ok(())
    }

    /// Give a new peer everything we know about the mesh, so it can route right away instead
    /// of waiting for the next refresh.
    async fn sync_topology(self, tx: mpsc::Sender<Message>) {
        let mut states: Vec<Vec<u8>> = self.inner.own_lsa.lock().unwrap().iter().cloned().collect();
        states.extend(
            self.inner
                .topology
                .lock()
                .unwrap()
                .states()
                .map(|s| s.encoded.clone()),
        );
        let _ = tokio::time::timeout(SYNC_TIMEOUT, async {
            for state in states {
                if tx.send(Message::LinkState(state)).await.is_err() {
                    return;
                }
            }
        })
        .await;
    }

    /// Verify an advertisement from `from`, store it if it is new, and flood it to our other
    /// neighbors.
    fn handle_link_state(&self, from: NodeId, bytes: Vec<u8>) {
        let state = match LinkState::verify(&bytes) {
            Ok(state) => state,
            Err(e) => {
                tracing::debug!("bad link state from {}: {e:#}", from.short());
                return;
            }
        };
        let origin = state.origin;
        if origin == self.id() {
            return;
        }
        let trusted = self.is_trusted(&origin);
        if !self.inner.topology.lock().unwrap().insert(state, trusted) {
            return;
        }
        tracing::trace!("link state from {} via {}", origin.short(), from.short());
        let senders: Vec<mpsc::Sender<Message>> = self
            .inner
            .peers
            .lock()
            .unwrap()
            .iter()
            .filter(|(id, _)| **id != from && **id != origin)
            .map(|(_, p)| p.tx.clone())
            .collect();
        for tx in senders {
            // Flooding is best effort; a peer with a full queue catches up on the next refresh.
            let _ = tx.try_send(Message::LinkState(bytes.clone()));
        }
    }

    /// Deliver a routed envelope addressed to us, or forward it one hop if we are the relay
    /// its route names next.
    fn handle_routed(&self, from: NodeId, bytes: &[u8]) -> Result<()> {
        let mut envelope = Envelope::decode(bytes)?;
        let hop = envelope.hop as usize;
        // Whoever handed us the envelope must be the node before us on its route.
        let expected_from = match hop {
            0 => envelope.src,
            _ => envelope.path[hop - 1],
        };
        if from != expected_from {
            bail!("came from {}, not the previous hop", from.short());
        }

        if envelope.dst == self.id() {
            if hop != envelope.path.len() {
                bail!("delivered before the end of its route");
            }
            let sender = self
                .inner
                .topology
                .lock()
                .unwrap()
                .get(&envelope.src)
                .cloned()
                .context("sender's link state is unknown")?;
            let data = envelope.open(&self.inner.keys.lock().unwrap(), &sender)?;
            if !self.inner.replay.lock().unwrap().check(envelope.msg_id()) {
                bail!("replayed message");
            }
            self.emit(Event::Message {
                from: envelope.src,
                trusted: self.is_trusted(&envelope.src),
                data,
                via: envelope.path,
            });
            return Ok(());
        }

        if envelope.path.get(hop) != Some(&self.id()) {
            bail!("we are not the next relay on its route");
        }
        if self.inner.relay_policy == RelayPolicy::Trusted && !self.is_trusted(&from) {
            bail!("relaying only for trusted peers");
        }
        envelope.hop += 1;
        let next = envelope.next_hop();
        let tx = self.sender(&next)?;
        // Relays never block: a full queue drops the message, like a congested router.
        tx.try_send(Message::Routed(envelope.encode()))
            .map_err(|_| anyhow::anyhow!("next hop {} is congested", next.short()))?;
        tracing::trace!(
            "relayed {} -> {} to {}",
            envelope.src.short(),
            envelope.dst.short(),
            next.short()
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two racing links must produce the same winner on both ends, whichever order each end
    /// saw them complete in.
    #[test]
    fn racing_links_resolve_the_same_way_on_both_ends() {
        let (a, b) = (NodeId([1; 32]), NodeId([2; 32]));
        let fresh = Duration::from_millis(5);
        let winner = |first: (NodeId, [u8; 32]), second: (NodeId, [u8; 32])| {
            if prefer_new_link(a.min(b), first, second, fresh) {
                second
            } else {
                first
            }
        };
        let links = [
            ((a, [7; 32]), (a, [3; 32])), // both opened by a
            ((b, [7; 32]), (b, [3; 32])), // both opened by b
            ((a, [7; 32]), (b, [3; 32])), // one each
        ];
        for (l1, l2) in links {
            assert_eq!(winner(l1, l2), winner(l2, l1), "{l1:?} vs {l2:?}");
        }
        assert_eq!(
            winner((a, [9; 32]), (b, [1; 32])).0,
            a,
            "lower ID's link wins"
        );
    }

    #[test]
    fn a_stale_link_is_replaced() {
        let (a, b) = (NodeId([1; 32]), NodeId([2; 32]));
        assert!(prefer_new_link(a, (a, [0; 32]), (b, [9; 32]), RACE_WINDOW));
    }
}
