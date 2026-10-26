//! Multi-hop routing: signed link-state advertisements, source routes through trusted relays,
//! and end-to-end encrypted, signed envelopes.
//!
//! Every node floods a [`LinkState`] listing its direct neighbors and a public key set for
//! receiving routed messages. From those, a sender computes the shortest path to the
//! destination that passes **only through relays it trusts**, writes that path into the
//! [`Envelope`], and seals the payload so only the destination can read it and the destination
//! can verify who sent it. Relays see the path and the endpoints, nothing more.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::SimpleHkdf;
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem768, TryKeyInit};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::identity::{self, Identity, NodeId, SIGNATURE_LEN};

/// Longest relay chain a route may use.
pub const MAX_RELAYS: usize = 8;
/// How often a node re-floods its link state even when nothing changed.
pub const LSA_REFRESH: Duration = Duration::from_secs(30);
/// Link states not refreshed for this long are dropped from the topology.
pub const LSA_EXPIRY: Duration = Duration::from_secs(120);
/// Most origins the topology tracks. Beyond this, only trusted origins are admitted.
pub const MAX_TOPOLOGY: usize = 1024;
/// Most neighbors a link state may list.
pub const MAX_NEIGHBORS: usize = 256;
/// How long one set of receiving keys is advertised before it is replaced.
pub const KEY_EPOCH: Duration = Duration::from_secs(300);
/// How many key sets (the current one and older ones) can still decrypt messages. Messages
/// sealed to older keys fail, which bounds how long a captured envelope can be replayed.
pub const KEPT_EPOCHS: usize = 3;
/// A node advertises at most this often.
pub const LSA_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// Newer advertisements a receiver accepts from one origin in a burst. After that it accepts
/// one per half [`LSA_MIN_INTERVAL`], which bounds how much flooding one node can cause while
/// leaving room for an honest node's updates to arrive close together, say right after a
/// stale copy from a topology sync.
const LSA_BURST: u32 = 4;

const LSA_VERSION: u8 = 1;
const ENVELOPE_VERSION: u8 = 1;
const LSA_LABEL: &[u8] = b"latchkey-v1 lsa";
const MSG_LABEL: &[u8] = b"latchkey-v1 msg";
const X25519_LEN: usize = 32;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;

/// Largest number of bytes an envelope adds to its payload, with a full-length route.
pub const ENVELOPE_OVERHEAD: usize = 1 // version
    + 32 + 32 // src, dst
    + 1 + 1 // hop, path length
    + MAX_RELAYS * 32
    + 8 // epoch
    + X25519_LEN
    + MLKEM_CT_LEN
    + 16 // msg_id
    + SIGNATURE_LEN
    + 16; // AEAD tag

/// A signed advertisement of one node's direct links and receiving keys.
#[derive(Clone, Debug)]
pub struct LinkState {
    pub origin: NodeId,
    pub verifying_key: Vec<u8>,
    /// Increases with every advertisement from the same origin.
    pub seq: u64,
    /// Which receiving key set `x25519` and `kem_ek` belong to.
    pub epoch: u64,
    pub x25519: [u8; 32],
    pub kem_ek: Vec<u8>,
    pub neighbors: Vec<NodeId>,
    /// The signed encoding, kept so the advertisement can be flooded unchanged.
    pub encoded: Vec<u8>,
}

impl LinkState {
    /// Build and sign an advertisement for `identity`.
    pub fn sign(
        identity: &Identity,
        seq: u64,
        keys: &EpochKeys,
        neighbors: &[NodeId],
    ) -> Result<Self> {
        ensure!(
            neighbors.len() <= MAX_NEIGHBORS,
            "too many neighbors to advertise"
        );
        let vk = identity.verifying_key_bytes();
        let mut body = vec![LSA_VERSION];
        body.extend_from_slice(&(vk.len() as u16).to_be_bytes());
        body.extend_from_slice(&vk);
        body.extend_from_slice(&seq.to_be_bytes());
        body.extend_from_slice(&keys.epoch.to_be_bytes());
        body.extend_from_slice(&keys.x_public);
        body.extend_from_slice(&(keys.kem_ek.len() as u16).to_be_bytes());
        body.extend_from_slice(&keys.kem_ek);
        body.extend_from_slice(&(neighbors.len() as u16).to_be_bytes());
        for n in neighbors {
            body.extend_from_slice(&n.0);
        }
        let signature = identity.sign(&[LSA_LABEL, &body].concat())?;
        let encoded = [body, signature].concat();
        Self::verify(&encoded)
    }

    /// Decode an advertisement and check its signature. The origin is the hash of the key that
    /// signed it, so an advertisement cannot claim to come from a node it doesn't control.
    pub fn verify(encoded: &[u8]) -> Result<Self> {
        ensure!(encoded.len() > SIGNATURE_LEN, "link state too short");
        let (body, signature) = encoded.split_at(encoded.len() - SIGNATURE_LEN);
        let mut r = Reader(body);
        ensure!(r.u8()? == LSA_VERSION, "unsupported link state version");
        let vk_len = r.u16()? as usize;
        let verifying_key = r.take(vk_len)?.to_vec();
        let seq = r.u64()?;
        let epoch = r.u64()?;
        let x25519: [u8; 32] = r.array()?;
        let ek_len = r.u16()? as usize;
        ensure!(ek_len == MLKEM_EK_LEN, "bad ML-KEM key length");
        let kem_ek = r.take(ek_len)?.to_vec();
        let count = r.u16()? as usize;
        ensure!(count <= MAX_NEIGHBORS, "too many neighbors");
        let mut neighbors = Vec::with_capacity(count);
        for _ in 0..count {
            neighbors.push(NodeId(r.array()?));
        }
        r.end()?;
        let origin = identity::verify(&verifying_key, &[LSA_LABEL, body].concat(), signature)
            .context("bad link state signature")?;
        Ok(Self {
            origin,
            verifying_key,
            seq,
            epoch,
            x25519,
            kem_ek,
            neighbors,
            encoded: encoded.to_vec(),
        })
    }
}

/// One set of keys for receiving routed messages: a static X25519 key and an ML-KEM-768 key.
pub struct EpochKeys {
    pub epoch: u64,
    x_secret: StaticSecret,
    pub x_public: [u8; 32],
    kem_dk: ml_kem::ml_kem_768::DecapsulationKey,
    pub kem_ek: Vec<u8>,
    created: Instant,
}

impl EpochKeys {
    fn generate(epoch: u64) -> Self {
        let x_secret = StaticSecret::random();
        let x_public = PublicKey::from(&x_secret).to_bytes();
        let (kem_dk, ek) = MlKem768::generate_keypair();
        Self {
            epoch,
            x_secret,
            x_public,
            kem_dk,
            kem_ek: ek.to_bytes().to_vec(),
            created: Instant::now(),
        }
    }
}

/// The node's receiving keys, rotated every [`KEY_EPOCH`].
pub struct KeyRing {
    epochs: VecDeque<EpochKeys>,
    next_epoch: u64,
}

impl Default for KeyRing {
    fn default() -> Self {
        // Start from the clock so a restarted node never reuses an epoch number it advertised
        // before, which would make senders encrypt to keys that no longer exist.
        let mut ring = Self {
            epochs: VecDeque::new(),
            next_epoch: unix_millis(),
        };
        ring.rotate();
        ring
    }
}

impl KeyRing {
    /// The key set to advertise, rotating first if the current one is too old.
    pub fn current(&mut self) -> &EpochKeys {
        if self
            .epochs
            .back()
            .is_none_or(|k| k.created.elapsed() >= KEY_EPOCH)
        {
            self.rotate();
        }
        self.epochs.back().expect("rotate adds a key set")
    }

    fn rotate(&mut self) {
        self.epochs.push_back(EpochKeys::generate(self.next_epoch));
        self.next_epoch += 1;
        while self.epochs.len() > KEPT_EPOCHS {
            self.epochs.pop_front();
        }
    }

    fn get(&self, epoch: u64) -> Option<&EpochKeys> {
        self.epochs.iter().find(|k| k.epoch == epoch)
    }
}

/// A routed message. The header travels in the clear so relays can forward it; the payload
/// and the sender's signature are sealed to the destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub src: NodeId,
    pub dst: NodeId,
    /// Relays between `src` and `dst`, in order.
    pub path: Vec<NodeId>,
    /// Index into `path` of the relay that should handle the envelope next. Equal to
    /// `path.len()` once it is on its last hop, to `dst`.
    pub hop: u8,
    epoch: u64,
    eph: [u8; 32],
    kem_ct: Vec<u8>,
    msg_id: [u8; 16],
    sealed: Vec<u8>,
}

impl Envelope {
    /// Seal `payload` from `identity` to the node described by `dst`, to travel via `path`.
    pub fn seal(
        identity: &Identity,
        dst: &LinkState,
        path: Vec<NodeId>,
        payload: &[u8],
    ) -> Result<Self> {
        ensure!(
            path.len() <= MAX_RELAYS,
            "route is longer than {MAX_RELAYS} relays"
        );
        let eph_secret = EphemeralSecret::random();
        let eph = PublicKey::from(&eph_secret).to_bytes();
        let x_shared = eph_secret.diffie_hellman(&PublicKey::from(dst.x25519));
        ensure!(
            x_shared.was_contributory(),
            "destination advertised a low-order X25519 key"
        );
        let ek = ml_kem::ml_kem_768::EncapsulationKey::new_from_slice(&dst.kem_ek)
            .map_err(|_| anyhow::anyhow!("destination advertised a bad ML-KEM key"))?;
        let (kem_ct, kem_secret) = ek.encapsulate();
        let kem_secret = Zeroizing::new(kem_secret);
        let mut msg_id = [0u8; 16];
        getrandom::fill(&mut msg_id).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;

        let mut envelope = Self {
            src: identity.id(),
            dst: dst.origin,
            path,
            hop: 0,
            epoch: dst.epoch,
            eph,
            kem_ct: kem_ct.to_vec(),
            msg_id,
            sealed: Vec::new(),
        };
        let aad = envelope.aad();
        let signature = identity.sign(&[&aad[..], payload].concat())?;
        let cipher = message_cipher(x_shared.as_bytes(), &kem_secret, &aad);
        let plaintext = Zeroizing::new([payload, &signature].concat());
        envelope.sealed = cipher
            .encrypt(
                &Nonce::default(),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        Ok(envelope)
    }

    /// Decrypt an envelope addressed to us and check the sender's signature against the
    /// sender's advertised key. Returns the payload.
    pub fn open(&self, keys: &KeyRing, sender: &LinkState) -> Result<Vec<u8>> {
        ensure!(
            sender.origin == self.src,
            "sender link state does not match"
        );
        let keys = keys
            .get(self.epoch)
            .context("envelope sealed to keys that have expired or never existed")?;
        let x_shared = keys.x_secret.diffie_hellman(&PublicKey::from(self.eph));
        ensure!(x_shared.was_contributory(), "low-order ephemeral key");
        let kem_secret = Zeroizing::new(
            keys.kem_dk
                .decapsulate_slice(&self.kem_ct)
                .map_err(|_| anyhow::anyhow!("bad ML-KEM ciphertext"))?,
        );
        let aad = self.aad();
        let cipher = message_cipher(x_shared.as_bytes(), &kem_secret, &aad);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::default(),
                    Payload {
                        msg: &self.sealed,
                        aad: &aad,
                    },
                )
                .map_err(|_| anyhow::anyhow!("envelope failed authentication"))?,
        );
        ensure!(plaintext.len() >= SIGNATURE_LEN, "envelope too short");
        let (payload, signature) = plaintext.split_at(plaintext.len() - SIGNATURE_LEN);
        let signer = identity::verify(
            &sender.verifying_key,
            &[&aad[..], payload].concat(),
            signature,
        )
        .context("bad sender signature")?;
        ensure!(signer == self.src, "envelope signed by the wrong node");
        Ok(payload.to_vec())
    }

    /// Unique per message; the receiver uses it to drop replays.
    pub fn msg_id(&self) -> [u8; 16] {
        self.msg_id
    }

    /// The node this envelope should be handed to after the relay at `hop`.
    pub fn next_hop(&self) -> NodeId {
        self.path
            .get(self.hop as usize)
            .copied()
            .unwrap_or(self.dst)
    }

    /// Everything the sender commits to, including the route, so the destination knows which
    /// relays carried the message. Only `hop` is left out, because relays advance it.
    fn aad(&self) -> Vec<u8> {
        let path: Vec<u8> = self.path.iter().flat_map(|n| n.0).collect();
        [
            MSG_LABEL,
            &self.src.0,
            &self.dst.0,
            &[self.path.len() as u8],
            &path,
            &self.epoch.to_be_bytes(),
            &self.eph,
            &self.kem_ct,
            &self.msg_id,
        ]
        .concat()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![ENVELOPE_VERSION];
        out.extend_from_slice(&self.src.0);
        out.extend_from_slice(&self.dst.0);
        out.push(self.hop);
        out.push(self.path.len() as u8);
        for relay in &self.path {
            out.extend_from_slice(&relay.0);
        }
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.eph);
        out.extend_from_slice(&self.kem_ct);
        out.extend_from_slice(&self.msg_id);
        out.extend_from_slice(&self.sealed);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        ensure!(r.u8()? == ENVELOPE_VERSION, "unsupported envelope version");
        let src = NodeId(r.array()?);
        let dst = NodeId(r.array()?);
        let hop = r.u8()?;
        let count = r.u8()? as usize;
        ensure!(count <= MAX_RELAYS, "route too long");
        ensure!(hop as usize <= count, "hop index past the end of the route");
        let mut path = Vec::with_capacity(count);
        for _ in 0..count {
            path.push(NodeId(r.array()?));
        }
        let epoch = r.u64()?;
        let eph = r.array()?;
        let kem_ct = r.take(MLKEM_CT_LEN)?.to_vec();
        let msg_id = r.array()?;
        let sealed = r.0.to_vec();
        Ok(Self {
            src,
            dst,
            path,
            hop,
            epoch,
            eph,
            kem_ct,
            msg_id,
            sealed,
        })
    }
}

fn message_cipher(x_shared: &[u8], kem_secret: &[u8], aad: &[u8]) -> ChaCha20Poly1305 {
    let salt = Sha3_256::digest(aad);
    let ikm = Zeroizing::new([x_shared, kem_secret].concat());
    let mut key = Zeroizing::new([0u8; 32]);
    SimpleHkdf::<Sha3_256>::new(Some(&salt), &ikm)
        .expand(b"latchkey-v1 msg key", key.as_mut())
        .expect("valid HKDF length");
    // Each message gets a fresh key, so a fixed nonce is safe.
    ChaCha20Poly1305::new(&Key::from(*key))
}

/// What a node knows about the rest of the mesh.
#[derive(Default)]
pub struct Topology {
    states: HashMap<NodeId, Entry>,
}

struct Entry {
    state: LinkState,
    received: Instant,
    /// Rate limit: how many more newer advertisements this origin may send right now.
    tokens: u32,
    refilled: Instant,
}

impl Entry {
    fn take_token(&mut self) -> bool {
        let per_token = LSA_MIN_INTERVAL / 2;
        let earned = (self.refilled.elapsed().as_millis() / per_token.as_millis()) as u32;
        if earned > 0 {
            self.tokens = (self.tokens + earned).min(LSA_BURST);
            self.refilled += per_token * earned;
        }
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

impl Topology {
    /// Store `state` if it is newer than what we have. Returns true if it was stored, in which
    /// case it should be flooded on. When the table is full, only trusted origins get in.
    pub fn insert(&mut self, state: LinkState, trusted: bool) -> bool {
        if let Some(entry) = self.states.get_mut(&state.origin) {
            if entry.state.seq >= state.seq || !entry.take_token() {
                return false;
            }
            entry.state = state;
            entry.received = Instant::now();
            return true;
        }
        if self.states.len() >= MAX_TOPOLOGY {
            self.expire();
            if self.states.len() >= MAX_TOPOLOGY && !trusted {
                return false;
            }
        }
        let now = Instant::now();
        self.states.insert(
            state.origin,
            Entry {
                state,
                received: now,
                tokens: LSA_BURST - 1,
                refilled: now,
            },
        );
        true
    }

    pub fn expire(&mut self) {
        self.states.retain(|_, e| e.received.elapsed() < LSA_EXPIRY);
    }

    pub fn get(&self, id: &NodeId) -> Option<&LinkState> {
        self.states.get(id).map(|e| &e.state)
    }

    pub fn ids(&self) -> impl Iterator<Item = &NodeId> {
        self.states.keys()
    }

    pub fn states(&self) -> impl Iterator<Item = &LinkState> {
        self.states.values().map(|e| &e.state)
    }

    /// The shortest relay list from `me` to `dst`, using `direct` as our own links. Every
    /// relay must satisfy `trusted`; the destination need not. A link between two other nodes
    /// counts only if both advertise it. Returns `None` if no such route exists, and an empty
    /// list if `dst` is a direct neighbor.
    pub fn route(
        &self,
        me: NodeId,
        direct: &HashSet<NodeId>,
        dst: NodeId,
        trusted: impl Fn(&NodeId) -> bool,
    ) -> Option<Vec<NodeId>> {
        if direct.contains(&dst) {
            return Some(Vec::new());
        }
        self.get(&dst)?;
        let mut previous: HashMap<NodeId, NodeId> = HashMap::new();
        let mut queue = VecDeque::from([(me, 0usize)]);
        let mut seen = HashSet::from([me]);
        while let Some((node, depth)) = queue.pop_front() {
            let neighbors: Vec<NodeId> = if node == me {
                direct.iter().copied().collect()
            } else {
                let Some(state) = self.get(&node) else {
                    continue;
                };
                state
                    .neighbors
                    .iter()
                    .copied()
                    .filter(|n| self.get(n).is_some_and(|s| s.neighbors.contains(&node)))
                    .collect()
            };
            for next in neighbors {
                if !seen.insert(next) {
                    continue;
                }
                previous.insert(next, node);
                if next == dst {
                    let mut path = Vec::new();
                    let mut at = node;
                    while at != me {
                        path.push(at);
                        at = previous[&at];
                    }
                    path.reverse();
                    return Some(path);
                }
                // Only trusted nodes may carry traffic onward, and routes stay short.
                if trusted(&next) && depth < MAX_RELAYS {
                    queue.push_back((next, depth + 1));
                }
            }
        }
        None
    }
}

/// Recently delivered message IDs, so a replayed envelope is delivered at most once. Entries
/// outlive the keys an envelope can be sealed to, after which replays fail to decrypt anyway.
#[derive(Default)]
pub struct ReplayGuard {
    seen: HashMap<[u8; 16], Instant>,
}

impl ReplayGuard {
    const WINDOW: Duration = Duration::from_secs(KEY_EPOCH.as_secs() * (KEPT_EPOCHS as u64 + 1));
    const MAX: usize = 100_000;

    /// Returns false if `id` was already seen.
    pub fn check(&mut self, id: [u8; 16]) -> bool {
        if self.seen.len() >= Self::MAX {
            self.seen.retain(|_, at| at.elapsed() < Self::WINDOW);
        }
        if self.seen.len() >= Self::MAX {
            // Still full of fresh IDs: refuse rather than forget and risk a replay.
            return false;
        }
        self.seen.insert(id, Instant::now()).is_none()
    }
}

pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("truncated");
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn end(&self) -> Result<()> {
        ensure!(self.0.is_empty(), "trailing bytes");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node() -> (Identity, KeyRing) {
        (Identity::generate().unwrap(), KeyRing::default())
    }

    fn lsa(identity: &Identity, keys: &mut KeyRing, seq: u64, neighbors: &[NodeId]) -> LinkState {
        LinkState::sign(identity, seq, keys.current(), neighbors).unwrap()
    }

    #[test]
    fn link_state_round_trips_and_rejects_tampering() {
        let (id, mut keys) = node();
        let n = vec![NodeId([1; 32]), NodeId([2; 32])];
        let state = lsa(&id, &mut keys, 7, &n);
        let back = LinkState::verify(&state.encoded).unwrap();
        assert_eq!(back.origin, id.id());
        assert_eq!(back.neighbors, n);
        assert_eq!(back.seq, 7);

        // Flip a byte in the neighbor list: the signature must no longer match.
        let mut forged = state.encoded.clone();
        let at = forged.len() - SIGNATURE_LEN - 1;
        forged[at] ^= 1;
        assert!(LinkState::verify(&forged).is_err());
    }

    #[test]
    fn envelope_reaches_only_its_destination() {
        let (alice, mut alice_keys) = node();
        let (bob, mut bob_keys) = node();
        let (eve, eve_keys) = node();
        let alice_lsa = lsa(&alice, &mut alice_keys, 1, &[]);
        let bob_lsa = lsa(&bob, &mut bob_keys, 1, &[]);

        let env = Envelope::seal(&alice, &bob_lsa, vec![eve.id()], b"secret").unwrap();
        let env = Envelope::decode(&env.encode()).unwrap();
        assert_eq!(env.open(&bob_keys, &alice_lsa).unwrap(), b"secret");
        // A relay holds different keys and cannot open it.
        assert!(env.open(&eve_keys, &alice_lsa).is_err());
    }

    #[test]
    fn envelope_rejects_tampering_and_forged_senders() {
        let (alice, mut alice_keys) = node();
        let (bob, mut bob_keys) = node();
        let (mallory, mut mallory_keys) = node();
        let alice_lsa = lsa(&alice, &mut alice_keys, 1, &[]);
        let bob_lsa = lsa(&bob, &mut bob_keys, 1, &[]);
        let mallory_lsa = lsa(&mallory, &mut mallory_keys, 1, &[]);

        let env = Envelope::seal(&alice, &bob_lsa, vec![], b"hi").unwrap();
        let mut tampered = env.clone();
        tampered.sealed[0] ^= 1;
        assert!(tampered.open(&bob_keys, &alice_lsa).is_err());

        // The route is authenticated, so a relay cannot rewrite it, but advancing the hop is fine.
        let routed = Envelope::seal(&alice, &bob_lsa, vec![NodeId([7; 32])], b"hi").unwrap();
        let mut rerouted = routed.clone();
        rerouted.path[0] = NodeId([8; 32]);
        assert!(rerouted.open(&bob_keys, &alice_lsa).is_err());
        let mut advanced = routed.clone();
        advanced.hop = 1;
        assert_eq!(advanced.open(&bob_keys, &alice_lsa).unwrap(), b"hi");

        // Mallory seals a message but claims Alice sent it.
        let mut spoofed = Envelope::seal(&mallory, &bob_lsa, vec![], b"hi").unwrap();
        spoofed.src = alice.id();
        assert!(spoofed.open(&bob_keys, &alice_lsa).is_err());
        assert!(spoofed.open(&bob_keys, &mallory_lsa).is_err());
    }

    #[test]
    fn expired_key_epochs_cannot_decrypt() {
        let (alice, mut alice_keys) = node();
        let (bob, mut bob_keys) = node();
        let alice_lsa = lsa(&alice, &mut alice_keys, 1, &[]);
        let bob_lsa = lsa(&bob, &mut bob_keys, 1, &[]);
        let env = Envelope::seal(&alice, &bob_lsa, vec![], b"old").unwrap();
        for _ in 0..KEPT_EPOCHS {
            bob_keys.rotate();
        }
        assert!(env.open(&bob_keys, &alice_lsa).is_err());
    }

    #[test]
    fn replays_are_caught() {
        let mut guard = ReplayGuard::default();
        assert!(guard.check([1; 16]));
        assert!(!guard.check([1; 16]));
        assert!(guard.check([2; 16]));
    }

    /// Build a topology from (node, neighbors) pairs, as if every node advertised them.
    fn topology(links: &[(&Identity, &[NodeId])]) -> Topology {
        let mut topo = Topology::default();
        for (id, neighbors) in links {
            let mut keys = KeyRing::default();
            topo.insert(lsa(id, &mut keys, 1, neighbors), true);
        }
        topo
    }

    #[test]
    fn routes_only_through_trusted_relays() {
        // me - r1 - dst, and me - r2 - r3 - dst
        let ids: Vec<Identity> = (0..5).map(|_| Identity::generate().unwrap()).collect();
        let [me, r1, r2, r3, dst] = [0, 1, 2, 3, 4].map(|i| ids[i].id());
        let topo = topology(&[
            (&ids[1], &[me, dst]),
            (&ids[2], &[me, r3]),
            (&ids[3], &[r2, dst]),
            (&ids[4], &[r1, r3]),
        ]);
        let direct = HashSet::from([r1, r2]);

        let all = |_: &NodeId| true;
        assert_eq!(topo.route(me, &direct, dst, all), Some(vec![r1]));
        let not_r1 = |n: &NodeId| *n != r1;
        assert_eq!(topo.route(me, &direct, dst, not_r1), Some(vec![r2, r3]));
        let none = |_: &NodeId| false;
        assert_eq!(topo.route(me, &direct, dst, none), None);
        assert_eq!(topo.route(me, &direct, r1, none), Some(vec![]));
    }

    #[test]
    fn one_sided_link_claims_are_ignored() {
        // r1 claims a link to dst, but dst doesn't list r1.
        let ids: Vec<Identity> = (0..3).map(|_| Identity::generate().unwrap()).collect();
        let [me, r1, dst] = [0, 1, 2].map(|i| ids[i].id());
        let topo = topology(&[(&ids[1], &[me, dst]), (&ids[2], &[])]);
        assert_eq!(topo.route(me, &HashSet::from([r1]), dst, |_| true), None);
    }

    #[test]
    fn newer_link_states_replace_older_ones() {
        let (id, mut keys) = node();
        let mut topo = Topology::default();
        assert!(topo.insert(lsa(&id, &mut keys, 5, &[]), false));
        assert!(!topo.insert(lsa(&id, &mut keys, 5, &[]), false));
        assert!(!topo.insert(lsa(&id, &mut keys, 4, &[]), false));
        assert!(topo.insert(lsa(&id, &mut keys, 6, &[NodeId([1; 32])]), false));
        assert_eq!(topo.get(&id.id()).unwrap().neighbors.len(), 1);
    }

    #[test]
    fn floods_from_one_origin_are_rate_limited() {
        let (id, mut keys) = node();
        let mut topo = Topology::default();
        let states: Vec<LinkState> = (1..=6).map(|seq| lsa(&id, &mut keys, seq, &[])).collect();
        // A short burst gets through, then the origin has to wait.
        let accepted = states[..5]
            .iter()
            .filter(|s| topo.insert((*s).clone(), false))
            .count();
        assert_eq!(accepted, LSA_BURST as usize);
        std::thread::sleep(LSA_MIN_INTERVAL / 2);
        assert!(topo.insert(states[5].clone(), false));
    }
}
