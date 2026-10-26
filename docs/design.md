# Latchkey design

This document describes the Latchkey MVP: what is on the wire, why it is built this way, and
what it does and does not protect against.

## Goals

- **Join automatically wherever possible.** Nodes on the same LAN connect with no
  configuration. Nodes that multicast can't reach join through static peer addresses.
- **Post-quantum confidentiality.** Recording traffic today and breaking it later with a
  quantum computer should not reveal it.
- **Authenticated identities.** Every node has a long-term identity, and a peer's identity is
  proven on every connection.
- **Joining is not trusting.** Anyone may connect, but trust is an explicit, local decision.

- **Never route through untrusted nodes.** Messages to distant nodes travel only through relays
  the sender trusts, and relays cannot read them.

Non-goals for the MVP: Byzantine fault tolerance, NAT traversal, hiding who talks to whom from
relays, and hiding the existence of nodes from the local network.

## Identity

Each node generates a random 32-byte seed and derives an **ML-DSA-65** (FIPS 204) key pair
from it. The seed is stored hex-encoded in `identity.key` with mode 0600.

The **node ID** is `SHA3-256(encoded ML-DSA-65 verifying key)`, written as 64 hex characters.
The CLI accepts any unique prefix of an ID.

## Discovery

Every `interval_secs` (5 by default), a node sends a 38-byte UDP datagram:

```
"LKA1" (4) | node ID (32) | TCP port, big-endian (2)
```

to `239.255.76.75` (an administratively scoped IPv4 group, RFC 2365) and to
`ff02::6c6b:7931` (link-local IPv6), both on UDP port 47471. The TTL is 1, so announcements
stay on the local link.

Discovery only accepts announcements that came from the local link:

- **IPv4:** on Unix, the listening socket is bound to the group address itself, not to
  `0.0.0.0`, so the kernel delivers only datagrams addressed to the group. A host that can
  merely reach the UDP port with unicast, possibly with a spoofed source address, cannot inject
  announcements. Announcements are sent from a separate socket.
- **No multicast route:** if the default interface cannot send to the IPv4 group (a host
  with no network, or some CI and container setups), the node falls back to announcing over
  loopback, so nodes on the same host still find each other, and logs a warning.
- **IPv6:** announcements must come from a link-local (`fe80::/10`) source. Routers never
  forward packets with link-local sources, so nothing from off the link gets through.

When a node hears an announcement from a node ID it isn't connected to, it dials the sender's
source IP at the announced port, provided the port is 1024 or above. Announcements carry no
authentication. They are only hints about where to try a handshake, and the handshake proves
who is on the other end. A forged announcement can make a node attempt a handshake with an
unprivileged port on a LAN address of the attacker's choosing, but it cannot make the node
accept a false identity. If the identity proven in the handshake differs from the announced
one, the node logs a warning.

In-flight dials are de-duplicated by address only, never by the announced node ID. Keying on
the claimed ID would let a forged announcement for a trusted node, pointing at a dead
address, hold that ID and hide the real node's announcements.

Static peers (`peers` in `config.toml`, or `--peer`) are dialed at startup and retried every
15 seconds until connected.

## Handshake

The handshake runs over TCP. Every frame is a 4-byte big-endian length followed by the body,
with frames capped at 64 KiB.

```
Initiator                                          Responder
---------                                          ---------
Hello_I = "LKY1" | X25519 eph pub (32) | ML-KEM-768 ek (1184)
                      ------------------------------>
       Hello_R = "LKY1" | X25519 eph pub (32) | ML-KEM-768 ct (1088)
                      <------------------------------
            both derive keys, then each sends:
AEAD{ Auth = vk_I | Sig_I(th | 'I') }  ------------->
               <-------------  AEAD{ Auth = vk_R | Sig_R(th | 'R') }
```

- `ct` encapsulates a fresh ML-KEM-768 (FIPS 203) secret to the initiator's ephemeral key.
- `th = SHA3-256("latchkey-v1 handshake" | Hello_I | Hello_R)` is the transcript hash.
- `ikm = X25519(eph_I, eph_R) | ML-KEM shared secret`. The handshake rejects non-contributory
  (low-order) X25519 results.
- `HKDF-SHA3-256(salt = th, ikm)` expands to two 32-byte keys, labelled `latchkey-v1 i2r` and
  `latchkey-v1 r2i`.
- Each side signs `th | role` with hedged (randomized) ML-DSA-65, as FIPS 204 recommends,
  under the context string `latchkey-v1`. The receiver verifies the signature and computes
  the peer's node ID from the verifying key.
- Ephemeral secrets, the ML-KEM shared secret, the combined key material, and the derived keys
  are zeroized after use.

**Why hybrid.** X25519 is well understood but breakable by a quantum computer. ML-KEM is
designed to resist quantum attacks but is much newer. Feeding both secrets into the KDF means
an attacker has to break both. This is the same construction as the X25519MLKEM768 hybrid now
deployed in TLS and SSH.

**Why signatures are not hybrid.** Signatures only need to resist forgery while the handshake
is happening; a future quantum computer cannot retroactively forge one. ML-DSA alone is enough.

**Why `th` is signed.** The transcript covers both ephemeral keys, so a signature can't be
replayed into a different session. Including the role stops a signature from being reflected
back to its signer.

## Session

After the handshake, each direction uses **ChaCha20-Poly1305** with its own key. The nonce is
a 64-bit counter (zero-padded to 96 bits) that starts at 0 and goes up by one per frame. A
dropped, reordered, replayed, or modified frame fails authentication and closes the
connection. Sessions do not rekey. A connection closes if its counter would wrap, which won't
happen in practice.

Encrypted message types, by tag byte:

| Tag | Message | Body |
| --- | --- | --- |
| 1 | Auth | vk length (u16) \| vk \| signature (handshake only) |
| 2 | Ping | u64 nonce |
| 3 | Pong | u64 nonce |
| 4 | Data | application bytes |
| 5 | LinkState | a signed link-state advertisement (see Routing) |
| 6 | Routed | a routed envelope (see Routing) |

A link closes if its peer stops reading for 20 seconds, and `send` gives up after 10 seconds
if the peer's outgoing queue stays full, so a stalled peer cannot hang the caller.

Each side sends a keepalive `Ping(0)` every 15 seconds and closes a link that has been
silent for 45 seconds.

### Duplicate connections

Two nodes often dial each other at the same moment, for example when both hear the other's
announcement, and one node can dial the same peer twice, for example over IPv4 and IPv6. When
a node already has a link to a peer and a second one completes, it decides which to keep using
only facts both ends share:

1. If the existing link is more than 10 seconds old, the new link replaces it. The old one is
   probably stale; for example, the peer restarted.
2. Otherwise the links raced. Keep the one **initiated by the node with the lower node ID**.
3. If the same node initiated both, keep the one with the **lower session hash** (`th`).

Both ends apply the same rule independently, so they keep the same link without exchanging
any messages. Replacing a link does not emit a second `PeerConnected` event, because the peer
never disconnected.

## Trust model

- **Connected** means the peer completed the handshake. Its node ID is authenticated, but it
  may belong to anyone.
- **Trusted** means the peer's node ID is in your local `trusted` file.

Trust does two things:

- It labels messages and peers in the CLI and API (`Event::Message.trusted`,
  `PeerInfo.trusted`). Untrusted nodes can still exchange messages, directly or routed.
- **A node never routes its messages through a node it doesn't trust.** Routes are chosen by
  the sender, so this is the sender's trust that counts. The destination does not have to be
  trusted.

Full Byzantine resilience is a non-goal. Trusted nodes are assumed honest.

Because those labels are all trust does today, a peer must not be able to fake them. The
daemon escapes control characters and bidirectional-override characters in message text, so a
peer cannot forge extra output lines (such as a fake "trusted" message) or inject terminal
escape sequences.

The allowlist is the first step. A PKI or delegated trust scheme may replace or extend it.

## Routing

### Link-state advertisements

Every node floods a signed **link-state advertisement** (LSA):

```
version (1) | vk length (u16) | ML-DSA-65 vk | seq (u64) | key epoch (u64)
  | X25519 public key (32) | ML-KEM-768 ek length (u16) | ek (1184)
  | neighbor count (u16) | neighbor IDs (32 each) | ML-DSA-65 signature over "latchkey-v1 lsa" | body
```

- The origin is the hash of the verifying key that signed the LSA, so an LSA can't speak for
  a node its sender doesn't control.
- `seq` comes from the clock and always increases, so after a restart a node's new LSAs still
  replace its old ones. A node keeps only the highest `seq` per origin.
- A node advertises on start, when its neighbors change (after a 200 ms debounce), and every
  30 seconds. It never advertises more than once a second. Receivers rate-limit each origin
  with a token bucket (a burst of 4 newer LSAs, then 2 per second), which bounds how much
  flooding one node can cause without dropping an honest node's updates that arrive close
  together.
- On receiving an LSA newer than the one it holds, a node stores it and forwards it to every
  other neighbor. A new neighbor gets the node's whole topology at once.
- LSAs not refreshed for 120 seconds expire. A node tracks at most 1024 origins; once full,
  only trusted origins get in.

### Choosing a route

Routing uses **source routes**: the sender picks the whole path. It runs a breadth-first
search over the topology and returns the shortest path where:

- every relay is on the **sender's** allowlist (the destination need not be);
- the first hop is one of the sender's live links;
- every other link is listed by **both** of its ends, so one node cannot invent a link to
  attract traffic;
- there are at most 8 relays.

Directly connected peers are always reached directly. `latchkey routes` and `Node::routes`
show each known node and the route a message would take now.

### Envelopes

A routed message is an envelope sealed to the destination's advertised receiving keys:

```
version (1) | src (32) | dst (32) | hop (1) | relay count (1) | relays (32 each)
  | key epoch (u64) | X25519 eph pub (32) | ML-KEM-768 ct (1088) | msg_id (16)
  | ChaCha20-Poly1305( payload | ML-DSA-65 signature )
```

- The sender does an X25519 exchange between a fresh ephemeral key and the destination's
  advertised X25519 key, and encapsulates to its advertised ML-KEM-768 key. Both secrets go
  through HKDF-SHA3-256 into a one-time ChaCha20-Poly1305 key, as in the link handshake.
- The AEAD's associated data covers every header field except `hop`, including the relay list,
  so the destination knows exactly which relays carried the message. Relays only advance
  `hop`.
- Inside the ciphertext, the sender signs the associated data and payload with its identity
  key. The destination checks the signature against the key in the sender's LSA. The receiver
  learns who sent the message even though the link it arrived on belongs to a relay.
- Receiving keys rotate every 5 minutes, and a node keeps the last 3 sets. Each LSA
  advertises the current set. A message sealed to a discarded set can't be decrypted, and the
  destination remembers delivered `msg_id`s for longer than that, so a captured envelope can
  be delivered at most once.

### Relaying

A node that receives an envelope checks that it came from the previous node on the route (the
sender itself for the first relay). If the envelope is addressed to it, it opens it. Otherwise
it forwards the envelope only if it is the relay at position `hop`, increments `hop`, and hands
it to the next node. Relays never wait on a congested next hop; they drop the message.

By default a node relays for anyone, since the route was chosen by a sender that trusts it.
With `relay_for = "trusted"` in `[routing]`, a node relays only envelopes handed to it by a
peer it trusts.

The maximum payload is the same whether a message is routed or not: a frame minus the largest
envelope.

## Threat model

Protected against:

- **Passive eavesdroppers, including "harvest now, decrypt later."** Session keys need both
  X25519 and ML-KEM-768 to be broken.
- **Active network attackers impersonating a node.** That requires forging an ML-DSA-65
  signature for a key whose hash is the claimed node ID.
- **Tampering, replay, and reordering** of session frames.
- **Relays reading or forging routed messages.** Envelopes are sealed to the destination with
  the same hybrid construction and signed by the sender.
- **Forward secrecy.** Every connection uses fresh ephemeral keys, so a stolen identity key
  does not decrypt past sessions.

Not protected against, in the MVP:

- **Revealing presence on the LAN.** Announcements broadcast node IDs in the clear. Identity
  keys inside the handshake are encrypted, but the announcement already gives the ID away.
- **Denial of service, beyond basic limits.** A node runs at most 32 inbound handshakes and
  16 background dials at once, and holds at most 256 peers. Connections beyond those limits are
  dropped. That bounds resource use, but an attacker who can reach the port can still fill the
  slots and keep legitimate peers out, and the handshake does expensive work before
  authentication.
- **Forged announcements from on-link hosts** that make nodes try handshakes with unprivileged
  ports on LAN addresses (see Discovery).
- **Prefix collisions in everyday commands.** `ping`, `send` and `untrust` accept a unique ID
  prefix for convenience. `trust` always requires the full 64-character ID, because an attacker
  can cheaply grind a key whose ID matches a short prefix.
- **A compromised host.** Anyone who can read `identity.key` can impersonate the node. The
  data directory is created with mode 0700, `identity.key` with mode 0600, and the node warns
  at startup if `identity.key` is readable by other users. The control socket is mode 0600, so
  other local users cannot drive the daemon.
- **Malicious trusted nodes.** Trust is binary, and trusted nodes are assumed honest. A trusted
  relay can drop messages or advertise links it doesn't have.
- **Traffic analysis.** Relays see the sender, the destination, the route, and message sizes.
  LSAs reveal the mesh's shape to every node.
- **Forward secrecy for routed messages is limited** to the 15-minute life of the receiving
  keys, not per message. Someone who takes a node's memory can read routed messages sent to it
  in that window.
- **Untrusted nodes flooding LSAs.** Rate limits and the topology cap bound the damage, but an
  attacker with many identities can fill the 1024 slots that untrusted origins share.

## Code map

| Module | Responsibility |
| --- | --- |
| `identity` | ML-DSA-65 keys, node IDs, signing and verification |
| `handshake` | Hybrid key exchange, authentication, and the session ciphers |
| `wire` | Frame I/O and message encoding |
| `display` | Escaping peer-supplied text for the terminal |
| `discovery` | Multicast announce and listen |
| `node` | Listener, dialing, peer table, connection tasks, flooding and relaying, public API |
| `routing` | Link-state advertisements, topology and route selection, envelopes, receiving keys |
| `trust` | The allowlist file |
| `control` | Unix socket protocol between the CLI and the daemon |
| `config` | `config.toml` |
