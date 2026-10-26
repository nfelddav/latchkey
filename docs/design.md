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

Non-goals for the MVP: multi-hop routing, Byzantine fault tolerance, NAT traversal, and
hiding the existence of nodes from the local network.

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

When a node hears an announcement from a node ID it isn't connected to, it dials the sender's
source IP at the announced port. Announcements carry no authentication. They are only hints
about where to try a handshake, and the handshake proves who is on the other end. A forged
announcement can make a node attempt a handshake with an address of the attacker's choosing,
but it cannot make the node accept a false identity.

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
- Each side signs `th | role` with ML-DSA-65 under the context string `latchkey-v1`. The
  receiver verifies the signature and computes the peer's node ID from the verifying key.

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

Each side sends a keepalive `Ping(0)` every 15 seconds and closes a link that has been
silent for 45 seconds.

### Duplicate connections

Two nodes often dial each other at the same moment, for example when both hear the other's
announcement. When a node already has a link to a peer and a second one completes, both nodes
keep the link **initiated by the node with the lower node ID**. If both links were opened by
the same node, the newer one wins, because the older one is probably stale (for example, the
peer restarted). The two nodes apply the same rule independently, so they agree without
exchanging any messages.

## Trust model

- **Connected** means the peer completed the handshake. Its node ID is authenticated, but it
  may belong to anyone.
- **Trusted** means the peer's node ID is in your local `trusted` file.

In the MVP, trust labels messages and peers in the CLI and API (`Event::Message.trusted`,
`PeerInfo.trusted`), and untrusted peers can still exchange direct messages. Once multi-hop
routing exists, the rule will be: **never route packets through a node you don't trust.** Full
Byzantine resilience is a non-goal. Trusted nodes are assumed honest.

The allowlist is the first step. A PKI or delegated trust scheme may replace or extend it.

## Threat model

Protected against:

- **Passive eavesdroppers, including "harvest now, decrypt later."** Session keys need both
  X25519 and ML-KEM-768 to be broken.
- **Active network attackers impersonating a node.** That requires forging an ML-DSA-65
  signature for a key whose hash is the claimed node ID.
- **Tampering, replay, and reordering** of session frames.
- **Forward secrecy.** Every connection uses fresh ephemeral keys, so a stolen identity key
  does not decrypt past sessions.

Not protected against, in the MVP:

- **Revealing presence on the LAN.** Announcements broadcast node IDs in the clear. Identity
  keys inside the handshake are encrypted, but the announcement already gives the ID away.
- **Denial of service.** There is no limit on inbound connections or handshakes, and the
  handshake does expensive work before authentication. Anyone who can reach the port can use
  up CPU and memory.
- **Forged announcements** that make nodes dial arbitrary LAN addresses (see Discovery).
- **A compromised host.** Anyone who can read `identity.key` can impersonate the node. The
  control socket is mode 0600, so other local users cannot drive the daemon.
- **Malicious trusted nodes.** Trust is binary, and trusted nodes are assumed honest.

## Code map

| Module | Responsibility |
| --- | --- |
| `identity` | ML-DSA-65 keys, node IDs, signing and verification |
| `handshake` | Hybrid key exchange, authentication, and the session ciphers |
| `wire` | Frame I/O and message encoding |
| `discovery` | Multicast announce and listen |
| `node` | Listener, dialing, peer table, connection tasks, public API |
| `trust` | The allowlist file |
| `control` | Unix socket protocol between the CLI and the daemon |
| `config` | `config.toml` |
