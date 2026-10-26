# Latchkey

Latchkey is a peer-to-peer mesh network secured with post-quantum cryptography. Nodes on the
same local network find each other over multicast and connect on their own; nodes elsewhere
join through static peer addresses. Every link is encrypted with a hybrid X25519 + ML-KEM-768
key exchange and authenticated with ML-DSA-65 identity keys.

Anyone can join the mesh, but joining does not make a node trusted. Trust is a separate
allowlist of node IDs that you control.

> **Status:** early MVP. Direct links between nodes work. Multi-hop routing is not built yet.
> Latchkey has not had a security audit, so don't rely on it to protect anything important.

## Quick start

```sh
cargo install --path .

# On each machine on the LAN:
latchkey run
```

Within a few seconds, the nodes discover each other and connect. In another terminal:

```sh
latchkey id                     # this node's ID
latchkey peers                  # connected peers and whether you trust them
latchkey ping 3f9a              # round-trip time to a peer (any unique ID prefix works)
latchkey send 3f9a hello there  # direct message; it shows up in the peer's `latchkey run` output
latchkey trust 3f9a             # add a peer to your allowlist
latchkey untrust 3f9a
latchkey trusted                # list the allowlist
```

To reach a node that multicast can't see, such as one on another subnet or over a VPN:

```sh
latchkey connect 10.1.2.3:47470           # once, from the CLI
latchkey run --peer 10.1.2.3:47470        # or at startup, retried until it connects
```

Run several nodes on one machine by giving each its own data directory and port:

```sh
latchkey --dir /tmp/lk-a run --listen 0.0.0.0:47480
latchkey --dir /tmp/lk-b run --listen 0.0.0.0:47481
latchkey --dir /tmp/lk-b peers
```

## Configuration

Latchkey keeps its state in a data directory: `~/.local/share/latchkey` on Linux and
`~/Library/Application Support/latchkey` on macOS. You can override it with `--dir` or
`LATCHKEY_DIR`.

| File | Purpose |
| --- | --- |
| `identity.key` | The node's ML-DSA-65 seed. Created on first run with mode 0600. Keep it secret. |
| `trusted` | The allowlist, one hex node ID per line. |
| `config.toml` | Optional settings, described below. |
| `control.sock` | Unix socket the CLI uses to talk to the running daemon. |

```toml
# config.toml (every field is optional)
listen = "0.0.0.0:47470"          # TCP address for peer connections
peers = ["10.1.2.3:47470"]        # static peers, retried every 15 s

[discovery]
enabled = true                    # multicast announce and discovery
port = 47471                      # UDP port, the same on every node
ipv6 = true                       # also use IPv6 link-local multicast
interval_secs = 5                 # time between announcements
```

## Using it as a library

```rust
use latchkey::{Config, Event, Node};

let node = Node::start(Config::default()).await?;
let mut events = node.subscribe();
while let Ok(event) = events.recv().await {
    if let Event::Message { from, trusted, data } = event {
        node.send(&from, b"got it".to_vec()).await?;
    }
}
```

## How it works

[`docs/design.md`](docs/design.md) covers the protocol, the trust model and the threat model.
In brief:

1. **Discovery.** Each node sends its node ID and TCP port to `239.255.76.75:47471` and
   `[ff02::6c6b:7931]:47471` every few seconds. When a node hears an announcement from a node
   it isn't connected to, it dials that node.
2. **Handshake.** The two nodes swap ephemeral X25519 keys and run ML-KEM-768. They derive
   ChaCha20-Poly1305 session keys from both shared secrets, so an attacker has to break both
   algorithms. Then each node signs the handshake transcript with its ML-DSA-65 identity key.
3. **Identity.** A node's ID is the SHA3-256 hash of its ML-DSA-65 public key, so an ID can't
   be claimed without the matching private key.
4. **Trust.** Every connected peer is authenticated, but only peers on your allowlist are
   trusted. Once routing exists, only trusted nodes will relay your traffic.

## Roadmap

- Multi-hop routing that relays only through trusted nodes
- A TUN interface, so ordinary IP applications can run over the mesh
- PKI or delegated trust, so you don't have to list every node by hand
- Windows support for the daemon and CLI (the library builds, but the control socket is Unix-only)

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
