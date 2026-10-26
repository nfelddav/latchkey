//! The local control socket the CLI uses to talk to a running daemon.
//!
//! One JSON request per line, one JSON response per line, over a Unix socket in the data
//! directory. The socket is created mode 0600, so only the owning user can drive the node.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::identity::NodeId;
use crate::node::Node;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Status,
    Peers,
    Ping { peer: String },
    Send { peer: String, text: String },
    Connect { addr: String },
    Trust { id: String },
    Untrust { id: String },
    Trusted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub result: Value,
}

/// Serve control requests for `node` on the Unix socket at `path` until the node shuts down.
pub async fn serve(node: Node, path: &Path) -> Result<()> {
    if path.exists() {
        if UnixStream::connect(path).await.is_ok() {
            bail!(
                "another latchkey daemon is already using {}",
                path.display()
            );
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    loop {
        let (stream, _) = listener.accept().await?;
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(node, stream).await {
                tracing::debug!("control client error: {e:#}");
            }
        });
    }
}

async fn handle_client(node: Node, stream: UnixStream) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<Request>(&line) {
            Ok(request) => match execute(&node, request).await {
                Ok(result) => Response {
                    ok: true,
                    error: None,
                    result,
                },
                Err(e) => Response {
                    ok: false,
                    error: Some(format!("{e:#}")),
                    result: Value::Null,
                },
            },
            Err(e) => Response {
                ok: false,
                error: Some(format!("bad request: {e}")),
                result: Value::Null,
            },
        };
        let mut out = serde_json::to_vec(&response)?;
        out.push(b'\n');
        writer.write_all(&out).await?;
    }
    Ok(())
}

async fn execute(node: &Node, request: Request) -> Result<Value> {
    Ok(match request {
        Request::Status => json!({
            "id": node.id(),
            "listen": node.local_addr(),
            "peers": node.peers().len(),
        }),
        Request::Peers => serde_json::to_value(node.peers())?,
        Request::Ping { peer } => {
            let id = node.resolve(&peer)?;
            let rtt = node.ping(&id).await?;
            json!({ "id": id, "rtt_ms": rtt.as_secs_f64() * 1000.0 })
        }
        Request::Send { peer, text } => {
            let id = node.resolve(&peer)?;
            node.send(&id, text.into_bytes()).await?;
            json!({ "id": id, "trusted": node.is_trusted(&id) })
        }
        Request::Connect { addr } => {
            let addr = tokio::net::lookup_host(addr.as_str())
                .await?
                .next()
                .with_context(|| format!("{addr} did not resolve"))?;
            let id = node.connect(addr).await?;
            json!({ "id": id, "trusted": node.is_trusted(&id) })
        }
        Request::Trust { id } => {
            // Never trust by prefix: anyone can connect, and grinding a key whose ID matches a
            // short prefix is cheap, so a prefix could resolve to an attacker's node.
            let id: NodeId = id
                .trim()
                .parse()
                .context("trust needs the full 64-character node ID (run `latchkey peers` or `latchkey id` on that node)")?;
            json!({ "id": id, "changed": node.trust(id)? })
        }
        Request::Untrust { id } => {
            let id = node.resolve(&id)?;
            json!({ "id": id, "changed": node.untrust(&id)? })
        }
        Request::Trusted => serde_json::to_value(node.trusted())?,
    })
}

/// Send one request to the daemon at `path` and return its result.
///
/// Fails with [`NotRunning`] if no daemon is listening, so callers can fall back to offline
/// behaviour.
pub async fn request(path: &Path, request: &Request) -> Result<Value> {
    let stream = UnixStream::connect(path).await.map_err(|_| NotRunning)?;
    let (reader, mut writer) = stream.into_split();
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    writer.write_all(&line).await?;
    let mut lines = BufReader::new(reader).lines();
    let reply = tokio::time::timeout(Duration::from_secs(30), lines.next_line())
        .await
        .context("daemon did not answer")??
        .context("daemon closed the connection")?;
    let response: Response = serde_json::from_str(&reply)?;
    if response.ok {
        Ok(response.result)
    } else {
        bail!(response.error.unwrap_or_else(|| "unknown error".into()))
    }
}

/// No daemon is listening on the control socket.
#[derive(Debug)]
pub struct NotRunning;

impl std::fmt::Display for NotRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the latchkey daemon is not running (start it with `latchkey run`)")
    }
}

impl std::error::Error for NotRunning {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;
    use crate::config::DiscoveryConfig;

    #[tokio::test]
    async fn trust_requires_a_full_node_id() {
        let dir = std::env::temp_dir().join(format!("latchkey-control-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = |name: &str| Config {
            data_dir: dir.join(name),
            listen: "127.0.0.1:0".parse().unwrap(),
            peers: vec![],
            discovery: DiscoveryConfig {
                enabled: false,
                ..Default::default()
            },
        };
        let a = Node::start(config("a")).await.unwrap();
        let b = Node::start(config("b")).await.unwrap();
        b.connect(a.local_addr()).await.unwrap();

        let prefix = a.id().to_string()[..8].to_string();
        // Prefixes still work for everyday commands...
        assert!(
            execute(
                &b,
                Request::Ping {
                    peer: prefix.clone()
                }
            )
            .await
            .is_ok()
        );
        // ...but not for trust.
        assert!(execute(&b, Request::Trust { id: prefix }).await.is_err());
        assert!(!b.is_trusted(&a.id()));
        assert!(
            execute(
                &b,
                Request::Trust {
                    id: a.id().to_string()
                }
            )
            .await
            .is_ok()
        );
        assert!(b.is_trusted(&a.id()));

        a.shutdown();
        b.shutdown();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
