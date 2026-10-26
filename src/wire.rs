//! Length-prefixed framing and the messages carried inside encrypted frames.

use anyhow::{Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame accepted from the network, in bytes.
pub const MAX_FRAME: usize = 64 * 1024;

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<()> {
    if body.len() > MAX_FRAME {
        bail!(
            "frame of {} bytes exceeds the {MAX_FRAME}-byte limit",
            body.len()
        );
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("peer sent a {len}-byte frame, over the {MAX_FRAME}-byte limit");
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// A message inside an encrypted frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Handshake authentication: the sender's verifying key and its signature over the transcript.
    Auth {
        verifying_key: Vec<u8>,
        signature: Vec<u8>,
    },
    Ping(u64),
    Pong(u64),
    /// Application data addressed to the receiving node.
    Data(Vec<u8>),
}

const TAG_AUTH: u8 = 1;
const TAG_PING: u8 = 2;
const TAG_PONG: u8 = 3;
const TAG_DATA: u8 = 4;

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Message::Auth {
                verifying_key,
                signature,
            } => {
                let mut out = Vec::with_capacity(3 + verifying_key.len() + signature.len());
                out.push(TAG_AUTH);
                out.extend_from_slice(&(verifying_key.len() as u16).to_be_bytes());
                out.extend_from_slice(verifying_key);
                out.extend_from_slice(signature);
                out
            }
            Message::Ping(n) => [&[TAG_PING][..], &n.to_be_bytes()].concat(),
            Message::Pong(n) => [&[TAG_PONG][..], &n.to_be_bytes()].concat(),
            Message::Data(data) => [&[TAG_DATA][..], data].concat(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let Some((&tag, rest)) = bytes.split_first() else {
            bail!("empty message");
        };
        Ok(match tag {
            TAG_AUTH => {
                if rest.len() < 2 {
                    bail!("truncated auth message");
                }
                let vk_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                let rest = &rest[2..];
                if rest.len() < vk_len {
                    bail!("truncated auth message");
                }
                let (vk, sig) = rest.split_at(vk_len);
                Message::Auth {
                    verifying_key: vk.to_vec(),
                    signature: sig.to_vec(),
                }
            }
            TAG_PING => Message::Ping(u64_from(rest)?),
            TAG_PONG => Message::Pong(u64_from(rest)?),
            TAG_DATA => Message::Data(rest.to_vec()),
            other => bail!("unknown message tag {other}"),
        })
    }
}

fn u64_from(bytes: &[u8]) -> Result<u64> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad u64 field"))?;
    Ok(u64::from_be_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip() {
        for msg in [
            Message::Auth {
                verifying_key: vec![1, 2, 3],
                signature: vec![4, 5],
            },
            Message::Ping(42),
            Message::Pong(u64::MAX),
            Message::Data(b"hello mesh".to_vec()),
            Message::Data(vec![]),
        ] {
            assert_eq!(Message::decode(&msg.encode()).unwrap(), msg);
        }
    }

    #[test]
    fn rejects_garbage() {
        assert!(Message::decode(&[]).is_err());
        assert!(Message::decode(&[99]).is_err());
        assert!(Message::decode(&[TAG_PING, 1, 2]).is_err());
        assert!(Message::decode(&[TAG_AUTH, 0, 10, 1]).is_err());
    }

    #[tokio::test]
    async fn frames_round_trip_and_enforce_limit() {
        let (mut a, mut b) = tokio::io::duplex(MAX_FRAME * 2);
        write_frame(&mut a, b"abc").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), b"abc");
        assert!(write_frame(&mut a, &vec![0; MAX_FRAME + 1]).await.is_err());
        a.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert!(read_frame(&mut b).await.is_err());
    }
}
