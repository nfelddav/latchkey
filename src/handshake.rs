//! The hybrid post-quantum handshake and the encrypted session it produces.
//!
//! 1. Initiator sends `Hello`: an ephemeral X25519 public key and an ephemeral ML-KEM-768
//!    encapsulation key.
//! 2. Responder replies with its own ephemeral X25519 public key and an ML-KEM-768 ciphertext
//!    encapsulated to the initiator's key.
//! 3. Both sides derive directional ChaCha20-Poly1305 keys with HKDF-SHA3-256 over
//!    `x25519_secret || mlkem_secret`, salted with the transcript hash.
//! 4. Both sides send an encrypted `Auth` message holding their ML-DSA-65 verifying key and a
//!    signature over the transcript hash and their role. The peer's node ID is the hash of
//!    that key.
//!
//! An attacker must break both X25519 and ML-KEM to recover session keys, and must forge an
//! ML-DSA signature to impersonate a node. See `docs/design.md` for the threat model.

use anyhow::{Context, Result, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::SimpleHkdf;
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem768, TryKeyInit};
use sha3::{Digest, Sha3_256};
use tokio::io::{AsyncRead, AsyncWrite};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::identity::{self, Identity, NodeId};
use crate::wire::{Message, read_frame, write_frame};

const MAGIC: &[u8; 4] = b"LKY1";
const X25519_LEN: usize = 32;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const TRANSCRIPT_LABEL: &[u8] = b"latchkey-v1 handshake";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Role::Initiator => b'I',
            Role::Responder => b'R',
        }
    }

    fn other(self) -> Self {
        match self {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        }
    }
}

/// The outcome of a successful handshake.
pub struct Established {
    pub peer: NodeId,
    pub send: SendCipher,
    pub recv: RecvCipher,
}

/// Run the handshake as `role` over `stream`.
pub async fn handshake<S>(stream: &mut S, identity: &Identity, role: Role) -> Result<Established>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let x_secret = EphemeralSecret::random();
    let x_public = PublicKey::from(&x_secret);

    let (hello_i, hello_r, x_peer, kem_secret) = match role {
        Role::Initiator => {
            let (dk, ek) = MlKem768::generate_keypair();
            let hello_i = [&MAGIC[..], x_public.as_bytes(), &ek.to_bytes()].concat();
            write_frame(stream, &hello_i).await?;

            let hello_r = read_frame(stream).await?;
            let body = strip_magic(&hello_r, X25519_LEN + MLKEM_CT_LEN)?;
            let (x_peer, ct) = body.split_at(X25519_LEN);
            let kem_secret = dk
                .decapsulate_slice(ct)
                .map_err(|_| anyhow::anyhow!("bad ML-KEM ciphertext"))?;
            let x_peer = x_peer.to_vec();
            (
                hello_i,
                hello_r,
                x_peer,
                Zeroizing::new(kem_secret.to_vec()),
            )
        }
        Role::Responder => {
            let hello_i = read_frame(stream).await?;
            let body = strip_magic(&hello_i, X25519_LEN + MLKEM_EK_LEN)?;
            let (x_peer, ek) = body.split_at(X25519_LEN);
            let ek = ml_kem::ml_kem_768::EncapsulationKey::new_from_slice(ek)
                .map_err(|_| anyhow::anyhow!("bad ML-KEM encapsulation key"))?;
            let (ct, kem_secret) = ek.encapsulate();
            let hello_r = [&MAGIC[..], x_public.as_bytes(), &ct[..]].concat();
            write_frame(stream, &hello_r).await?;
            let x_peer = x_peer.to_vec();
            (
                hello_i,
                hello_r,
                x_peer,
                Zeroizing::new(kem_secret.to_vec()),
            )
        }
    };

    let x_peer: [u8; 32] = x_peer.try_into().expect("length checked above");
    let x_shared = x_secret.diffie_hellman(&PublicKey::from(x_peer));
    ensure!(
        x_shared.was_contributory(),
        "peer sent a low-order X25519 key"
    );

    let transcript: [u8; 32] = Sha3_256::new()
        .chain_update(TRANSCRIPT_LABEL)
        .chain_update(&hello_i)
        .chain_update(&hello_r)
        .finalize()
        .into();

    let ikm = Zeroizing::new([x_shared.as_bytes().as_slice(), &kem_secret].concat());
    let hkdf = SimpleHkdf::<Sha3_256>::new(Some(&transcript), &ikm);
    let mut i2r = Zeroizing::new([0u8; 32]);
    let mut r2i = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"latchkey-v1 i2r", i2r.as_mut())
        .expect("valid HKDF length");
    hkdf.expand(b"latchkey-v1 r2i", r2i.as_mut())
        .expect("valid HKDF length");
    let (send_key, recv_key) = match role {
        Role::Initiator => (&i2r, &r2i),
        Role::Responder => (&r2i, &i2r),
    };
    let mut send = SendCipher::new(send_key);
    let mut recv = RecvCipher::new(recv_key);

    let auth = Message::Auth {
        verifying_key: identity.verifying_key_bytes(),
        signature: identity.sign(&auth_payload(&transcript, role)),
    };
    write_frame(stream, &send.seal(&auth.encode())?).await?;

    let frame = read_frame(stream).await?;
    let Message::Auth {
        verifying_key,
        signature,
    } = Message::decode(&recv.open(&frame)?)?
    else {
        bail!("expected an auth message");
    };
    let peer = identity::verify(
        &verifying_key,
        &auth_payload(&transcript, role.other()),
        &signature,
    )
    .context("peer failed to authenticate")?;

    Ok(Established { peer, send, recv })
}

fn auth_payload(transcript: &[u8; 32], signer: Role) -> Vec<u8> {
    [&transcript[..], &[signer.byte()]].concat()
}

fn strip_magic(frame: &[u8], body_len: usize) -> Result<&[u8]> {
    ensure!(
        frame.len() == MAGIC.len() + body_len,
        "malformed hello ({} bytes)",
        frame.len()
    );
    ensure!(
        &frame[..4] == MAGIC,
        "not a Latchkey peer or unsupported version"
    );
    Ok(&frame[4..])
}

fn nonce_for(counter: u64) -> Nonce {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce.into()
}

/// Encrypts outgoing frames. The nonce is a per-direction counter, so frames must be sent in
/// the order they are sealed.
pub struct SendCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl SendCipher {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(*key)),
            counter: 0,
        }
    }

    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        ensure!(self.counter < u64::MAX, "send nonce space exhausted");
        let out = self
            .cipher
            .encrypt(&nonce_for(self.counter), plaintext)
            .map_err(|_| anyhow::anyhow!("encryption failed"))?;
        self.counter += 1;
        Ok(out)
    }
}

/// Decrypts incoming frames, rejecting any frame that is forged, replayed, or reordered.
pub struct RecvCipher {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl RecvCipher {
    fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(&Key::from(*key)),
            counter: 0,
        }
    }

    pub fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        ensure!(self.counter < u64::MAX, "receive nonce space exhausted");
        let out = self
            .cipher
            .decrypt(&nonce_for(self.counter), ciphertext)
            .map_err(|_| anyhow::anyhow!("frame failed authentication"))?;
        self.counter += 1;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair() -> (Result<Established>, Result<Established>, NodeId, NodeId) {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let ia = Identity::generate().unwrap();
        let ib = Identity::generate().unwrap();
        let (ra, rb) = tokio::join!(
            handshake(&mut a, &ia, Role::Initiator),
            handshake(&mut b, &ib, Role::Responder),
        );
        (ra, rb, ia.id(), ib.id())
    }

    #[tokio::test]
    async fn peers_learn_each_others_ids_and_can_talk() {
        let (a, b, id_a, id_b) = pair().await;
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.peer, id_b);
        assert_eq!(b.peer, id_a);

        let sealed = a.send.seal(b"over the mesh").unwrap();
        assert_eq!(b.recv.open(&sealed).unwrap(), b"over the mesh");
        let sealed = b.send.seal(b"and back").unwrap();
        assert_eq!(a.recv.open(&sealed).unwrap(), b"and back");
    }

    #[tokio::test]
    async fn replayed_and_tampered_frames_are_rejected() {
        let (a, b, _, _) = pair().await;
        let (mut a, mut b) = (a.unwrap(), b.unwrap());
        let first = a.send.seal(b"one").unwrap();
        b.recv.open(&first).unwrap();
        assert!(b.recv.open(&first).is_err(), "replay must fail");

        let mut second = a.send.seal(b"two").unwrap();
        second[0] ^= 1;
        assert!(b.recv.open(&second).is_err(), "tampering must fail");
    }

    #[tokio::test]
    async fn wrong_magic_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let ib = Identity::generate().unwrap();
        write_frame(&mut a, &vec![0u8; 4 + X25519_LEN + MLKEM_EK_LEN])
            .await
            .unwrap();
        assert!(handshake(&mut b, &ib, Role::Responder).await.is_err());
    }
}
