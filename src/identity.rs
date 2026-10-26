//! Long-term node identity: an ML-DSA-65 signing key and the node ID derived from it.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use ml_dsa::signature::Keypair;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

/// Domain separation context passed to ML-DSA for every Latchkey signature.
const SIGNATURE_CONTEXT: &[u8] = b"latchkey-v1";

/// Encoded size of an ML-DSA-65 verifying key.
pub const VERIFYING_KEY_LEN: usize = 1952;
/// Encoded size of an ML-DSA-65 signature.
pub const SIGNATURE_LEN: usize = 3309;

/// A node's long-term identity.
pub struct Identity {
    signing_key: SigningKey<MlDsa65>,
    verifying_key: VerifyingKey<MlDsa65>,
    id: NodeId,
}

impl Identity {
    /// Generate a fresh identity from the OS random number generator.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        Ok(Self::from_seed(&seed))
    }

    /// Rebuild an identity from its 32-byte ML-DSA seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
        let verifying_key = signing_key.verifying_key();
        let id = NodeId::from_verifying_key(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            id,
        }
    }

    /// Load the identity stored at `path`, creating and saving a new one if it does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let text = Zeroizing::new(
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading identity {}", path.display()))?,
            );
            let bytes =
                Zeroizing::new(hex::decode(text.trim()).context("identity file is not hex")?);
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .context("identity file must hold a 32-byte seed")?;
            return Ok(Self::from_seed(&seed));
        }
        let identity = Self::generate()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let seed = Zeroizing::new(hex::encode(identity.signing_key.to_seed()));
        write_private(path, seed.as_bytes())
            .with_context(|| format!("writing identity {}", path.display()))?;
        Ok(identity)
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    /// The encoded public verifying key, sent to peers during the handshake.
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.encode().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.signing_key
            .expanded_key()
            .sign_deterministic(message, SIGNATURE_CONTEXT)
            .expect("context is shorter than 255 bytes")
            .encode()
            .to_vec()
    }
}

/// Verify `signature` over `message` against an encoded verifying key, returning the signer's ID.
pub fn verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<NodeId> {
    let Ok(encoded) = EncodedVerifyingKey::<MlDsa65>::try_from(verifying_key) else {
        bail!("bad verifying key length");
    };
    let key = VerifyingKey::<MlDsa65>::decode(&encoded);
    let Ok(signature) = Signature::<MlDsa65>::try_from(signature) else {
        bail!("malformed signature");
    };
    if !key.verify_with_context(message, SIGNATURE_CONTEXT, &signature) {
        bail!("signature verification failed");
    }
    Ok(NodeId::from_verifying_key(&key))
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// A node's ID: the SHA3-256 hash of its encoded ML-DSA-65 verifying key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; 32]);

impl NodeId {
    fn from_verifying_key(key: &VerifyingKey<MlDsa65>) -> Self {
        Self(Sha3_256::digest(key.encode()).into())
    }

    /// The first 16 hex characters, for compact display.
    pub fn short(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.short())
    }
}

impl FromStr for NodeId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s.trim()).context("node ID is not hex")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("node ID must be 64 hex characters"))?;
        Ok(Self(bytes))
    }
}

impl serde::Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let identity = Identity::generate().unwrap();
        let signature = identity.sign(b"hello");
        assert_eq!(signature.len(), SIGNATURE_LEN);
        let vk = identity.verifying_key_bytes();
        assert_eq!(vk.len(), VERIFYING_KEY_LEN);
        assert_eq!(verify(&vk, b"hello", &signature).unwrap(), identity.id());
        assert!(verify(&vk, b"tampered", &signature).is_err());
    }

    #[test]
    fn seed_reproduces_identity() {
        let seed = [7u8; 32];
        assert_eq!(
            Identity::from_seed(&seed).id(),
            Identity::from_seed(&seed).id()
        );
    }

    #[test]
    fn node_id_parses_its_display_form() {
        let id = Identity::generate().unwrap().id();
        assert_eq!(id.to_string().parse::<NodeId>().unwrap(), id);
    }

    #[test]
    fn identity_file_is_reloaded() {
        let dir = std::env::temp_dir().join(format!("latchkey-id-{}", std::process::id()));
        let path = dir.join("identity.key");
        let _ = std::fs::remove_dir_all(&dir);
        let first = Identity::load_or_create(&path).unwrap();
        let second = Identity::load_or_create(&path).unwrap();
        assert_eq!(first.id(), second.id());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
