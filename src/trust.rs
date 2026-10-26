//! The allowlist of trusted node IDs.
//!
//! Connecting to a node never makes it trusted. Trust only comes from this list, which the
//! user edits with `latchkey trust` and `latchkey untrust`. Once multi-hop routing exists,
//! only trusted nodes will be used as relays.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::identity::NodeId;

/// The trust file holds one hex node ID per line. Blank lines and `#` comments are ignored.
pub struct TrustStore {
    path: PathBuf,
    trusted: BTreeSet<NodeId>,
}

impl TrustStore {
    pub fn load(path: &Path) -> Result<Self> {
        let mut trusted = BTreeSet::new();
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading trust file {}", path.display()))?;
            for (n, line) in text.lines().enumerate() {
                let entry = line.split('#').next().unwrap_or("").trim();
                if entry.is_empty() {
                    continue;
                }
                let id = entry
                    .parse()
                    .with_context(|| format!("{}:{}: bad node ID", path.display(), n + 1))?;
                trusted.insert(id);
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            trusted,
        })
    }

    pub fn is_trusted(&self, id: &NodeId) -> bool {
        self.trusted.contains(id)
    }

    pub fn list(&self) -> impl Iterator<Item = &NodeId> {
        self.trusted.iter()
    }

    /// Add `id` and save. Returns false if it was already trusted.
    pub fn trust(&mut self, id: NodeId) -> Result<bool> {
        let added = self.trusted.insert(id);
        if added && let Err(e) = self.save() {
            self.trusted.remove(&id);
            return Err(e);
        }
        Ok(added)
    }

    /// Remove `id` and save. Returns false if it was not trusted.
    pub fn untrust(&mut self, id: &NodeId) -> Result<bool> {
        let removed = self.trusted.remove(id);
        if removed && let Err(e) = self.save() {
            self.trusted.insert(*id);
            return Err(e);
        }
        Ok(removed)
    }

    /// Write the list to a temporary file and rename it into place, so a crash mid-write
    /// never leaves a truncated allowlist.
    fn save(&self) -> Result<()> {
        use std::io::Write;

        if let Some(dir) = self.path.parent() {
            crate::identity::create_private_dir(dir)?;
        }
        let mut text = String::from("# Latchkey trusted node IDs, one per line\n");
        for id in &self.trusted {
            text.push_str(&id.to_string());
            text.push('\n');
        }
        let tmp = self.path.with_extension("tmp");
        let write = || -> std::io::Result<()> {
            let mut file = std::fs::File::create(&tmp)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        };
        write().with_context(|| format!("writing trust file {}", self.path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_persists_across_loads() {
        let dir = std::env::temp_dir().join(format!("latchkey-trust-{}", std::process::id()));
        let path = dir.join("trusted");
        let _ = std::fs::remove_dir_all(&dir);
        let id = NodeId([3; 32]);

        let mut store = TrustStore::load(&path).unwrap();
        assert!(!store.is_trusted(&id));
        assert!(store.trust(id).unwrap());
        assert!(!store.trust(id).unwrap());
        assert!(TrustStore::load(&path).unwrap().is_trusted(&id));

        assert!(store.untrust(&id).unwrap());
        assert!(!TrustStore::load(&path).unwrap().is_trusted(&id));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let dir = std::env::temp_dir().join(format!("latchkey-trust2-{}", std::process::id()));
        let path = dir.join("trusted");
        std::fs::create_dir_all(&dir).unwrap();
        let id = NodeId([9; 32]);
        std::fs::write(&path, format!("# header\n\n{id}  # laptop\n")).unwrap();
        assert!(TrustStore::load(&path).unwrap().is_trusted(&id));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
