//! Signature and publication metadata for the canonical Balance owner document.
//! Economic policy and proof-artifact semantics remain with its accounting owner.
use crate::{Error, Result};
use serde::Deserialize;

/// Authenticated original owner bytes, not a current member-record capability.
#[derive(Clone)]
pub struct Balance {
    revision: u64,
    deadline: u64,
    bytes: Vec<u8>,
    payload: Vec<u8>,
}

impl Balance {
    /// Verify against the configured publication ring and signed manifest floors.
    /// This deliberately reads only routing metadata, never a second economic schema.
    pub fn verify(
        ring: &csgn::KeyRing,
        bytes: &[u8],
        epoch: u64,
        revision: u64,
        now: u64,
    ) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Header {
            purpose: String,
            community: String,
            revision: u64,
            policy_epoch: u64,
        }
        if bytes.len() > crate::MAX_COSE_BYTES {
            return Err(Error::Incoherent);
        }
        let signed = ring
            .verify(bytes, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Signature)?;
        let header: Header =
            serde_json::from_slice(signed.payload()).map_err(|_| Error::Incoherent)?;
        if header.purpose != "cblc.public-verifier.v2"
            || header.community != ring.issuer()
            || header.revision != revision
            || revision == 0
            || revision > i64::MAX as u64
            || header.policy_epoch != epoch
            || epoch == 0
            || epoch > i64::MAX as u64
        {
            return Err(Error::Incoherent);
        }
        Ok(Self {
            revision,
            deadline: signed.valid_until(),
            bytes: bytes.to_vec(),
            payload: signed.payload().to_vec(),
        })
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn valid_until(&self) -> u64 {
        self.deadline
    }
    /// Decode with the canonical accounting owner only after checking this view's lifetime.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Original authenticated JSON; economic validation belongs to Balance.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Retain per-kind floors even when the previous publication has expired.
    pub fn check_successor(&self, previous: &Self) -> Result<()> {
        if self.revision < previous.revision {
            return Err(Error::Rollback);
        }
        if self.revision == previous.revision && self.bytes != previous.bytes {
            return Err(Error::Equivocation);
        }
        Ok(())
    }
}
