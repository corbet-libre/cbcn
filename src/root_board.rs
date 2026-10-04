//! Authenticated common root-board public descriptor transport.
//! Credential codec and proof semantics remain with CPSD and its consumers.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Domain separation for the Policy owner's public descriptor.
pub const PURPOSE: &str = "cplc.root-board.v1";

/// Public routing metadata and the original canonical CPSD descriptor bytes.
/// Deserializing this value does not authenticate or validate the descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub purpose: String,
    pub community: String,
    pub revision: u64,
    pub policy_epoch: u64,
    pub descriptor: Vec<u8>,
}

/// Authenticated owner bytes, not a credential, role or decoded CPSD capability.
#[derive(Clone)]
pub struct RootBoard {
    revision: u64,
    deadline: u64,
    bytes: Vec<u8>,
    payload: Vec<u8>,
}
impl RootBoard {
    /// Authenticate against the configured ring and exact signed manifest floors.
    pub fn verify(
        ring: &csgn::KeyRing,
        bytes: &[u8],
        epoch: u64,
        revision: u64,
        now: u64,
    ) -> Result<Self> {
        if bytes.len() > crate::MAX_COSE_BYTES {
            return Err(Error::Incoherent);
        }
        let signed = ring
            .verify(bytes, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Signature)?;
        let payload: Payload =
            serde_json::from_slice(signed.payload()).map_err(|_| Error::Incoherent)?;
        if payload.purpose != PURPOSE
            || payload.community != ring.issuer()
            || payload.revision != revision
            || revision == 0
            || revision > i64::MAX as u64
            || payload.policy_epoch != epoch
            || epoch == 0
            || epoch > i64::MAX as u64
            || payload.descriptor.is_empty()
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
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Original authenticated JSON. A current consumer must decode the descriptor
    /// with CPSD and check scope, epoch and lifetime before using it.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    /// Retain the per-kind floor even after the previous envelope expires.
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
