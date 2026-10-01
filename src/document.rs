//! Shared signed-document cache for global publishers. Payload semantics remain
//! with the owning facade; csgn supplies envelope authentication and lifetimes.
use crate::{Error, MAX_COSE_BYTES, Result};
use serde::de::DeserializeOwned;
use std::sync::Arc;

/// Authenticated owner version. This is a policy floor, not a member event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    pub revision: u64,
    pub epoch: u64,
}

/// Typed public document semantics implemented by the publication owner.
/// Validate purpose, issuer/scope and all payload invariants. Do not infer fields
/// absent from the signed payload. This port performs no signing or I/O.
pub trait Document: DeserializeOwned + PartialEq {
    const KIND: csgn::Kind;
    fn version(&self, issuer: &str) -> Result<Version>;
}

struct Current<T> {
    issuer: String,
    value: T,
    version: Version,
    issued: u64,
    deadline: u64,
    bytes: Arc<[u8]>,
}

/// One issuer's current exact signed document, reused by the global facade.
/// Equal policy versions may refresh their envelope only if payloads agree and
/// signed issuance does not regress. This supports day-bucketed global status.
pub struct Cache<T> {
    current: Option<Current<T>>,
    high_water: u64,
}
impl<T> Default for Cache<T> {
    fn default() -> Self {
        Self {
            current: None,
            high_water: 0,
        }
    }
}
impl<T: Document> Cache<T> {
    fn observe(&mut self, now: u64) -> Result<()> {
        if now < self.high_water {
            return Err(Error::ClockRegression);
        }
        self.high_water = now;
        Ok(())
    }
    /// Authenticate with the configured owner's ring, never one from submitted
    /// bytes. Failed candidates leave the previous deadline unchanged.
    pub fn install(&mut self, ring: &csgn::KeyRing, bytes: Vec<u8>, now: u64) -> Result<Arc<[u8]>> {
        self.observe(now)?;
        if bytes.len() > MAX_COSE_BYTES {
            return Err(Error::Incoherent);
        }
        let signed = ring
            .verify(&bytes, T::KIND, now)
            .map_err(|_| Error::Signature)?;
        let value: T = serde_json::from_slice(signed.payload()).map_err(|_| Error::Incoherent)?;
        let version = value.version(ring.issuer())?;
        if version.revision == 0 || version.epoch == 0 {
            return Err(Error::Incoherent);
        }
        if let Some(old) = &self.current {
            if old.issuer != ring.issuer() {
                return Err(Error::Incoherent);
            }
            if version.revision < old.version.revision
                || version.epoch < old.version.epoch
                || signed.issued_at() < old.issued
            {
                return Err(Error::Rollback);
            }
            if version == old.version && value != old.value {
                return Err(Error::Equivocation);
            }
        }
        let issued = signed.issued_at();
        let deadline = signed.valid_until();
        let bytes: Arc<[u8]> = bytes.into();
        self.current = Some(Current {
            issuer: ring.issuer().into(),
            value,
            version,
            issued,
            deadline,
            bytes: bytes.clone(),
        });
        Ok(bytes)
    }
    /// Exact cached signed bytes; neither a replacement signature nor a history.
    pub fn current(&mut self, now: u64) -> Result<Arc<[u8]>> {
        self.observe(now)?;
        let current = self.current.as_ref().ok_or(Error::Unavailable)?;
        if now >= current.deadline {
            return Err(Error::Expired);
        }
        Ok(current.bytes.clone())
    }
}
