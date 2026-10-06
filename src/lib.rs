//! Beacon assembles signed public trust publications with injected I/O and time.
#![forbid(unsafe_code)]
pub mod balance;
pub mod document;
pub mod root_board;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub type Result<T> = std::result::Result<T, Error>;
/// Stable diagnostics contain no publisher errors, document data or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Publication,
    Signature,
    Incoherent,
    Rollback,
    Equivocation,
    Expired,
    ClockRegression,
    Unavailable,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Existing public publication kinds, in the door's original publication order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Settings,
    Schema,
    Communities,
    Revocations,
    SchemaVersions,
}
impl Kind {
    fn signing_kind(self) -> csgn::Kind {
        match self {
            Self::Settings => csgn::Kind::SettingsSnapshot,
            Self::Schema | Self::SchemaVersions => csgn::Kind::SchemaSnapshot,
            Self::Communities => csgn::Kind::CommunitiesSnapshot,
            Self::Revocations => csgn::Kind::RevocationListSnapshot,
        }
    }
}
const KINDS: [Kind; 5] = [
    Kind::Settings,
    Kind::Schema,
    Kind::Communities,
    Kind::Revocations,
    Kind::SchemaVersions,
];
const MAX_COSE_BYTES: usize = (1 << 20) + 8192;

/// Privileged port implemented by the configured publication owner. The key ring
/// is from that owner's signer, never copied from an untrusted submitted feed.
/// Serialize the whole collect operation with policy mutations and key rotation.
pub trait Publisher: Send {
    fn key_ring(&self) -> Result<csgn::KeyRing>;
    /// Original durable public ring proofs retained by the publication owner.
    fn key_transitions(&self) -> Result<Vec<KeyTransition>> {
        Ok(Vec::new())
    }
    fn publish(&mut self, kind: Kind, now: u64) -> impl Future<Output = Result<Vec<u8>>> + Send;
    fn manifest(&mut self, now: u64) -> impl Future<Output = Result<Vec<u8>>> + Send;
    /// Original common root-board public descriptor, when configured.
    fn root_board(&mut self, _now: u64) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send {
        std::future::ready(Ok(None))
    }
    /// Original canonical Balance document, when this community has accounting.
    fn balance(&mut self, _now: u64) -> impl Future<Output = Result<Option<Vec<u8>>>> + Send {
        std::future::ready(Ok(None))
    }
}

/// The existing door transport. Fields are public data, never authority by type.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub revision: u64,
    pub policy_epoch: u64,
    pub key_ring: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_transitions: Vec<KeyTransition>,
    pub manifest: Vec<u8>,
    pub settings: Vec<u8>,
    pub schema: Vec<u8>,
    pub communities: Vec<u8>,
    pub revocations: Vec<u8>,
    pub schema_versions: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_board: Option<Vec<u8>>,
}
impl Feed {
    fn documents(&self) -> [&[u8]; 5] {
        [
            &self.settings,
            &self.schema,
            &self.communities,
            &self.revocations,
            &self.schema_versions,
        ]
    }
}

/// Original signed ring-change bytes, not authority by type.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyTransition {
    pub revision: u64,
    pub proof: Vec<u8>,
}
/// Retained public changes are bounded independently of member activity.
pub const MAX_KEY_TRANSITIONS: usize = 256;
pub const MAX_KEY_TRANSITION_BYTES: usize = 1 << 20;

/// Check transport/storage shape only. Charter authenticates configured continuity.
pub fn validate_transition_history(history: &[KeyTransition]) -> Result<()> {
    if history.len() > MAX_KEY_TRANSITIONS {
        return Err(Error::Incoherent);
    }
    let mut revision = 0;
    let mut size = 0usize;
    for item in history {
        size = size.saturating_add(item.proof.len());
        if item.revision <= revision || item.proof.is_empty() || size > MAX_KEY_TRANSITION_BYTES {
            return Err(Error::Incoherent);
        }
        revision = item.revision;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    purpose: String,
    community: String,
    revision: u64,
    policy_epoch: u64,
    key_ring: Vec<u8>,
    schema_version: u32,
    #[serde(default)]
    balance_revision: Option<u64>,
    #[serde(default)]
    root_board_revision: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    community: String,
    revision: u64,
    policy_epoch: u64,
    content: serde_json::Value,
}

/// Authenticated complete candidate. Only collection from a Publisher creates it.
pub struct Publication {
    observed_at: u64,
    community: String,
    feed: Arc<Feed>,
    deadline: u64,
    revisions: [u64; 5],
    balance: Option<balance::Balance>,
    root_board: Option<root_board::RootBoard>,
}

/// Preserve the door's original sequence. The publisher persists each signed
/// result first; only a fully authenticated candidate reaches the public cache.
pub async fn collect(publisher: &mut impl Publisher, now: u64) -> Result<Publication> {
    let settings = publisher.publish(Kind::Settings, now).await?;
    let schema = publisher.publish(Kind::Schema, now).await?;
    let communities = publisher.publish(Kind::Communities, now).await?;
    let revocations = publisher.publish(Kind::Revocations, now).await?;
    let schema_versions = publisher.publish(Kind::SchemaVersions, now).await?;
    let balance_bytes = publisher.balance(now).await?;
    let root_board_bytes = publisher.root_board(now).await?;
    let manifest = publisher.manifest(now).await?;
    let ring = publisher.key_ring()?;
    let key_transitions = publisher.key_transitions()?;
    validate_transition_history(&key_transitions)?;
    let (view, mut deadline): (Manifest, _) =
        verify(&ring, &manifest, csgn::Kind::SettingsSnapshot, now)?;
    if view.purpose != "cplc.trust.v1"
        || view.community != ring.issuer()
        || view.key_ring != ring.to_cbor()
        || view.revision == 0
        || view.revision > i64::MAX as u64
        || view.policy_epoch == 0
        || view.policy_epoch > i64::MAX as u64
        || view.schema_version == 0
    {
        return Err(Error::Incoherent);
    }
    let feed = Feed {
        revision: view.revision,
        policy_epoch: view.policy_epoch,
        key_ring: view.key_ring,
        key_transitions,
        manifest,
        settings,
        schema,
        communities,
        revocations,
        schema_versions,
        balance: balance_bytes,
        root_board: root_board_bytes,
    };
    let mut revisions = [0; 5];
    for ((kind, bytes), revision) in KINDS.into_iter().zip(feed.documents()).zip(&mut revisions) {
        let (snapshot, until): (Snapshot, _) = verify(&ring, bytes, kind.signing_kind(), now)?;
        if snapshot.community != view.community
            || snapshot.policy_epoch != view.policy_epoch
            || snapshot.revision == 0
            || snapshot.revision > view.revision
        {
            return Err(Error::Incoherent);
        }
        match kind {
            Kind::Schema
                if snapshot.content.get("version").and_then(|v| v.as_u64())
                    != Some(u64::from(view.schema_version)) =>
            {
                return Err(Error::Incoherent);
            }
            _ => (),
        }
        *revision = snapshot.revision;
        deadline = deadline.min(until);
    }
    let balance = match (&feed.balance, view.balance_revision) {
        (None, None) => None,
        (Some(bytes), Some(revision)) if revision <= view.revision => {
            let material =
                balance::Balance::verify(&ring, bytes, view.policy_epoch, revision, now)?;
            deadline = deadline.min(material.valid_until());
            Some(material)
        }
        _ => return Err(Error::Incoherent),
    };
    let root_board = match (&feed.root_board, view.root_board_revision) {
        (None, None) => None,
        (Some(bytes), Some(revision)) if revision <= view.revision => {
            let material =
                root_board::RootBoard::verify(&ring, bytes, view.policy_epoch, revision, now)?;
            deadline = deadline.min(material.valid_until());
            Some(material)
        }
        _ => return Err(Error::Incoherent),
    };
    Ok(Publication {
        observed_at: now,
        community: view.community,
        feed: Arc::new(feed),
        deadline,
        revisions,
        balance,
        root_board,
    })
}
fn verify<T: serde::de::DeserializeOwned>(
    ring: &csgn::KeyRing,
    bytes: &[u8],
    kind: csgn::Kind,
    now: u64,
) -> Result<(T, u64)> {
    if bytes.len() > MAX_COSE_BYTES {
        return Err(Error::Incoherent);
    }
    let signed = ring
        .verify(bytes, kind, now)
        .map_err(|_| Error::Signature)?;
    let value = serde_json::from_slice(signed.payload()).map_err(|_| Error::Incoherent)?;
    Ok((value, signed.valid_until()))
}

/// A hint to refetch, not a signature or an authority floor.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Announcement {
    pub revision: u64,
    pub policy_epoch: u64,
    pub changed: bool,
}

/// Current publication only; no activity history or I/O. A failed replacement
/// retains the old candidate, whose original deadline never gets extended.
#[derive(Default)]
pub struct Beacon {
    current: Option<Publication>,
    high_water: u64,
}
impl Beacon {
    fn observe(&mut self, now: u64) -> Result<()> {
        if now < self.high_water {
            return Err(Error::ClockRegression);
        }
        self.high_water = now;
        Ok(())
    }
    pub fn install(&mut self, candidate: Publication, now: u64) -> Result<Arc<Feed>> {
        self.observe(now)?;
        if now < candidate.observed_at {
            return Err(Error::ClockRegression);
        }
        if now >= candidate.deadline {
            return Err(Error::Expired);
        }
        if let Some(old) = &self.current {
            if candidate.community != old.community {
                return Err(Error::Incoherent);
            }
            if candidate.feed.revision == old.feed.revision && candidate.feed != old.feed {
                return Err(Error::Equivocation);
            }
            if candidate.feed.revision < old.feed.revision
                || candidate.feed.policy_epoch < old.feed.policy_epoch
            {
                return Err(Error::Rollback);
            }
            for ((new_revision, old_revision), (new_bytes, old_bytes)) in
                candidate.revisions.iter().zip(old.revisions.iter()).zip(
                    candidate
                        .feed
                        .documents()
                        .into_iter()
                        .zip(old.feed.documents()),
                )
            {
                if new_revision < old_revision {
                    return Err(Error::Rollback);
                }
                if new_revision == old_revision && new_bytes != old_bytes {
                    return Err(Error::Equivocation);
                }
            }
            if let Some(previous) = &old.balance {
                candidate
                    .balance
                    .as_ref()
                    .ok_or(Error::Rollback)?
                    .check_successor(previous)?;
            }
        }
        if let Some(previous) = self
            .current
            .as_ref()
            .and_then(|old| old.root_board.as_ref())
        {
            candidate
                .root_board
                .as_ref()
                .ok_or(Error::Rollback)?
                .check_successor(previous)?;
        }
        let feed = candidate.feed.clone();
        self.current = Some(candidate);
        Ok(feed)
    }
    pub fn current(&mut self, now: u64) -> Result<Arc<Feed>> {
        self.observe(now)?;
        let current = self.current.as_ref().ok_or(Error::Unavailable)?;
        if now >= current.deadline {
            return Err(Error::Expired);
        }
        Ok(current.feed.clone())
    }
    pub fn changes_since(&mut self, revision: u64, now: u64) -> Result<Announcement> {
        let current = self.current(now)?;
        if revision > current.revision {
            return Err(Error::Rollback);
        }
        Ok(Announcement {
            revision: current.revision,
            policy_epoch: current.policy_epoch,
            changed: revision != current.revision,
        })
    }
}
