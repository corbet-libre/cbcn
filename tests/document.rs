//! Real signed document cache vectors shared by native and wasm.
use cbcn::{Error, document::*};
use csgn::{Kind, SecretKey, Signer};
use serde::{Deserialize, Serialize};
#[derive(Deserialize, Serialize, PartialEq)]
struct Status {
    scope: String,
    revision: u64,
    epoch: u64,
    public_key: Vec<u8>,
}
impl Document for Status {
    const KIND: Kind = Kind::SettingsSnapshot;
    fn version(&self, issuer: &str) -> cbcn::Result<Version> {
        if self.scope != issuer {
            return Err(Error::Incoherent);
        }
        Ok(Version {
            revision: self.revision,
            epoch: self.epoch,
        })
    }
}
fn signer(scope: &str) -> Signer {
    Signer::new(scope, SecretKey::from_seed(&mut [13; 32]), 100, 1000).unwrap()
}
fn signed(s: &mut Signer, revision: u64, epoch: u64, issued: u64, key: u8) -> Vec<u8> {
    let status = Status {
        scope: s.key_ring().issuer().into(),
        revision,
        epoch,
        public_key: vec![key; 32],
    };
    s.sign(
        Kind::SettingsSnapshot,
        &serde_json::to_vec(&status).unwrap(),
        issued,
        900,
    )
    .unwrap()
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signed_document_cache_retains_scope_floors_and_exact_bytes() {
    let mut s = signer("global");
    let mut cache = Cache::<Status>::default();
    assert_eq!(cache.current(200), Err(Error::Unavailable));
    let bytes = signed(&mut s, 1, 1, 100, 1);
    assert_eq!(
        cache
            .install(s.key_ring(), bytes.clone(), 200)
            .unwrap()
            .as_ref(),
        bytes
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), bytes);
    let refreshed = signed(&mut s, 1, 1, 101, 1);
    cache.install(s.key_ring(), refreshed, 200).unwrap();
    for (revision, epoch, issued, key, expected) in [
        (0, 1, 101, 1, Error::Incoherent),
        (1, 0, 101, 1, Error::Incoherent),
        (1, 1, 100, 1, Error::Rollback),
        (1, 1, 101, 2, Error::Equivocation),
    ] {
        // A separately captured older envelope uses the same real signing key.
        // The live signer itself correctly refuses to move its clock backward.
        let mut historical = signer("global");
        let bytes = signed(&mut historical, revision, epoch, issued, key);
        assert_eq!(cache.install(s.key_ring(), bytes, 200), Err(expected));
    }
    let newer = signed(&mut s, 2, 2, 102, 2);
    cache.install(s.key_ring(), newer, 200).unwrap();
    for (revision, epoch) in [(1, 2), (2, 1)] {
        let bytes = signed(&mut s, revision, epoch, 102, 2);
        assert_eq!(
            cache.install(s.key_ring(), bytes, 200),
            Err(Error::Rollback)
        );
    }
    let mut other = signer("other");
    let bytes = signed(&mut other, 3, 3, 103, 3);
    assert_eq!(
        cache.install(other.key_ring(), bytes, 200),
        Err(Error::Incoherent)
    );
    assert_eq!(cache.current(199), Err(Error::ClockRegression));
    assert_eq!(cache.current(900), Err(Error::Expired));
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn signed_document_rejects_malformed_and_cross_scope_payloads() {
    let mut s = signer("global");
    let mut cache = Cache::<Status>::default();
    assert_eq!(
        cache.install(s.key_ring(), vec![0; (1 << 20) + 8193], 200),
        Err(Error::Incoherent)
    );
    assert_eq!(
        cache.install(s.key_ring(), vec![], 200),
        Err(Error::Signature)
    );
    let payload = serde_json::to_vec(&Status {
        scope: "global".into(),
        revision: 1,
        epoch: 1,
        public_key: vec![1; 32],
    })
    .unwrap();
    let credential = s.sign(Kind::Credential, &payload, 100, 900).unwrap();
    assert_eq!(
        cache.install(s.key_ring(), credential, 200),
        Err(Error::Signature)
    );
    for payload in [
        b"{}".as_slice(),
        br#"{"scope":"other","revision":1,"epoch":1,"public_key":[]}"#,
    ] {
        let bytes = s.sign(Kind::SettingsSnapshot, payload, 100, 900).unwrap();
        assert_eq!(
            cache.install(s.key_ring(), bytes, 200),
            Err(Error::Incoherent)
        );
    }
}
