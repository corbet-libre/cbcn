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

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn rejected_higher_floors_leave_original_and_intermediate_installable() {
    let mut s = signer("global");
    let mut cache = Cache::<Status>::default();
    let original = signed(&mut s, 1, 1, 200, 1);
    assert_eq!(
        cache
            .install(s.key_ring(), original.clone(), 200)
            .unwrap()
            .as_ref(),
        original
    );
    // Higher proposed floors with regressed issuance must not replace.
    let mut historical = signer("global");
    let higher_rollback = signed(&mut historical, 5, 5, 100, 9);
    assert_eq!(
        cache.install(s.key_ring(), higher_rollback, 200),
        Err(Error::Rollback)
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), original);
    // Higher proposed floors from a distinct issuer must not replace.
    let mut other = signer("other");
    let cross_scope = signed(&mut other, 5, 5, 200, 9);
    assert_eq!(
        cache.install(other.key_ring(), cross_scope, 200),
        Err(Error::Incoherent)
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), original);
    // Same floors with a changed payload must not replace.
    let equivocation = signed(&mut historical, 1, 1, 200, 2);
    assert_eq!(
        cache.install(s.key_ring(), equivocation, 200),
        Err(Error::Equivocation)
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), original);
    // A legitimate intermediate revision is still installable after rejections.
    let intermediate = signed(&mut s, 2, 2, 201, 2);
    assert_eq!(
        cache
            .install(s.key_ring(), intermediate.clone(), 201)
            .unwrap()
            .as_ref(),
        intermediate
    );
    assert_eq!(cache.current(201).unwrap().as_ref(), intermediate);
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn expired_cache_keeps_floors_and_failed_refresh_keeps_deadline() {
    let mut s = signer("global");
    let mut cache = Cache::<Status>::default();
    let issuer: String = s.key_ring().issuer().into();
    let payload = serde_json::to_vec(&Status {
        scope: issuer.clone(),
        revision: 2,
        epoch: 2,
        public_key: vec![1; 32],
    })
    .unwrap();
    let short = s.sign(Kind::SettingsSnapshot, &payload, 100, 400).unwrap();
    cache.install(s.key_ring(), short.clone(), 200).unwrap();
    assert_eq!(cache.current(200).unwrap().as_ref(), short);
    assert_eq!(cache.current(399).unwrap().as_ref(), short);
    assert_eq!(cache.current(400), Err(Error::Expired));
    // Lower floors remain rollback even though the installed bytes are expired.
    let rollback_payload = serde_json::to_vec(&Status {
        scope: issuer.clone(),
        revision: 1,
        epoch: 1,
        public_key: vec![1; 32],
    })
    .unwrap();
    let rollback = s
        .sign(Kind::SettingsSnapshot, &rollback_payload, 300, 900)
        .unwrap();
    assert_eq!(
        cache.install(s.key_ring(), rollback, 500),
        Err(Error::Rollback)
    );
    assert_eq!(cache.current(500), Err(Error::Expired));
    // Same floors with changed payload must not extend the expired deadline.
    let equiv_payload = serde_json::to_vec(&Status {
        scope: issuer.clone(),
        revision: 2,
        epoch: 2,
        public_key: vec![2; 32],
    })
    .unwrap();
    let equiv = s
        .sign(Kind::SettingsSnapshot, &equiv_payload, 300, 900)
        .unwrap();
    assert_eq!(
        cache.install(s.key_ring(), equiv, 500),
        Err(Error::Equivocation)
    );
    assert_eq!(cache.current(500), Err(Error::Expired));
    // Only a successful install moves the deadline forward.
    let next_payload = serde_json::to_vec(&Status {
        scope: issuer,
        revision: 3,
        epoch: 3,
        public_key: vec![3; 32],
    })
    .unwrap();
    let next = s
        .sign(Kind::SettingsSnapshot, &next_payload, 500, 900)
        .unwrap();
    assert_eq!(
        cache
            .install(s.key_ring(), next.clone(), 500)
            .unwrap()
            .as_ref(),
        next
    );
    assert_eq!(cache.current(500).unwrap().as_ref(), next);
    assert_eq!(cache.current(899).unwrap().as_ref(), next);
    assert_eq!(cache.current(900), Err(Error::Expired));
}
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn same_revision_epoch_bump_is_forward_progress_with_issuance_floor() {
    let mut s = signer("global");
    let mut cache = Cache::<Status>::default();
    let v11 = signed(&mut s, 1, 1, 100, 1);
    cache.install(s.key_ring(), v11, 200).unwrap();
    // Same revision with a higher epoch does not regress, so it installs even
    // though the typed payload changes; only equal floors require payload equality.
    let v12 = signed(&mut s, 1, 2, 101, 2);
    assert_eq!(
        cache
            .install(s.key_ring(), v12.clone(), 200)
            .unwrap()
            .as_ref(),
        v12
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), v12);
    // Regressed epoch at the same revision must not replace.
    let regressed = signed(&mut s, 1, 1, 102, 1);
    assert_eq!(
        cache.install(s.key_ring(), regressed, 200),
        Err(Error::Rollback)
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), v12);
    // Equal floors with a changed payload must not replace.
    let mut historical = signer("global");
    let equiv = signed(&mut historical, 1, 2, 102, 9);
    assert_eq!(
        cache.install(s.key_ring(), equiv, 200),
        Err(Error::Equivocation)
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), v12);
    // Equal floors and equal payload with regressed issuance must not replace.
    // A second fresh signer is required: historical already advanced to 102.
    let mut stale_signer = signer("global");
    let stale = signed(&mut stale_signer, 1, 2, 100, 2);
    assert_eq!(
        cache.install(s.key_ring(), stale, 200),
        Err(Error::Rollback)
    );
    assert_eq!(cache.current(200).unwrap().as_ref(), v12);
}
