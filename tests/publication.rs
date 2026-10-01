use cbcn::*;
use csgn::{SecretKey, Signer};
use futures::executor::block_on;
use serde_json::{Value, json};

macro_rules! shared_test {
    ($name:ident, $body:block) => {
        #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(target_arch = "wasm32"), test)]
        fn $name() $body
    };
}
const NOW: u64 = 1000;
struct Source {
    ring: csgn::KeyRing,
    feed: Feed,
    fail: Option<Kind>,
}
impl Publisher for Source {
    fn key_ring(&self) -> Result<csgn::KeyRing> {
        Ok(self.ring.clone())
    }
    fn key_transitions(&self) -> Result<Vec<KeyTransition>> {
        Ok(self.feed.key_transitions.clone())
    }
    async fn publish(&mut self, kind: Kind, _: u64) -> Result<Vec<u8>> {
        if self.fail == Some(kind) {
            return Err(Error::Publication);
        }
        Ok(match kind {
            Kind::Settings => self.feed.settings.clone(),
            Kind::Schema => self.feed.schema.clone(),
            Kind::Communities => self.feed.communities.clone(),
            Kind::Revocations => self.feed.revocations.clone(),
            Kind::SchemaVersions => self.feed.schema_versions.clone(),
        })
    }
    async fn manifest(&mut self, _: u64) -> Result<Vec<u8>> {
        Ok(self.feed.manifest.clone())
    }
}
fn source(community: &str, revision: u64, epoch: u64) -> (Source, Signer) {
    let mut signer = Signer::new(
        community,
        SecretKey::from_seed(&mut [72; 32]),
        NOW - 1,
        1000,
    )
    .unwrap();
    let mut signed = |kind, value: Value| {
        signer
            .sign(kind, &serde_json::to_vec(&value).unwrap(), NOW, NOW + 500)
            .unwrap()
    };
    let snapshot = |content: Value| json!({"community":community,"revision":revision,"policy_epoch":epoch,"content":content});
    let settings = signed(csgn::Kind::SettingsSnapshot, snapshot(json!({})));
    let schema = signed(
        csgn::Kind::SchemaSnapshot,
        snapshot(json!({"community":community,"version":1,"public":[],"private":[]})),
    );
    let communities = signed(
        csgn::Kind::CommunitiesSnapshot,
        snapshot(json!([community])),
    );
    let revocations = signed(
        csgn::Kind::RevocationListSnapshot,
        snapshot(json!({"members":[],"devices":[]})),
    );
    let schema_versions = signed(
        csgn::Kind::SchemaSnapshot,
        snapshot(json!({"purpose":"cplc.schema-versions.v1","current":1,"versions":[]})),
    );
    let ring = signer.key_ring().clone();
    let manifest=signer.sign(csgn::Kind::SettingsSnapshot,&serde_json::to_vec(&json!({"purpose":"cplc.trust.v1","community":community,"revision":revision,"policy_epoch":epoch,"schema_version":1,"key_ring":ring.to_cbor()})).unwrap(),NOW,NOW+500).unwrap();
    (
        Source {
            ring,
            feed: Feed {
                revision,
                policy_epoch: epoch,
                key_ring: signer.key_ring().to_cbor(),
                key_transitions: vec![],
                manifest,
                settings,
                schema,
                communities,
                revocations,
                schema_versions,
            },
            fail: None,
        },
        signer,
    )
}
fn edit(
    signer: &mut Signer,
    bytes: &mut Vec<u8>,
    kind: csgn::Kind,
    change: impl FnOnce(&mut Value),
) {
    let mut value: Value = serde_json::from_slice(
        signer
            .key_ring()
            .verify(bytes, kind, NOW)
            .unwrap()
            .payload(),
    )
    .unwrap();
    change(&mut value);
    *bytes = signer
        .sign(kind, &serde_json::to_vec(&value).unwrap(), NOW, NOW + 500)
        .unwrap();
}
fn rejected(source: &mut Source, error: Error) {
    assert!(matches!(block_on(collect(source,NOW)),Err(e) if e==error));
}

shared_test!(real_door_original_bytes_survive_the_publication_port, {
    let mut beacon = Beacon::default();
    let now = 1_800_000_003;
    for bytes in [
        include_bytes!("fixtures/initial.json").as_slice(),
        include_bytes!("fixtures/all.json"),
        include_bytes!("fixtures/any.json"),
        include_bytes!("fixtures/threshold.json"),
        include_bytes!("fixtures/schema.json"),
        include_bytes!("fixtures/revoked.json"),
    ] {
        let feed: Feed = serde_json::from_slice(bytes).unwrap();
        let mut source = Source {
            ring: csgn::KeyRing::from_cbor(&feed.key_ring).unwrap(),
            feed: feed.clone(),
            fail: None,
        };
        let installed = beacon
            .install(block_on(collect(&mut source, now)).unwrap(), now)
            .unwrap();
        assert_eq!(*installed, feed);
        assert_eq!(beacon.current(now).unwrap(), installed);
        assert!(!beacon.changes_since(feed.revision, now).unwrap().changed);
        assert!(beacon.changes_since(0, now).unwrap().changed);
        assert_eq!(
            beacon.changes_since(feed.revision + 1, now),
            Err(Error::Rollback)
        );
    }
});

shared_test!(publication_failure_preserves_current_deadline_and_scope, {
    let (mut source, _) = source("alpha", 10, 1);
    let mut beacon = Beacon::default();
    assert_eq!(beacon.current(NOW), Err(Error::Unavailable));
    let installed = beacon
        .install(block_on(collect(&mut source, NOW)).unwrap(), NOW)
        .unwrap();
    let replay = beacon
        .install(block_on(collect(&mut source, NOW)).unwrap(), NOW)
        .unwrap();
    assert_eq!(installed, replay);
    source.fail = Some(Kind::Revocations);
    rejected(&mut source, Error::Publication);
    assert_eq!(beacon.current(NOW).unwrap(), installed);
    let (mut other, _) = self::source("beta", 11, 2);
    assert!(matches!(
        beacon.install(block_on(collect(&mut other, NOW)).unwrap(), NOW),
        Err(Error::Incoherent)
    ));
    assert_eq!(beacon.current(NOW - 1), Err(Error::ClockRegression));
    assert_eq!(beacon.current(NOW + 500), Err(Error::Expired));
    let (mut source, _) = self::source("alpha", 11, 2);
    assert_eq!(
        beacon.install(block_on(collect(&mut source, NOW)).unwrap(), NOW + 500),
        Err(Error::Expired)
    );
    assert_eq!(Error::Publication.to_string(), "Publication");
});

shared_test!(signed_manifest_and_snapshot_bindings_are_required, {
    for (field, value) in [
        ("purpose", json!("other")),
        ("community", json!("beta")),
        ("key_ring", json!([])),
        ("revision", json!(0)),
        ("revision", json!(u64::MAX)),
        ("policy_epoch", json!(0)),
        ("policy_epoch", json!(u64::MAX)),
        ("schema_version", json!(0)),
    ] {
        let (mut source, mut signer) = source("alpha", 10, 1);
        edit(
            &mut signer,
            &mut source.feed.manifest,
            csgn::Kind::SettingsSnapshot,
            |v| v[field] = value,
        );
        rejected(&mut source, Error::Incoherent);
    }
    for (field, value) in [
        ("community", json!("beta")),
        ("policy_epoch", json!(2)),
        ("revision", json!(0)),
        ("revision", json!(11)),
    ] {
        let (mut source, mut signer) = source("alpha", 10, 1);
        edit(
            &mut signer,
            &mut source.feed.settings,
            csgn::Kind::SettingsSnapshot,
            |v| v[field] = value,
        );
        rejected(&mut source, Error::Incoherent);
    }
    let (mut source, mut signer) = source("alpha", 10, 1);
    edit(
        &mut signer,
        &mut source.feed.schema,
        csgn::Kind::SchemaSnapshot,
        |v| v["content"]["version"] = json!(2),
    );
    rejected(&mut source, Error::Incoherent);
    source.feed.schema = vec![];
    rejected(&mut source, Error::Signature);
    source.feed.schema = vec![0; (1 << 20) + 8193];
    rejected(&mut source, Error::Incoherent);
    source.feed.schema = signer
        .sign(csgn::Kind::SchemaSnapshot, b"{}", NOW, NOW + 500)
        .unwrap();
    rejected(&mut source, Error::Incoherent);
});

shared_test!(cache_refuses_signed_rollback_and_equivocation, {
    let (mut first, _) = source("alpha", 10, 2);
    let mut beacon = Beacon::default();
    beacon
        .install(block_on(collect(&mut first, NOW)).unwrap(), NOW)
        .unwrap();
    for (revision, epoch) in [(9, 2), (11, 1)] {
        let (mut candidate, _) = source("alpha", revision, epoch);
        assert_eq!(
            beacon.install(block_on(collect(&mut candidate, NOW)).unwrap(), NOW),
            Err(Error::Rollback)
        );
    }
    for revision in [10, 11] {
        let (mut candidate, mut signer) = source("alpha", revision, 2);
        edit(
            &mut signer,
            &mut candidate.feed.settings,
            csgn::Kind::SettingsSnapshot,
            |v| {
                v["revision"] = json!(10);
                v["content"] = json!({"changed":true});
            },
        );
        assert_eq!(
            beacon.install(block_on(collect(&mut candidate, NOW)).unwrap(), NOW),
            Err(Error::Equivocation)
        );
    }
    let (mut candidate, mut signer) = source("alpha", 11, 2);
    edit(
        &mut signer,
        &mut candidate.feed.settings,
        csgn::Kind::SettingsSnapshot,
        |v| v["revision"] = json!(9),
    );
    assert_eq!(
        beacon.install(block_on(collect(&mut candidate, NOW)).unwrap(), NOW),
        Err(Error::Rollback)
    );
});

shared_test!(candidate_cannot_be_installed_before_it_was_authenticated, {
    let (mut source, _) = source("alpha", 10, 1);
    let candidate = block_on(collect(&mut source, NOW)).unwrap();
    assert_eq!(
        Beacon::default().install(candidate, NOW - 1),
        Err(Error::ClockRegression)
    );
});

shared_test!(transition_transport_bounds_never_assert_authentication, {
    let valid = KeyTransition {
        revision: 1,
        proof: vec![1],
    };
    validate_transition_history(&[]).unwrap();
    validate_transition_history(std::slice::from_ref(&valid)).unwrap();
    for bad in [
        vec![valid.clone(); MAX_KEY_TRANSITIONS + 1],
        vec![KeyTransition {
            revision: 0,
            proof: vec![1],
        }],
        vec![KeyTransition {
            revision: 1,
            proof: vec![],
        }],
        vec![valid.clone(), valid.clone()],
        vec![KeyTransition {
            revision: 1,
            proof: vec![1; MAX_KEY_TRANSITION_BYTES + 1],
        }],
        vec![
            KeyTransition {
                revision: 1,
                proof: vec![1; MAX_KEY_TRANSITION_BYTES],
            },
            KeyTransition {
                revision: 2,
                proof: vec![1],
            },
        ],
    ] {
        assert_eq!(validate_transition_history(&bad), Err(Error::Incoherent));
    }
    // Shape-valid bytes are deliberately not described as verified signatures.
    let (mut source, _) = source("alpha", 10, 1);
    source.feed.key_transitions = vec![valid];
    let candidate = block_on(collect(&mut source, NOW)).unwrap();
    let feed = Beacon::default().install(candidate, NOW).unwrap();
    assert_eq!(feed.key_transitions, source.feed.key_transitions);
    let encoded = serde_json::to_vec(&*feed).unwrap();
    assert_eq!(serde_json::from_slice::<Feed>(&encoded).unwrap(), *feed);
});

shared_test!(legacy_publishers_keep_the_original_empty_history_wire, {
    struct Legacy(Source);
    impl Publisher for Legacy {
        fn key_ring(&self) -> Result<csgn::KeyRing> {
            self.0.key_ring()
        }
        async fn publish(&mut self, kind: Kind, now: u64) -> Result<Vec<u8>> {
            self.0.publish(kind, now).await
        }
        async fn manifest(&mut self, now: u64) -> Result<Vec<u8>> {
            self.0.manifest(now).await
        }
    }
    let (source, _) = source("alpha", 10, 1);
    let original = serde_json::to_vec(&source.feed).unwrap();
    let candidate = block_on(collect(&mut Legacy(source), NOW)).unwrap();
    let feed = Beacon::default().install(candidate, NOW).unwrap();
    assert!(feed.key_transitions.is_empty());
    assert_eq!(serde_json::to_vec(&*feed).unwrap(), original);
    assert!(
        !serde_json::to_value(&*feed)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("key_transitions")
    );
});
