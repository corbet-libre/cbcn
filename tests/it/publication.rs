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
struct WithoutBalance(Source);
impl Publisher for WithoutBalance {
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
shared_test!(
    unconfigured_accounting_uses_the_existing_publication_port,
    {
        let (source, _) = source("alpha", 10, 1);
        let mut source = WithoutBalance(source);
        let mut beacon = Beacon::default();
        assert!(
            beacon
                .install(block_on(collect(&mut source, NOW)).unwrap(), NOW)
                .unwrap()
                .balance
                .is_none()
        );
    }
);
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
    async fn root_board(&mut self, _: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.feed.root_board.clone())
    }
    async fn balance(&mut self, _: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.feed.balance.clone())
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
                balance: None,
                root_board: None,
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

fn add_balance(source: &mut Source, signer: &mut Signer, revision: u64) {
    // Beacon validates authenticated routing only. This deliberately incomplete
    // header cannot be decoded as accounting material or authorize any proof.
    let material = json!({"purpose":"cblc.public-verifier.v2",
        "community":source.ring.issuer(), "revision":revision,
        "policyEpoch":source.feed.policy_epoch});
    source.feed.balance = Some(
        signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&material).unwrap(),
                NOW,
                NOW + 100,
            )
            .unwrap(),
    );
    edit(
        signer,
        &mut source.feed.manifest,
        csgn::Kind::SettingsSnapshot,
        |value| value["balance_revision"] = json!(revision),
    );
}

shared_test!(
    current_balance_capture_authenticates_the_original_owner_bytes,
    {
        let fixture: Value =
            serde_json::from_slice(include_bytes!("../fixtures/balance-publication-v2.json"))
                .unwrap();
        let ring = csgn::KeyRing::from_cbor(
            &serde_json::from_value::<Vec<u8>>(fixture["configuredFixtureRing"].clone()).unwrap(),
        )
        .unwrap();
        let original: Vec<u8> = serde_json::from_value(fixture["signed"].clone()).unwrap();
        let verified = balance::Balance::verify(&ring, &original, 1, 1, 200).unwrap();
        assert_eq!(verified.signed_bytes(), original);
        let payload: Value = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(payload, fixture["material"]);
        assert_eq!(payload["purpose"], "cblc.public-verifier.v2");
        assert_eq!(payload["admissionPolicyDigest"], json!(vec![3_u8; 32]));
        assert_eq!(verified.valid_until(), 900);
        let mut damaged = original.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            balance::Balance::verify(&ring, &damaged, 1, 1, 200),
            Err(Error::Signature)
        ));
    }
);

shared_test!(
    legacy_balance_capture_refuses_and_current_routing_binds_the_complete_manifest,
    {
        let fixture: Value =
            serde_json::from_slice(include_bytes!("../fixtures/balance-material.json")).unwrap();
        let ring = csgn::KeyRing::from_cbor(
            &serde_json::from_value::<Vec<u8>>(fixture["configuredFixtureRing"].clone()).unwrap(),
        )
        .unwrap();
        let original: Vec<u8> = serde_json::from_value(fixture["signed"].clone()).unwrap();
        assert!(matches!(
            balance::Balance::verify(&ring, &original, 1, 1, 200),
            Err(Error::Incoherent)
        ));
        assert!(matches!(
            balance::Balance::verify(&ring, &original, 1, 1, 900),
            Err(Error::Signature)
        ));

        let (mut source, mut signer) = source("alpha", 10, 1);
        add_balance(&mut source, &mut signer, 1);
        let bytes = source.feed.balance.as_ref().unwrap();
        let verified = balance::Balance::verify(&source.ring, bytes, 1, 1, NOW).unwrap();
        assert_eq!(verified.signed_bytes(), bytes);
        let header: Value = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(header["purpose"], "cblc.public-verifier.v2");
        assert_eq!(header["community"], "alpha");
        assert_eq!(verified.revision(), 1);
        assert_eq!(verified.valid_until(), NOW + 100);
        let mut beacon = Beacon::default();
        let installed = beacon
            .install(block_on(collect(&mut source, NOW)).unwrap(), NOW)
            .unwrap();
        assert_eq!(installed.balance, source.feed.balance);
        beacon
            .install(block_on(collect(&mut source, NOW)).unwrap(), NOW)
            .unwrap();
        assert_eq!(beacon.current(NOW + 100), Err(Error::Expired));
    }
);

shared_test!(
    balance_missing_mismatched_or_regressed_never_replaces_the_feed,
    {
        for case in 0..5 {
            let (mut source, mut signer) = source("alpha", 10, 1);
            add_balance(&mut source, &mut signer, 1);
            match case {
                0 => source.feed.balance = None,
                1 => edit(
                    &mut signer,
                    &mut source.feed.manifest,
                    csgn::Kind::SettingsSnapshot,
                    |v| {
                        v.as_object_mut().unwrap().remove("balance_revision");
                    },
                ),
                2 => edit(
                    &mut signer,
                    &mut source.feed.manifest,
                    csgn::Kind::SettingsSnapshot,
                    |v| v["balance_revision"] = json!(11),
                ),
                3 => edit(
                    &mut signer,
                    source.feed.balance.as_mut().unwrap(),
                    csgn::Kind::SettingsSnapshot,
                    |v| v["policyEpoch"] = json!(2),
                ),
                _ => source.feed.balance.as_mut().unwrap()[0] ^= 1,
            }
            rejected(
                &mut source,
                if case == 4 {
                    Error::Signature
                } else {
                    Error::Incoherent
                },
            );
        }
        for case in 0..3 {
            let (mut first, mut signer) = source("alpha", 10, 1);
            add_balance(&mut first, &mut signer, 2);
            let mut beacon = Beacon::default();
            let original = beacon
                .install(block_on(collect(&mut first, NOW)).unwrap(), NOW)
                .unwrap();
            let (mut next, mut signer) = source("alpha", 11, 1);
            match case {
                0 => (),
                1 => add_balance(&mut next, &mut signer, 1),
                _ => {
                    add_balance(&mut next, &mut signer, 2);
                    edit(
                        &mut signer,
                        next.feed.balance.as_mut().unwrap(),
                        csgn::Kind::SettingsSnapshot,
                        |v| v["manifestSha256"] = json!(vec![7; 32]),
                    );
                }
            }
            assert_eq!(
                beacon.install(block_on(collect(&mut next, NOW)).unwrap(), NOW),
                Err(if case == 2 {
                    Error::Equivocation
                } else {
                    Error::Rollback
                })
            );
            assert_eq!(beacon.current(NOW).unwrap(), original);
        }
    }
);

shared_test!(
    balance_routing_header_refuses_wrong_purpose_scope_bounds_and_encoding,
    {
        let (source, mut signer) = source("alpha", 10, 1);
        for case in 0..10 {
            let mut value = json!({"purpose":"cblc.public-verifier.v2", "community":"alpha", "revision":1, "policyEpoch":1});
            let mut revision = 1;
            let mut epoch = 1;
            match case {
                0 => value["purpose"] = json!("other"),
                1 => value["community"] = json!("other"),
                2 => value["revision"] = json!(2),
                3 => {
                    revision = 0;
                    value["revision"] = json!(0);
                }
                4 => {
                    revision = i64::MAX as u64 + 1;
                    value["revision"] = json!(revision);
                }
                5 => value["policyEpoch"] = json!(2),
                6 => {
                    epoch = 0;
                    value["policyEpoch"] = json!(0);
                }
                9 => value["purpose"] = json!("cblc.public-verifier.v1"),
                7 => {
                    epoch = i64::MAX as u64 + 1;
                    value["policyEpoch"] = json!(epoch);
                }
                _ => {
                    value.as_object_mut().unwrap().remove("purpose");
                }
            }
            let bytes = signer
                .sign(
                    csgn::Kind::SettingsSnapshot,
                    &serde_json::to_vec(&value).unwrap(),
                    NOW,
                    NOW + 100,
                )
                .unwrap();
            assert!(matches!(
                balance::Balance::verify(&source.ring, &bytes, epoch, revision, NOW),
                Err(Error::Incoherent)
            ));
        }
        assert!(matches!(
            balance::Balance::verify(&source.ring, &vec![0; (1 << 20) + 8193], 1, 1, NOW),
            Err(Error::Incoherent)
        ));
    }
);

shared_test!(real_door_original_bytes_survive_the_publication_port, {
    let mut beacon = Beacon::default();
    let now = 1_800_000_003;
    for bytes in [
        include_bytes!("../fixtures/initial.json").as_slice(),
        include_bytes!("../fixtures/all.json"),
        include_bytes!("../fixtures/any.json"),
        include_bytes!("../fixtures/threshold.json"),
        include_bytes!("../fixtures/schema.json"),
        include_bytes!("../fixtures/revoked.json"),
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

shared_test!(
    a_newer_feed_may_republish_the_identical_balance_bytes_at_the_same_revision,
    {
        let (mut first, mut signer) = source("alpha", 10, 1);
        add_balance(&mut first, &mut signer, 2);
        let mut beacon = Beacon::default();
        beacon
            .install(block_on(collect(&mut first, NOW)).unwrap(), NOW)
            .unwrap();
        // Same Balance revision and exact original bytes under a newer feed
        // revision: the per-kind floor is kept and nothing is an equivocation.
        let (mut next, mut signer) = source("alpha", 11, 1);
        add_balance(&mut next, &mut signer, 2);
        let installed = beacon
            .install(block_on(collect(&mut next, NOW)).unwrap(), NOW)
            .unwrap();
        assert_eq!(installed.revision, 11);
        // A strictly newer Balance revision under a newer feed is an ordinary successor.
        let (mut newest, mut signer) = source("alpha", 12, 1);
        add_balance(&mut newest, &mut signer, 3);
        let installed = beacon
            .install(block_on(collect(&mut newest, NOW)).unwrap(), NOW)
            .unwrap();
        assert_eq!(installed.revision, 12);
    }
);

fn add_root_board(source: &mut Source, signer: &mut Signer, revision: u64) {
    let descriptor: Vec<u8> = include_bytes!("../fixtures/root-board-public.bin").to_vec();
    let value = json!({"purpose":"cplc.root-board.v1","community":source.ring.issuer(),"revision":revision,"policy_epoch":source.feed.policy_epoch,"descriptor":descriptor});
    source.feed.root_board = Some(
        signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&value).unwrap(),
                NOW,
                NOW + 100,
            )
            .unwrap(),
    );
    edit(
        signer,
        &mut source.feed.manifest,
        csgn::Kind::SettingsSnapshot,
        |v| v["root_board_revision"] = json!(revision),
    );
}
shared_test!(
    root_board_is_original_owner_bytes_bound_to_the_complete_manifest,
    {
        let (mut source, mut signer) = source("alpha", 10, 1);
        add_root_board(&mut source, &mut signer, 1);
        let bytes = source.feed.root_board.clone().unwrap();
        let verified = root_board::RootBoard::verify(&source.ring, &bytes, 1, 1, NOW).unwrap();
        assert_eq!(verified.signed_bytes(), bytes);
        let signed = source
            .ring
            .verify(&bytes, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap();
        assert_eq!(verified.payload(), signed.payload());
        let payload: root_board::Payload = serde_json::from_slice(verified.payload()).unwrap();
        assert_eq!(
            payload.descriptor.as_slice(),
            include_bytes!("../fixtures/root-board-public.bin").as_slice()
        );
        assert_eq!(verified.check_successor(&verified), Ok(()));
        assert_eq!(verified.revision(), 1);
        assert_eq!(verified.valid_until(), NOW + 100);
        assert!(matches!(
            root_board::RootBoard::verify(&source.ring, &bytes, 1, 1, NOW + 100),
            Err(Error::Signature)
        ));
        let mut beacon = Beacon::default();
        let installed = beacon
            .install(block_on(collect(&mut source, NOW)).unwrap(), NOW)
            .unwrap();
        assert_eq!(installed.root_board, source.feed.root_board);
        beacon
            .install(block_on(collect(&mut source, NOW)).unwrap(), NOW)
            .unwrap();
        let (mut next, mut signer) = self::source("alpha", 11, 1);
        add_root_board(&mut next, &mut signer, 2);
        let installed = beacon
            .install(block_on(collect(&mut next, NOW)).unwrap(), NOW)
            .unwrap();
        assert_eq!(installed.revision, 11);
        assert_eq!(installed.root_board, next.feed.root_board);
        assert_eq!(beacon.current(NOW + 100), Err(Error::Expired));
    }
);
shared_test!(
    root_board_missing_mismatched_or_regressed_never_replaces_the_feed,
    {
        for case in 0..5 {
            let (mut source, mut signer) = source("alpha", 10, 1);
            add_root_board(&mut source, &mut signer, 1);
            match case {
                0 => source.feed.root_board = None,
                1 => edit(
                    &mut signer,
                    &mut source.feed.manifest,
                    csgn::Kind::SettingsSnapshot,
                    |v| {
                        v.as_object_mut().unwrap().remove("root_board_revision");
                    },
                ),
                2 => edit(
                    &mut signer,
                    &mut source.feed.manifest,
                    csgn::Kind::SettingsSnapshot,
                    |v| v["root_board_revision"] = json!(11),
                ),
                3 => edit(
                    &mut signer,
                    source.feed.root_board.as_mut().unwrap(),
                    csgn::Kind::SettingsSnapshot,
                    |v| v["policy_epoch"] = json!(2),
                ),
                _ => source.feed.root_board.as_mut().unwrap()[0] ^= 1,
            }
            rejected(
                &mut source,
                if case == 4 {
                    Error::Signature
                } else {
                    Error::Incoherent
                },
            );
        }
        for case in 0..3 {
            let (mut first, mut signer) = source("alpha", 10, 1);
            add_root_board(&mut first, &mut signer, 2);
            let mut beacon = Beacon::default();
            let original = beacon
                .install(block_on(collect(&mut first, NOW)).unwrap(), NOW)
                .unwrap();
            let (mut next, mut signer) = source("alpha", 11, 1);
            match case {
                0 => (),
                1 => add_root_board(&mut next, &mut signer, 1),
                _ => {
                    add_root_board(&mut next, &mut signer, 2);
                    edit(
                        &mut signer,
                        next.feed.root_board.as_mut().unwrap(),
                        csgn::Kind::SettingsSnapshot,
                        |v| v["descriptor"] = json!(vec![7]),
                    );
                }
            }
            assert_eq!(
                beacon.install(block_on(collect(&mut next, NOW)).unwrap(), NOW),
                Err(if case == 2 {
                    Error::Equivocation
                } else {
                    Error::Rollback
                })
            );
            assert_eq!(beacon.current(NOW).unwrap(), original);
        }
    }
);
shared_test!(
    root_board_routing_header_refuses_wrong_purpose_scope_bounds_and_encoding,
    {
        let (source, mut signer) = source("alpha", 10, 1);
        let descriptor: Vec<u8> = include_bytes!("../fixtures/root-board-public.bin").to_vec();
        for case in 0..12 {
            let mut value = json!({"purpose":"cplc.root-board.v1","community":"alpha","revision":1,"policy_epoch":1,"descriptor":descriptor});
            let (mut revision, mut epoch) = (1, 1);
            match case {
                0 => value["purpose"] = json!("other"),
                1 => value["community"] = json!("other"),
                2 => value["revision"] = json!(2),
                3 => {
                    revision = 0;
                    value["revision"] = json!(0);
                }
                4 => {
                    revision = i64::MAX as u64 + 1;
                    value["revision"] = json!(revision);
                }
                5 => value["policy_epoch"] = json!(2),
                6 => {
                    epoch = 0;
                    value["policy_epoch"] = json!(0);
                }
                7 => {
                    epoch = i64::MAX as u64 + 1;
                    value["policy_epoch"] = json!(epoch);
                }
                8 => value["descriptor"] = json!([]),
                9 => value["extra"] = json!(1),
                10 => {
                    value.as_object_mut().unwrap().remove("purpose");
                }
                _ => value["revision"] = json!("1"),
            }
            let bytes = signer
                .sign(
                    csgn::Kind::SettingsSnapshot,
                    &serde_json::to_vec(&value).unwrap(),
                    NOW,
                    NOW + 100,
                )
                .unwrap();
            assert!(matches!(
                root_board::RootBoard::verify(&source.ring, &bytes, epoch, revision, NOW),
                Err(Error::Incoherent)
            ));
        }
        let value = json!({"purpose":"cplc.root-board.v1","community":"alpha","revision":1,"policy_epoch":1,"descriptor":descriptor});
        let raw = serde_json::to_vec(&value).unwrap();
        let mut dup = raw.clone();
        dup.pop();
        dup.extend_from_slice(br#","purpose":"cplc.root-board.v1""#);
        dup.push(b'}');
        let bytes = signer
            .sign(csgn::Kind::SettingsSnapshot, &dup, NOW, NOW + 100)
            .unwrap();
        assert!(matches!(
            root_board::RootBoard::verify(&source.ring, &bytes, 1, 1, NOW),
            Err(Error::Incoherent)
        ));
        let bytes = signer
            .sign(csgn::Kind::SchemaSnapshot, &raw, NOW, NOW + 100)
            .unwrap();
        assert!(matches!(
            root_board::RootBoard::verify(&source.ring, &bytes, 1, 1, NOW),
            Err(Error::Signature)
        ));
        let mut bytes = signer
            .sign(csgn::Kind::SettingsSnapshot, &raw, NOW, NOW + 100)
            .unwrap();
        bytes[0] ^= 1;
        assert!(matches!(
            root_board::RootBoard::verify(&source.ring, &bytes, 1, 1, NOW),
            Err(Error::Signature)
        ));
        assert!(matches!(
            root_board::RootBoard::verify(&source.ring, &vec![0; (1 << 20) + 8193], 1, 1, NOW),
            Err(Error::Incoherent)
        ));
    }
);
