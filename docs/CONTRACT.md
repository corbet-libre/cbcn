# Beacon publication contract

Beacon aggregates the existing settings, schema, communities, revocations and
schema-history signatures, then the trust manifest. The injected Publisher owns
signing and durable per-kind revisions. A failed sequence does not expose partial
bytes or replace the previous cache; durable counters need not roll back.

The original signatures remain unchanged. The supplied signing key ring must
come from the configured publication owner. Beacon verifies protected kinds,
issuer, lifetime, community, epoch and positive publication revisions against the
manifest before constructing a cache candidate. It does not re-sign documents.
The public feed is a current view, never an activity log. Expiry, clock regression,
rollback and conflicting bytes at equal revisions refuse. Announcement consumers
must fetch and authenticate the whole feed; hints are not authority.

No clocks, sockets, SQL, private keys or FSL dependency are owned here. The door
owns HTTP waiting and cancellation. cplc serializes publication under its existing
policy lock and persists counters before returning signed bytes. Independent
native/wasm signatures and original door fixtures are required before acceptance.
