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
rollback and conflicting bytes at equal revisions refuse. A candidate cannot be
installed before its authenticated collection time. Announcement consumers
must fetch and authenticate the whole feed; hints are not authority.

No clocks, sockets, SQL, private keys or FSL dependency are owned here. The door
owns HTTP waiting and cancellation. cplc serializes publication under its existing
policy lock and persists counters before returning signed bytes. Independent
native/wasm signatures and original door fixtures are required before acceptance.

## Original optional owner publications

The Publisher may supply the original canonical Balance document and common
root-board descriptor. Absent owner configuration leaves both fields omitted
from the existing feed. Supplied documents must match their signed manifest
revisions, community and policy epoch, and their original signature lifetimes
bound the complete publication. Once installed, each optional document retains
its revision floor even after expiry: omission or an older revision refuses, and
different signed bytes at an equal revision refuse as equivocation.

Beacon authenticates routing metadata and preserves the original bytes. Balance
owns economic policy and proof-artifact validation; CPSD owns descriptor decoding,
scope, epoch and credential semantics. These authenticated transport views are
neither current member records nor decoded credential capabilities.

## Global reuse

`document::Cache<T>` retains one original signed public document, authenticating
it with the configured owner's ring. The owning type implements `Document` to
fix the expected protected kind, validate its existing payload purpose/scope and
extract signed policy floors.
Policy revision, epoch and signed issuance cannot regress. Equal policy floors
allow a freshly signed lifetime only if the typed payload is unchanged. Distinct
issuer scopes cannot share a cache. No generic community manifest is fabricated
for global status and no private global revocation data becomes public.

## Public key continuity transport

The publication owner supplies `key_transitions`: original signed csgn proofs
with separate public ring-change revisions. Beacon transports them unchanged.
`validate_transition_history` checks only a strictly increasing positive sequence,
nonempty proofs, at most 256 changes and at most 1 MiB of proof bytes. It does not
verify signatures or grant publishing authority. Charter authenticates every new
transition against its configured or installed predecessor. cplc must durably
retain each pending csgn proof before acknowledging it; ordinary issuance never
increments this public ring sequence. History exhaustion refuses rotation instead
of silently dropping continuity. Initial feeds omit the empty optional field and
remain byte-compatible with the existing door protocol.

## Balance public material

The separate `balance` feed field carries the original canonical
`cblc.public-verifier.v1` COSE document. `Publisher::balance` returns absence
only for a community without configured accounting. The signed manifest names
its exact `balance_revision`; stripping either half or mixing scope/epoch fails.
Beacon authenticates publication metadata, retains its independent monotonic
floor and includes its expiry in the complete feed deadline. After installation
a later feed cannot drop it. Economic policy and proof-artifact validation stay
with the canonical accounting owner; no economic schema is copied here.
`balance::Balance` retains signed bytes and original authenticated JSON, never
a member verdict. Its presence gives no current-record or settlement authority.
