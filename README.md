# cbcn — Beacon

## Scope

Own signed public trust-feed aggregation, current cache and revision announcements
under Policy (`cplc`) in `cvld → cmty → cplc`. Global policy reuses Beacon by
reference. Inject signing/publication storage and time. Never query member data,
store private keys, deploy services, or depend on an FSL facade. cplc owns durable
publication counters and mutation serialization; csgn owns signature primitives.

## Reuse and candidates

Extract the existing cvld publication sequence and wire format. Use csgn for
original-envelope verification, serde for the existing JSON transport and the
standard library for the current cache. Generic HTTP middleware does not own
coherent multi-kind publication; transport stays in the door. No bespoke crypto,
network protocol or storage engine is introduced.

Stream A includes Dependabot Cargo/Actions, protected exact-head auto-merge,
one CI-resolved lock, strict line/branch gates and executed native/wasm vectors.
No npm manifest exists. No registry publication. See [contract](docs/CONTRACT.md).

`document::Cache<T>` is the shared global-publication port. csgn authenticates
the original envelope; the owner implements `Document` for its existing public
status type. Equal policy versions permit envelope refresh only with identical
payloads and nondecreasing signed issuance. Private suspension lists remain in
the global facade and never enter this cache.

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

## Common root-board public material

The optional `root_board` field carries Policy's `cplc.root-board.v1` COSE
publication. The signed manifest binds its exact `root_board_revision`; scope,
epoch, per-kind revision, expiry and continued presence follow the Balance path.
`root_board::Payload` holds routing metadata and original CPSD descriptor bytes.
`root_board::RootBoard` authenticates and retains those bytes; it does not decode
CPSD, establish a role or validate a credential. Existing CPSD consumers own
those semantic checks after obtaining a current authenticated publication.
