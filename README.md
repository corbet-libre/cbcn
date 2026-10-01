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
