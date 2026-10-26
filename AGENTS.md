# cbcn — agent instructions

Work in a lane, never in ~/agents/scratch/ws. From the repo dir:
`cargo fmt --all --check`,
`cargo clippy --locked --all-targets -- -D warnings`,
`cargo test --locked`,
`cargo check --locked --target wasm32-unknown-unknown`,
`CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner cargo test
--locked --target wasm32-unknown-unknown --test publication --test document`.
First-party git deps on branch main, one locked revision per crate
(`python3 .github/check-first-party.py`). Fixtures: `python3 scripts/check-fixtures.py`.
No registry publication.

Invariants (rules: docs/CONTRACT.md):
- Failed collect/install never replaces the cache or moves the deadline
  (tests/publication.rs:402).
- Revision/epoch regression refuses as Rollback; same-revision different bytes
  as Equivocation (tests/publication.rs:484).
- Install before the authenticated collection time refuses as ClockRegression
  (tests/publication.rs:526).
- Optional balance/root_board bind the exact manifest revision; after install a
  drop, regress or equivocation refuses and the floor stays
  (tests/publication.rs:244, :698).
- Equal floors allow refresh only with identical payload + nondecreasing issuance
  (tests/document.rs:247).
- Key transitions are transported, never authenticated: strictly increasing,
  at most 256 entries and 1 MiB of proof bytes (tests/publication.rs:535).
- No re-signing: owner bytes install byte-identical (tests/publication.rs:371).

Pointers: docs/CONTRACT.md, docs/COVERAGE.md, tests/publication.rs,
tests/document.rs, scripts/check-fixtures.py.
