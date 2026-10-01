# Coverage gate

CI uses cargo-llvm-cov on nightly for upstream Rust branch instrumentation.
Stable Rust remains the compiler for formatting, Clippy, native and wasm checks.
The gate requires exactly 100% covered production lines and branches, from the complete same-execution LCOV, raw JSON and annotated text inventories.
Missing files, interior line/branch records, inconsistent counters and empty
measurements fail. JSON generic instantiations remain diagnostics; the gate
measures merged source counters. There are no
production-code exclusions. Test harness and fixture files are excluded because
they are validation inputs rather than shipped behavior. A failed gate is an
open test gap, never evidence of complete coverage.

Dependencies are resolved once per CI run and the resulting Cargo.lock artifact
is reused by every job. CI refreshes within the declared ranges;
Dependabot proposes lockfile updates for review and merging after full CI.
The checked-in lock and per-run artifacts retain exact reproducible resolutions.

Committed lockfiles are verified before CI refresh. Any future line-only
exception must have a documented invariant and exact source context; an emitted
branch or executed line at that exclusion is refused. The current manifest is
empty. Nine parser checks exercise these integrity guarantees independently of
the real native/wasm domain tests.
