//! The crate's integration tests in one binary.
//!
//! Every former `tests/<name>.rs` is a module here, so a warm edit loop links one test
//! executable instead of one per file. The test names keep their module prefix
//! (`<name>::<test>`); `tests/fixtures` stays at its path (also read by
//! `scripts/check-fixtures.py` and the import script), so the modules include `../fixtures/`.
mod document;
mod publication;
