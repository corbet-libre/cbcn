# Full Crow acceptance

`.crow/acceptance.yaml` adopts the reviewed fixed adapter contract. Its browser
setup placeholders intentionally refuse until the independently qualified
immutable environment is supplied. This workflow has not passed qualification.
The diagnostic `ccid` workflow remains separate and cannot qualify a merge.

One source archive enters the original ccid resolver; one fresh candidate lock
runs native, Wasm, browser, strict line/branch coverage, and dependency policy.
Reports, metadata, matched runner and WebDriver configuration stay outside the
source tree. The original first-party checker validates both metadata graphs;
the original coverage parser and all exclusions/thresholds are unchanged.
The workflow hashes both original/candidate locks and every phase's unchanged
lock. The external resolver independently verifies source/manifest integrity.

The maintained wasm-bindgen runner is downloaded at the exact resolved
wasm-bindgen version and checked against its upstream checksum before any owner
compilation. Node and Chromium execute the same original publication/document
vectors. Browser execution explicitly sets `WASM_BINDGEN_USE_BROWSER=1` and the
actual chromedriver; its WebDriver config identifies the immutable Chromium
binary. This uses the maintained runner's documented environment interface:
https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/browsers.html

Only coverage runs inside the verified nightly environment; stable Cargo and
Rust remain selected for all other phases. Resource admission and strict/admin
branch protection stay in force. Any changed resolved lock needs a new reviewed
commit and qualification of that exact commit before protected merging.
