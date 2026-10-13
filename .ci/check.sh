#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS=2 CARGO_NET_GIT_FETCH_WITH_CLI=true
export PYTHONDONTWRITEBYTECODE=1
report_dir="${CI_ACCEPTANCE_ARTIFACTS:-${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cbcn-reports-${CI_COMMIT_SHA:-diagnostic}}"
mkdir -p "$report_dir"
rustc -Vv
sha256sum Cargo.lock
python3 .github/check-first-party.py
case "${1:?selected check required}" in
  native)
    cargo fmt --all --check
    python3 scripts/check-fixtures.py
    cargo clippy --locked --all-targets -- -D warnings
    cargo test --locked
    ;;
  wasm|browser)
    cargo check --locked --target wasm32-unknown-unknown
    if [[ -z "${CBCN_MATCHED_RUNNER:-}" ]]; then
      export DEPENDENCY_METADATA="$report_dir/dependency-metadata.json"
      cargo metadata --locked --all-features --format-version 1 > "$DEPENDENCY_METADATA"
      python3 .github/check-first-party.py --metadata "$DEPENDENCY_METADATA"
      export RUNNER_TEMP="$report_dir/runner"
      mkdir -p "$RUNNER_TEMP"
      export GITHUB_PATH="$RUNNER_TEMP/runner-path"
      : > "$GITHUB_PATH"
      bash scripts/wasm-runner.sh
      export PATH="$(cat "$GITHUB_PATH"):$PATH"
    fi
    export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner
    unset WASM_BINDGEN_USE_BROWSER WASM_BINDGEN_USE_DEDICATED_WORKER WASM_BINDGEN_USE_SHARED_WORKER WASM_BINDGEN_USE_SERVICE_WORKER WASM_BINDGEN_USE_DENO WASM_BINDGEN_USE_NODE_EXPERIMENTAL
    if [[ "$1" == browser ]]; then
      export WASM_BINDGEN_USE_BROWSER=1
      export CHROMEDRIVER="$(command -v chromedriver)"
      test -x "$CHROMEDRIVER"
      unset NO_HEADLESS
    fi
    cargo test --locked --target wasm32-unknown-unknown --test publication --test document
    ;;
  coverage)
    cargo llvm-cov --locked --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --json --output-path "$report_dir/coverage.json"
    cargo llvm-cov report --locked --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --lcov --output-path "$report_dir/coverage.lcov"
    cargo llvm-cov report --locked --branch --ignore-filename-regex '(^|/)(tests|scripts)/' --text --show-instantiations > "$report_dir/coverage.txt"
    python3 .github/test-check-source-coverage.py
    python3 .github/check-source-coverage.py "$report_dir/coverage.lcov" "$report_dir/coverage.json" "$report_dir/coverage.txt"
    ;;
  dependency-policy)
    cargo deny --locked check advisories
    python3 .github/test-check-source-coverage.py
    ;;
  resolve)
    cargo update
    cargo metadata --locked --format-version 1 > dependency-metadata.json
    python3 .github/check-first-party.py
    date -u +%FT%TZ > resolver.txt
    rustc -Vv >> resolver.txt
    sha256sum Cargo.lock >> resolver.txt
    cat resolver.txt
    : "${CARGO_TARGET_DIR:?persistent artifact root required}"
    mkdir -p "$CARGO_TARGET_DIR/ci-receipts"
    receipt=$(mktemp -d "$CARGO_TARGET_DIR/ci-receipts/${CI_COMMIT_SHA:?}.XXXXXXXX")
    cp Cargo.lock resolver.txt "$receipt/"
    sha256sum "$receipt/Cargo.lock" "$receipt/resolver.txt"
    printf 'RESOLUTION_ARTIFACTS=%s\n' "$receipt"
    ;;
  *) exit 2 ;;
esac
sha256sum Cargo.lock
