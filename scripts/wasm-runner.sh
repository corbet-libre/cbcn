#!/usr/bin/env bash
set -euo pipefail
version=$(jq -er '[.packages[] | select(.name == "wasm-bindgen") | .version] | unique | if length == 1 then .[0] else error("one matching wasm-bindgen required") end' "${DEPENDENCY_METADATA:-dependency-metadata.json}")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="${WASM_BINDGEN_DOWNLOAD_BASE:-https://github.com/wasm-bindgen/wasm-bindgen/releases/download}/${version}"
mkdir -p "$RUNNER_TEMP/beacon-wasm-runner"
cd "$RUNNER_TEMP/beacon-wasm-runner"
curl -A 'ci-dependency-fetch/1.0' --fail --location --retry 3 --remote-name "$base/$archive"
curl -A 'ci-dependency-fetch/1.0' --fail --location --retry 3 --remote-name "$base/$archive.sha256sum"
checksum=$(cut -d ' ' -f1 "$archive.sha256sum")
[[ "$checksum" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check --strict
tar -xzf "$archive" --strip-components=1
test "$(./wasm-bindgen --version)" = "wasm-bindgen $version"
printf '%s  %s\n' "$checksum" "$archive" > runner-artifact.sha256
./wasm-bindgen-test-runner --version > runner-version.txt
echo "$PWD" >> "$GITHUB_PATH"
