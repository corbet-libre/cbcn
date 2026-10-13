#!/usr/bin/env bash
# Original native publication-owner checks with exact, job-local candidate sources.
set -euo pipefail
: "${CI:?CI only}" "${CARGO_HOME:?}" "${CI_COMMIT_SHA:?}"
export PYTHONDONTWRITEBYTECODE=1
# Narrow this selector only; preserve the source closure's exact URL rewrites.
export GIT_ALLOW_PROTOCOL=file
mkdir -p "$CARGO_HOME/ccid-artifacts/root-board-native"
export CI_ACCEPTANCE_ARTIFACTS
CI_ACCEPTANCE_ARTIFACTS=$(mktemp -d "$CARGO_HOME/ccid-artifacts/root-board-native/$CI_COMMIT_SHA.XXXXXXXX")
export CPLC_ROOT_BOARD_VECTOR_DIR="$CI_ACCEPTANCE_ARTIFACTS/public-vectors"
printf 'Root-board native artifacts: %s\n' "$CI_ACCEPTANCE_ARTIFACTS"
result=0
timeout --signal=TERM --kill-after=15s 1800s python3 .ci/root-board-native.py || result=$?
export ROOT_BOARD_NATIVE_EXIT="$result"
python3 - <<'PY'
import hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path
report = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS'])
locks = {}
for label, root in [('cbcn', Path('.')), ('cplc', Path('.root-board-candidates/cplc')),
                    ('cchr', Path('.root-board-candidates/cchr'))]:
    lock = root / 'Cargo.lock'
    if lock.is_file():
        data = lock.read_bytes()
        (report / (label + '-final-Cargo.lock')).write_bytes(data)
        locks[label] = hashlib.sha256(data).hexdigest()
artifacts = {}
for path in sorted(report.rglob('*')):
    if path.is_file() and path != report / 'execution.json':
        if path.is_symlink():
            raise RuntimeError('linked report artifact')
        artifacts[path.relative_to(report).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
(report / 'execution.json').write_text(json.dumps({
    'selector': os.environ['CHECKS'],
    'exit_code': int(os.environ['ROOT_BOARD_NATIVE_EXIT']),
    'completed_at': datetime.now(timezone.utc).isoformat(),
    'source_commit': os.environ['CI_COMMIT_SHA'], 'source_sha256': os.environ['SOURCE_SHA256'],
    'closure_sha256': os.environ['DEPENDENCY_CLOSURE_SHA256'],
    'final_locks': locks, 'artifact_sha256': artifacts, 'product_acceptance': False}, indent=2, sort_keys=True) + '\n')
PY
exit "$result"
