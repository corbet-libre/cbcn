#!/usr/bin/env python3
"""Fixed full-gate selectors; only the verified Crow workflow may invoke them."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, *, output=None, env=None):
    subprocess.run(command, check=True, stdout=output, stderr=subprocess.STDOUT,
                   env=env)


def metadata(root, name):
    path = root / name
    with path.open('x') as stream:
        subprocess.run(['cargo', 'metadata', '--locked', '--all-features',
                        '--format-version', '1'], check=True, stdout=stream)
    run(['python3', '.github/check-first-party.py', '--metadata', str(path)])
    return path


def coverage(command):
    # The immutable setup is pinned by the workflow, not selected by an input.
    return ['bash', '-euo', 'pipefail', '-c',
            'printf "%s  %s\\n" "$CI_ACCEPTANCE_COVERAGE_SHA256" '
            '"$CI_ACCEPTANCE_COVERAGE_SETUP" | sha256sum --check --strict; '
            '. "$CI_ACCEPTANCE_COVERAGE_SETUP"; "$@"', 'coverage', *command]


def preflight(root):
    for program in ['cargo', 'rustc', 'node', 'npm', 'python3', 'jq', 'curl',
                    'tar', 'sha256sum', 'chromium', 'chromedriver']:
        require(shutil.which(program), 'missing required tool: ' + program)
    target = subprocess.check_output(['rustc', '--print', 'target-libdir',
                                      '--target', 'wasm32-unknown-unknown'], text=True).strip()
    require(list(Path(target).glob('libstd-*.rlib')), 'stable wasm stdlib missing')
    before = digest('Cargo.lock')
    with (root / 'tool-versions.txt').open('x') as output:
        for command in [['rustc', '-Vv'], ['cargo', '-V'], ['cargo', 'deny', '--version'],
                        ['node', '--version'], ['chromium', '--version'],
                        ['chromedriver', '--version'], coverage(['rustc', '-Vv']),
                        coverage(['cargo', 'llvm-cov', '--version']),
                        coverage(['bash', '-euo', 'pipefail', '-c',
                                  '"${LLVM_COV:?}" --version; '
                                  '"${LLVM_PROFDATA:?}" --version'])]:
            run(command, output=output)
    run(['python3', '.github/check-first-party.py', '--self-test'])
    run(['python3', '.github/test-check-source-coverage.py'])
    metadata(root, 'baseline-dependency-metadata.json')
    require(digest('Cargo.lock') == before, 'baseline lock changed')


def acceptance(root):
    before = digest('Cargo.lock')
    resolved = metadata(root, 'resolved-dependency-metadata.json')
    runner_root = root / 'runner'
    runner_root.mkdir()
    runner_path = runner_root / 'runner-path'
    runner_path.touch(exist_ok=False)
    env = dict(os.environ, DEPENDENCY_METADATA=str(resolved),
               RUNNER_TEMP=str(runner_root), GITHUB_PATH=str(runner_path))
    with (root / 'runner-acquisition.log').open('x') as output:
        run(['bash', 'scripts/wasm-runner.sh'], output=output, env=env)
    paths = runner_path.read_text().splitlines()
    require(len(paths) == 1 and Path(paths[0]).is_relative_to(root),
            'unexpected runner installation')
    os.environ['PATH'] = paths[0] + os.pathsep + os.environ['PATH']
    os.environ['CBCN_MATCHED_RUNNER'] = '1'
    require(digest('Cargo.lock') == before, 'runner acquisition changed lock')
    # Declare the actual installed browser binary to the maintained WebDriver.
    webdriver = root / 'webdriver.json'
    webdriver.write_text(json.dumps({'goog:chromeOptions': {
        'binary': shutil.which('chromium'), 'args': ['--disable-dev-shm-usage']}}) + '\n')
    os.environ['WASM_BINDGEN_TEST_WEBDRIVER_JSON'] = str(webdriver)
    phases = []
    path = root / 'phases.json'
    with path.open('x') as output:
        json.dump(phases, output)
    for phase in ['native', 'wasm', 'browser', 'coverage', 'dependency-policy']:
        require(digest('Cargo.lock') == before, 'lock changed before ' + phase)
        command = ['bash', '.ci/check.sh', phase]
        if phase == 'coverage':
            command = coverage(command)
        log = root / (phase + '.log')
        try:
            with log.open('x') as output:
                run(command, output=output)
        except subprocess.CalledProcessError:
            print(log.read_text(), flush=True)
            raise
        require(digest('Cargo.lock') == before, 'lock changed after ' + phase)
        phases.append({'name': phase, 'status': 'passed', 'lock_before': before,
                       'lock_after': before, 'log': phase + '.log'})
        path.write_text(json.dumps(phases, indent=2) + '\n')
        print('completed full acceptance phase:', phase, flush=True)


def main():
    require(os.environ.get('CI') == 'crow', 'Crow acceptance only')
    require(not os.environ.get('CHECKS'), 'caller-selected phases forbidden')
    require(sys.argv[1:] in [['preflight'], ['run']], 'exact selector required')
    os.environ['PYTHONDONTWRITEBYTECODE'] = '1'
    root = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    require(not root.is_relative_to(Path.cwd().resolve()), 'artifacts must be outside source')
    for kind in ['STABLE', 'BROWSER', 'COVERAGE']:
        setup = Path(os.environ['CI_ACCEPTANCE_' + kind + '_SETUP'])
        require(setup.is_absolute() and str(setup).startswith('/nix/store/'),
                'immutable setup required')
        require(digest(setup) == os.environ['CI_ACCEPTANCE_' + kind + '_SHA256'],
                'setup digest mismatch')
    (preflight if sys.argv[1] == 'preflight' else acceptance)(root)


if __name__ == '__main__':
    main()
