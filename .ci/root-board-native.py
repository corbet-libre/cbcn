"""Run original publication-owner native checks over explicit candidate sources."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path.cwd().resolve()
REPORT = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
SELECTOR = 'root-board-native'
OWNERS = ['cplc', 'cbcn', 'cchr']
FIRST_PARTY = re.compile(r'git\+https://github\.com/(corbet-foss|corbet-libs|corbet-labs|cmtymeet)/([^?#]+)\?branch=main#([0-9a-f]{40})')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(name, value):
    (REPORT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def inventory(root, exclusions=()):
    result = {}
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if any(relative == Path(skip) or Path(skip) in relative.parents for skip in exclusions):
            continue
        require(not path.is_symlink(), 'linked source input')
        if path.is_file():
            result[relative.as_posix()] = sha(path)
        else:
            require(path.is_dir(), 'nonregular source input')
    return result


class Qualification:
    def __init__(self):
        self.contract = json.loads((ROOT / '.ci/root-board-sources.json').read_text())
        self.closure = json.loads(Path(os.environ['DEPENDENCY_CLOSURE_MANIFEST']).read_text())
        self.sources = {'cbcn': ROOT}
        self.frozen_sources = {}
        self.locks = {}
        self.graphs = {}
        self.metadata = {}
        self.git_environment = {key: value for key, value in os.environ.items()
                                if key.startswith('GIT_CONFIG_') or key in {
                                    'GIT_ALLOW_PROTOCOL', 'CARGO_NET_GIT_FETCH_WITH_CLI'}}

    def run(self, label, argv, name):
        print(json.dumps({'owner': label, 'command': argv, 'log': name}), flush=True)
        with (REPORT / name).open('w') as output, (REPORT / (name + '.stderr')).open('w') as errors:
            subprocess.run(argv, cwd=self.sources[label], stdout=output, stderr=errors, check=True)

    def patch_bytes(self, label):
        result = []
        for name in self.contract['patches'][label]:
            url = 'https://github.com/corbet-foss/cbcn' if name == 'cbcn' else self.contract['candidates'][name]['repository']
            result.append(f'[patch.{json.dumps(url)}]\n{name} = {{ path = {json.dumps(str(self.sources[name]))} }}\n')
        return '\n'.join(result).encode()

    def excluded(self, name):
        if name == 'cbcn':
            return ['.git', '.root-board-candidates', '.cargo', 'Cargo.lock']
        return ['.cargo', 'Cargo.lock'] if name in OWNERS else []

    def prepare(self):
        require(self.closure['freshness'] == 'main-observed', 'observed main closure required')
        require(os.environ.get('CARGO_NET_GIT_FETCH_WITH_CLI') == 'true'
                and int(os.environ.get('GIT_CONFIG_COUNT', '0')) > 0
                and os.environ.get('GIT_ALLOW_PROTOCOL') == 'file',
                'original source-closure transport required')
        require(self.contract['patches'] == {'cbcn': [], 'cchr': ['cbcn', 'cgrd', 'ckyh'],
                'cplc': ['cbcn', 'cchr', 'cgrd', 'ckyh', 'cpsd', 'cblc', 'cwlt', 'czkp', 'ckmg']},
                'unexpected workspace patch contract')
        require(self.contract['resolution_only'] == {'cbcn': [], 'cchr': [], 'cplc': ['ckmg']},
                'unexpected resolution-only contract')
        require(set(self.contract['candidates']) == {'cplc', 'cchr', 'cgrd', 'ckyh', 'cpsd',
                'cblc', 'cwlt', 'czkp', 'ckmg'},
                'unexpected source owners')
        require(not (ROOT / '.root-board-candidates').exists(), 'candidate directory must start fresh')
        write('observed-main-closure.json', self.closure)
        records = {}
        for name, expected in self.contract['candidates'].items():
            prefix = 'ROOT_BOARD_' + name.upper() + '_SOURCE_'
            archive = Path(os.environ[prefix + 'ARCHIVE'])
            require(os.environ[prefix + 'SHA256'] == expected['archive_sha256']
                    and archive.stat().st_size == expected['archive_bytes']
                    and archive.stat().st_size <= 32 * 1024 * 1024
                    and sha(archive) == expected['archive_sha256'], 'candidate archive identity differs')
            matches = [entry for entry in self.closure['consumers']
                       if entry['url'].removesuffix('.git') == expected['repository']]
            require(len(matches) == 1 and all(matches[0][key] == expected[value]
                    for key, value in [('commit', 'commit'), ('tree', 'tree'),
                                       ('source_sha256', 'archive_sha256')]),
                    'candidate is not producer-validated consumer')
            target = ROOT / '.root-board-candidates' / name
            with archive.open('rb') as stream:
                commit = subprocess.check_output(['git', 'get-tar-commit-id'], stdin=stream, text=True).strip()
                require(commit == expected['commit'], 'candidate Git commit differs')
                stream.seek(0)
                with tarfile.open(fileobj=stream, mode='r:') as package:
                    members = package.getmembers()
                    require(len(members) <= 10000 and sum(m.size for m in members) <= 32 * 1024 * 1024,
                            'candidate member bound exceeded')
                    seen = set()
                    for member in members:
                        path = PurePosixPath(member.name)
                        require(not path.is_absolute() and '..' not in path.parts and path.parts
                                and path.as_posix() == member.name.rstrip('/') and '.git' not in path.parts
                                and 'node_modules' not in path.parts and (member.isfile() or member.isdir())
                                and path.as_posix() not in seen, 'unsafe candidate member')
                        seen.add(path.as_posix())
                    target.mkdir(parents=True)
                    package.extractall(target, members=members, filter='data')
            manifest = tomllib.loads((target / 'Cargo.toml').read_text())['package']
            require(manifest['name'] == name and manifest['version'] == expected['version']
                    and manifest['repository'].removesuffix('.git') == expected['repository'],
                    'candidate package owner differs')
            self.sources[name] = target
            records[name] = dict(expected, path=str(target), identity='exact candidate, not observed main')
        write('candidate-sources.json', records)
        for name, path in self.sources.items():
            if name in OWNERS:
                require(not (path / '.cargo').exists(), 'workspace Cargo configuration must start fresh')
                (path / '.cargo').mkdir()
                patch = self.patch_bytes(name)
                (path / '.cargo/config.toml').write_bytes(patch)
                (REPORT / f'{name}-patches.toml').write_bytes(patch)
                shutil.copyfile(path / 'Cargo.lock', REPORT / f'{name}-before-Cargo.lock')
            self.frozen_sources[name] = inventory(path, self.excluded(name))
        write('source-files.json', self.frozen_sources)
        write('git-transport-environment.json', self.git_environment)
        self.unchanged()

    def unchanged(self):
        current_environment = {key: value for key, value in os.environ.items()
                               if key.startswith('GIT_CONFIG_') or key in {
                                   'GIT_ALLOW_PROTOCOL', 'CARGO_NET_GIT_FETCH_WITH_CLI'}}
        require(current_environment == self.git_environment, 'source transport environment changed')
        for label, digest in self.metadata.items():
            require(sha(REPORT / f'{label}-metadata.json') == digest, 'frozen metadata changed')
        for name, path in self.sources.items():
            require(path.resolve(strict=True) == path
                    and inventory(path, self.excluded(name)) == self.frozen_sources[name],
                    'original source input changed')
            if name in OWNERS:
                config = path / '.cargo/config.toml'
                require(not config.is_symlink() and not config.parent.is_symlink()
                        and list(config.parent.iterdir()) == [config]
                        and config.read_bytes() == self.patch_bytes(name)
                        and (REPORT / f'{name}-patches.toml').read_bytes() == self.patch_bytes(name),
                        'workspace patches changed')
            if name in self.locks:
                require(sha(path / 'Cargo.lock') == self.locks[name]
                        and sha(REPORT / f'{name}-Cargo.lock') == self.locks[name], 'frozen lock changed')

    def verify_graph(self, label):
        graph = json.loads((REPORT / f'{label}-metadata.json').read_text())
        lock = tomllib.loads((self.sources[label] / 'Cargo.lock').read_text())
        require(not lock.get('patch', {}).get('unused'), 'unused candidate patch')
        expected_local = {label, *self.contract['patches'][label]}
        resolution_only = set(self.contract['resolution_only'][label])
        selected_local = expected_local - resolution_only
        roots = [p for p in graph['packages'] if Path(p['manifest_path']).resolve()
                 == self.sources[label] / 'Cargo.toml']
        require(len(roots) == 1 and roots[0]['name'] == label
                and graph['resolve']['root'] == roots[0]['id']
                and graph['workspace_default_members'] == [roots[0]['id']], 'unexpected workspace root')
        observed = {entry['url']: entry['main'] for entry in self.closure['repositories']}
        require(len(observed) == len(self.closure['repositories']), 'duplicate observed main owner')
        names = expected_local | {p['name'] for p in graph['packages'] + lock['package']
                                  if FIRST_PARTY.fullmatch(p.get('source') or '')}
        identities = {}
        for kind, packages in [('metadata', graph['packages']), ('lock', lock['package'])]:
            for name in names:
                matches = [p for p in packages if p['name'] == name]
                if kind == 'metadata' and not matches:
                    # Cargo freezes inactive optional dependencies in Cargo.lock.
                    # Every lock entry is still checked below against its exact
                    # archive or observed main; no selected candidate may vanish.
                    require(name not in selected_local, 'selected candidate absent from metadata')
                    continue
                require(len(matches) == 1, 'missing or duplicate first-party package')
                package = matches[0]
                if name in expected_local:
                    manifest = tomllib.loads((self.sources[name] / 'Cargo.toml').read_text())['package']
                    require(package.get('source') is None and package['version'] == manifest['version'],
                            'local candidate package differs')
                    if kind == 'metadata':
                        require(Path(package['manifest_path']).resolve() == self.sources[name] / 'Cargo.toml',
                                'candidate manifest path differs')
                    identity = {'version': package['version'], 'manifest_path': str(self.sources[name] / 'Cargo.toml')}
                else:
                    source = package.get('source') or ''
                    match = FIRST_PARTY.fullmatch(source)
                    require(match is not None, 'noncanonical first-party source')
                    org, repository, commit = match.groups()
                    url = f'https://github.com/{org}/{repository.removesuffix(".git")}'
                    require(observed.get(url) == commit, 'dependency does not match observed main')
                    identity = {'version': package['version'], 'source': source}
                require(name not in identities or identities[name] == identity, 'lock and metadata disagree')
                identities[name] = identity
            for package in packages:
                source = package.get('source')
                require(source is not None or package['name'] in expected_local, 'unlisted local package')
                require(not (source or '').startswith('git+') or FIRST_PARTY.fullmatch(source),
                        'unbound Git dependency')
        nodes = {node['id']: node for node in graph['resolve']['nodes']}
        packages_by_id = {package['id']: package for package in graph['packages']}
        require(len(nodes) == len(graph['resolve']['nodes'])
                and len(packages_by_id) == len(graph['packages']), 'duplicate graph identity')
        reached, pending = set(), [graph['resolve']['root']]
        while pending:
            node = pending.pop()
            if node in reached:
                continue
            package = packages_by_id[node]
            require(package['name'] not in resolution_only, 'resolution-only candidate selected')
            require(package['name'] != 'cwlt' or not {'passport', 'native-verifier'}
                    .intersection(nodes[node]['features']), 'unassigned Wallet feature selected')
            reached.add(node)
            pending.extend(dep['pkg'] for dep in nodes[node]['deps'])
        require(selected_local <= {p['name'] for p in graph['packages'] if p['id'] in reached},
                'candidate absent from selected graph')
        self.graphs[label] = identities
        write(f'{label}-graph-identities.json', {'identities': identities, 'reachable_package_ids': sorted(reached),
              'resolution_only': {name: {'selected': False, 'qualified': False} for name in resolution_only},
              'lock_only_first_party': sorted(names - {package['name'] for package in graph['packages']}),
              'lock_sha256': self.locks[label], 'patch_sha256': sha(REPORT / f'{label}-patches.toml'),
              'metadata_sha256': self.metadata[label]})

    def execute(self):
        for label in OWNERS:
            self.unchanged()
            self.run(label, ['cargo', 'update'], f'{label}-resolve.log')
            path = self.sources[label] / 'Cargo.lock'
            shutil.copyfile(path, REPORT / f'{label}-Cargo.lock')
            self.locks[label] = sha(path)
            write(f'{label}-resolution.json', {'resolved_at': datetime.now(timezone.utc).isoformat(),
                  'lock_sha256': self.locks[label], 'patch_sha256': sha(REPORT / f'{label}-patches.toml')})
            self.unchanged()
            self.run(label, ['cargo', 'metadata', '--locked', '--format-version', '1'], f'{label}-metadata.json')
            self.metadata[label] = sha(REPORT / f'{label}-metadata.json')
            self.verify_graph(label)
            self.unchanged()
        common = {}
        for label, graph in self.graphs.items():
            for name, identity in graph.items():
                require(name not in common or common[name] == identity, 'owner graphs disagree on source identity')
                common[name] = identity
        write('common-first-party-identities.json', common)
        for label in OWNERS:
            self.unchanged()
            commands = [['bash', '.ci/check.sh', 'native']] if label == 'cbcn' else [
                ['cargo', 'fmt', '--all', '--check'],
                ['python3', '.github/check-first-party.py'],
                ['cargo', 'clippy', '--locked', '--all-targets', '--', '-D', 'warnings'],
                ['cargo', 'test', '--locked', '--no-fail-fast'] if label == 'cplc' else ['cargo', 'test', '--locked']]
            for index, command in enumerate(commands):
                self.run(label, command, f'{label}-check-{index}.log')
                self.unchanged()
        vectors = REPORT / 'public-vectors'
        require(set(inventory(vectors)) == {'root-board-public.bin', 'root-board-feed.json', 'root-board-anchor.json'},
                'actual Policy public vectors missing')
        write('public-vector-files.json', inventory(vectors))
        write('native-result.json', {'selector': SELECTOR, 'source_commit': os.environ['CI_COMMIT_SHA'],
              'source_sha256': os.environ['SOURCE_SHA256'], 'closure_sha256': os.environ['DEPENDENCY_CLOSURE_SHA256'],
              'locks': self.locks, 'checks_passed': OWNERS, 'product_acceptance': False,
              'scope': 'public descriptor publication and original decoding only'})


def main():
    require(os.environ.get('CI') == 'crow' and os.environ.get('CHECKS') == SELECTOR, 'explicit CI selector required')
    require(os.environ.get('CI_REPOSITORY_URL', '').removesuffix('.git') == 'https://github.com/corbet-foss/cbcn',
            'canonical Beacon source required')
    for name, length in [('CI_COMMIT_SHA', 40), ('SOURCE_SHA256', 64), ('DEPENDENCY_CLOSURE_SHA256', 64)]:
        require(re.fullmatch(f'[0-9a-f]{{{length}}}', os.environ.get(name, '')), 'missing source identity')
    require(not REPORT.is_relative_to(ROOT), 'external retained artifacts required')
    target = Path(os.environ.get('CARGO_TARGET_DIR', ''))
    require(target.is_absolute() and target.is_dir() and not target.resolve().is_relative_to(ROOT),
            'existing absolute external persistent Cargo target required')
    require(os.environ.get('GIT_ALLOW_PROTOCOL') == 'file', 'job-local file-only Git transport required')
    require(os.environ.get('CARGO_BUILD_JOBS') in {'1', '2'} and os.environ.get('CI_JOBS') in {'1', '2'}
            and os.environ.get('RUST_TEST_THREADS') in {'1', '2'}
            and 0 < int(os.environ['CI_MEMORY_MB']) <= 16384, 'resource envelope exceeded')
    require(not os.environ.get('RUSTC_BOOTSTRAP'), 'stable compiler required')
    qualification = Qualification()
    qualification.run('cbcn', ['rustc', '-Vv'], 'rustc-version.txt')
    require('-nightly' not in (REPORT / 'rustc-version.txt').read_text()
            and '-beta' not in (REPORT / 'rustc-version.txt').read_text(), 'stable compiler required')
    qualification.run('cbcn', ['cargo', '-V'], 'cargo-version.txt')
    qualification.prepare()
    qualification.execute()


if __name__ == '__main__':
    main()
