#!/usr/bin/env python3
"""Check that captured cvld publications still match their CI evidence digests."""
import hashlib
import json
from pathlib import Path
root = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
record = json.loads((root / 'provenance.json').read_text())
for name, expected in record['sha256'].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected, name
print('Captured public cvld evidence matches its provenance manifest')
