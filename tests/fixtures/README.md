# Actual cvld public trust publications

These unchanged JSON responses were captured by the running global/community
cvld door in [cchr CI](https://github.com/corbet-foss/cchr/actions/runs/36879511545).
The services use a temporary libSQL store and synthetic users, real software
WebAuthn credentials, and real BBS proofs. No external account is involved.

`initial.json` and `ordinary.json` are byte-identical despite registration, lobby,
voucher admission, credential issuance and renewal. The remaining responses and
announcements follow all/any/threshold settings, schema version 2, then revocation
of the member's last passkey. Native and wasm tests consume these original bytes
through the follower and Charter; they do not substitute verification verdicts.

`provenance.json` records producer commit, cvld commit, successful CI URL and
SHA-256 for every capture. `scripts/check-fixtures.py` detects altered captures.
`import-door-evidence.py` imports a downloaded successful cchr `door-evidence`
artifact. The hash manifest is an audit record, not a cryptographic trust root.

csrn tests replay this evidence; they do not start cvld themselves. The cchr CI
producer runs real HTTP door services afresh. The separate csrn HTTP tests use
real local TLS to exercise origin authentication, refusal and response bounds.
These are public trust publications only, with synthetic fixture material.
