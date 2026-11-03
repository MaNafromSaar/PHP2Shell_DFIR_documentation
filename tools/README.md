# Helper tools

These small utilities support evidence handling and local triage. They are provided as reviewable source, not as a substitute for analyst judgment. Run them only on authorized copies of evidence and within the applicable engagement scope.

| Tool | Purpose |
|---|---|
| `evidence-log.sh` | Calculate SHA-256 hashes, record evidence metadata, and re-verify logged files |
| `webroot_scan.py` | Read-only review of a copied web root for suspicious files, code patterns, and optional hash-baseline differences |
| `apache_triage.py` | Parse Apache access logs and tag events for analyst review; supports compressed logs and pseudonymized IPs |
| `safe_extract.py` | Verify an expected hash, then unpack an archive to a new directory while reporting skipped unsafe entries |
| `make_demo_data.py` | Generate invented web-root and access-log fixtures for demonstrations and testing |

## Requirements and tests

The Python utilities use the standard library. `webroot_scan.py` and `apache_triage.py` require Python 3.10 or later; `safe_extract.py` requires Python 3.12 or later. Run the synthetic-data test suite from this directory:

```bash
python3 -m unittest discover -s tools/tests -v
```

The suite contains 50 tests and passed in the reviewed environment. Tests use temporary directories and synthetic inputs only; no client evidence is included or required.

## Safe demonstration

```bash
python3 tools/make_demo_data.py /tmp/dfir-demo
python3 tools/webroot_scan.py /tmp/dfir-demo/webroot \
  --markdown /tmp/scan.md --json /tmp/scan.json
python3 tools/apache_triage.py /tmp/dfir-demo/access.log \
  --csv /tmp/timeline.csv --markdown /tmp/triage.md
```

The scanner and log triage produce candidate findings, not proof of compromise. Review every result in context. A clean scan does not establish that a system is clean, and log conclusions are limited by what the source logs recorded and retained.

## Evidence logger

`evidence-log.sh` expects a Markdown evidence table and writes only to the configured log; it does not modify evidence files. Point it at a case-specific register outside this sanitized package:

```bash
EVIDENCE_PROJECT_ROOT=/case-copy \
EVIDENCE_LOG=/case-copy/evidence-log.md \
  tools/evidence-log.sh add /case-copy/sample.log \
  --site Site-A --desc "Provider access log" --source "Provider export"
```

Use only a verified working copy. Preserve the original evidence separately, record provenance and collection details, and protect any personal or sensitive data according to the engagement requirements.
