# mcp-authscan: Quality Assurance

## What the Benchmark Measures

The static rule corpus is validated against seeded fixture pairs across 15 pinned repositories. All repositories are frozen at specific commits; results are reproducible locally with `python3 tests/benchmark.py`.

**Precision 1.0 and recall 1.0 on the corpus** are measurements of the detector layer on that static test set. They do **not** measure live-scan probe accuracy against real OAuth servers in the field.

## Live Probe Layer Validation

The nine authorization-server probes are validated by:

- **Nine-probe fixtures** — Seeded test cases that each probe must correctly identify and reject
- **Exit-code proofs** — Codes 0–6 demonstrate the exact verdict reached: permit, deny, network failure, or protocol error

These fixtures and exit codes are the contract for the live layer. Every probe fires against its test fixture; every result reaches the correct exit code.

## What This Does Not Cover

The benchmark does not measure probe accuracy against the full diversity of real-world OAuth implementations, vendor-specific behaviors, or edge cases not present in the fixture set.

---

## Accessing Full Results

- **JSON Report** — `vata-authscan-bench.json` (corpus, expected findings, results)
- **Test Manifest** — `tests/benchmark_manifest.json` (15 pinned repos, seed vulnerabilities)
- **Fixtures and Probes** — `tests/` (nine-probe fixtures, exit code validation)
