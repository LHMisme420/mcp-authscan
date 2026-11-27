# MCP AuthScan labeled dataset — Zenodo deposit

A ground-truth dataset of Model Context Protocol (MCP) OAuth authorization-server
configurations with known-correct probe verdicts, used to measure the accuracy of
the mcp-authscan scanner. Every configuration is a local fixture with a flaw (or a
combination) switched on, labeled before the scanner runs.

## Scope

This deposit measures the **scanner's own accuracy** against labeled local
fixtures. It does **not** contain or disclose any third-party client or server
vulnerability. The fixtures imitate flaw classes; they are not any real product's
code, and nothing outside the local machine is scanned.

## Contents

- `cases.json` — 33 labeled configurations of the fixture OAuth server.
- `DATASHEET.md` — what the data is, the case families, and what it does not show.
- `run_dataset.py` — the runner (reference copy; see Reproduce below).
- `results/run-<UTC>/` — each run's `rows.jsonl` (one row per case and probe),
  `summary.json` (scanner version, provenance commit, counts) and `SHA256SUMS`.

## Headline result

mcp-authscan 1.1.47: 33 cases, 462 rows, **176 of 176 labeled probe verdicts
correct** (reference run `results/run-20261127T124143Z`, recorded from a clean
checkout, provenance commit `8f3f2a7`). Unlabeled probe rows are recorded but not
scored.

## Provenance and integrity

- Source: https://github.com/LHMisme420/mcp-authscan at commit
  `8f3f2a770c0f8de9057856d97931fe013c02968e`.
- Verify any run: `cd results/run-<UTC> && sha256sum -c SHA256SUMS`.
- Each `summary.json` records the scanner version, the provenance commit, and
  whether the checkout had uncommitted tracked changes (`repo_dirty`).

## Reproduce

    git clone https://github.com/LHMisme420/mcp-authscan
    cd mcp-authscan && git checkout 8f3f2a770c0f8de9057856d97931fe013c02968e
    python3 -m venv .venv && . .venv/bin/activate
    pip install -e '.[signing]'
    python3 bench/dataset/run_dataset.py

The runner needs the scanner and the fixture `fixture_oauth.py`, both in that
repository at that commit, so reproduction is from the repository rather than from
this archive alone.

## License

Creative Commons Attribution 4.0 International (CC-BY-4.0).

## Cite

Leroy H. Mason (2026). *MCP AuthScan labeled dataset.* Zenodo. DOI: <added on publish>.
