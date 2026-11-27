# Releasing mcp-authscan to PyPI

Publishing is automated by `.github/workflows/release.yml`: pushing a `v*` tag
rebuilds the wheel reproducibly, refuses unless it matches `release/anchors.tsv`,
uploads it to PyPI through trusted publishing (with PEP 740 attestations), and
creates a GitHub release with the verified wheel.

## One-time setup

1. **Confirm the name is available.** Check https://pypi.org/project/mcp-authscan/.
   If it's taken, pick another distribution name in `pyproject.toml` (repository root) (`name =`)
   — the import package `mcp_authscan` can stay the same.
2. **Create a PyPI account** at https://pypi.org and verify your email.
3. **Trusted publisher (configured 2026-11-27):** PyPI → mcp-authscan → Publishing →
   GitHub publisher with owner `LHMisme420`, repository `mcp-authscan`, workflow
   `release.yml`, no environment. No API token or repo secret is used. A leftover
   `PYPI_API_TOKEN` secret is no longer read and can be deleted.

Attestations exist only for wheels this workflow uploads. Do not upload by hand:
a hand-uploaded version gets no attestation, and the workflow then only verifies it.

## Cutting a release

Before sending source changes to GitHub, follow
[the public-push safety check](PUBLIC_PUSH_SAFETY.md). A clean tip alone does not
make older local database commits safe to publish. The branch guard does not
check release tags; do not tag private local history.

1. Bump the version in **both** places (they must match):
   - `pyproject.toml` (repository root) **and** `mcp_authscan/pyproject.toml` → `version = "X.Y.Z"`
   - `mcp_authscan/__init__.py` → `__version__ = "X.Y.Z"`
2. Update `CHANGELOG.md` (move items from *Unreleased* into the new version).
3. Commit via a PR and merge to `main`.
   Then anchor the wheel: at that commit, build with
   `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)` and `python -m build --no-isolation --wheel`
   using build 1.6.1, setuptools 84.2.1 and wheel 0.48.0. Build twice and confirm both hashes
   match. Add `X.Y.Z<TAB>sha256<TAB>epoch` to `release/anchors.tsv` and put the hash at the top of
   the CHANGELOG entry. `release.yml` refuses any tag without an anchor. Never upload a wheel by hand.
   Before tagging, run the full suite on the release commit (`python -m pytest -q`).
   Do not tag unless it exits 0: 1.1.36 was tagged without this and shipped with version-parity failures.
4. Tag and push:
   ```bash
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
5. Watch the `release` workflow. On success, `pip install mcp-authscan` works and
   a GitHub release is published.

## Verifying

```bash
pip install mcp-authscan
mcp-authscan --help
```
