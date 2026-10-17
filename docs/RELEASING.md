# Releasing mcp-authscan to PyPI

Publishing is automated by `.github/workflows/release.yml`: pushing a `v*` tag
builds the sdist + wheel, uploads to PyPI (if a token is configured), and
creates a GitHub release with the artifacts.

## One-time setup

1. **Confirm the name is available.** Check https://pypi.org/project/mcp-authscan/.
   If it's taken, pick another distribution name in `pyproject.toml` (`name =`)
   — the import package `mcp_authscan` can stay the same.
2. **Create a PyPI account** at https://pypi.org and verify your email.
3. **Create an API token:** PyPI → Account settings → API tokens → *Add API
   token*. Scope it to the project after the first upload, or "entire account"
   for the very first publish.
4. **Add it as a repo secret:** GitHub → repo Settings → Secrets and variables →
   Actions → *New repository secret* → name it exactly `PYPI_API_TOKEN`, paste
   the token value.

If `PYPI_API_TOKEN` is not set, the release workflow still runs and creates the
GitHub release — it just skips the PyPI upload.

## Cutting a release

1. Bump the version in **both** places (they must match):
   - `pyproject.toml` → `version = "X.Y.Z"`
   - `mcp_authscan/__init__.py` → `__version__ = "X.Y.Z"`
2. Update `CHANGELOG.md` (move items from *Unreleased* into the new version).
3. Commit via a PR and merge to `main`.
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
mcp-authscan scan --help
```
