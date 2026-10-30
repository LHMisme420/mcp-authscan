# Run mcp-authscan in your CI in 5 minutes

Gate your pipeline so a misconfigured MCP server fails the build instead of
reaching production. Scan only MCP servers you operate or are explicitly
authorized to test.

> Until `mcp-authscan` is on PyPI, replace `pip install mcp-authscan` with:
> `pip install "git+https://github.com/LHMisme420/mcp-authscan@main"`

## 1. The one-liner

```bash
pip install mcp-authscan
mcp-authscan https://your-mcp-server --fail-on high \
  --authorized-by "Your Name" --auth-basis "written consent" --contact "you@example.com"
```
Exit code: `0` clean, `1` a FAIL at/above the threshold, `2` authorization
validation failed (nothing sent), `3` target unreachable, `4` not a valid MCP
server (see EXIT_CODES.md). That exit code is what gates your pipeline.

## 2. GitHub Actions

```yaml
# .github/workflows/mcp-authscan.yml
name: mcp-authscan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # to upload SARIF to code scanning
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install mcp-authscan
      - name: Scan MCP servers
        run: |
          mcp-authscan https://your-mcp-server \
            --sarif \
            --fail-on high \
            --authorized-by "Your Name" \
            --auth-basis "written consent" \
            --contact "you@example.com" > results.sarif
      - name: Upload results to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```
SARIF goes to stdout (`--output` does not apply to `--sarif`). The CLI scans one
target per run; there is no `--targets` fleet mode. Findings show up
in the repo's **Security → Code scanning** tab via the SARIF upload.

## 3. GitLab CI

```yaml
mcp-authscan:
  image: python:3.12-slim
  script:
    - pip install mcp-authscan
    - mcp-authscan https://your-mcp-server --fail-on high --authorized-by "Your Name" --auth-basis "written consent" --contact "you@example.com"
```

## 4. Local one-off / pre-commit

```bash
# scan a single server
mcp-authscan https://your-mcp-server \
  --authorized-by "Your Name" --auth-basis "written consent" --contact "you@example.com"

# JSON report for your own tooling (also printed to stdout)
mcp-authscan https://your-mcp-server --json -o report.json \
  --authorized-by "Your Name" --auth-basis "written consent" --contact "you@example.com"
```

## Options worth knowing

- `--fail-on {critical,high,medium}` — tune how strict the gate is (default high).
- `--json`, `--sarif`, `--html` — output format; `-o FILE` names the JSON or HTML file.
- `--allow-host HOST` — authorize an extra host for discovery (repeatable).
- `--acquire-token` — attended OAuth consent so the token-bearing probes run.
- `mcp-authscan --help` lists every option.

## No live server to try it on?

Run a reference MCP server locally and scan `localhost` — fully safe:
```bash
# in one shell
npx -y supergateway --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp" --port 8000
# in another
mcp-authscan http://localhost:8000 \
  --authorized-by "Your Name" --auth-basis "written consent" --contact "you@example.com"
```
