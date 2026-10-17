# Run mcp-authscan in your CI in 5 minutes

Gate your pipeline so a misconfigured MCP server fails the build instead of
reaching production. Scan only MCP servers you operate or are explicitly
authorized to test.

> Until `mcp-authscan` is on PyPI, replace `pip install mcp-authscan` with:
> `pip install "git+https://github.com/LHMisme420/mcp-authscan@main"`

## 1. The one-liner

```bash
pip install mcp-authscan
mcp-authscan scan https://your-mcp-server --fail-on high
```
Exit code: `0` clean, `1` a finding at/above the threshold, `2` a target
couldn't be scanned. That exit code is what gates your pipeline.

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
          mcp-authscan scan \
            --targets mcp-targets.txt \
            --format sarif \
            --output results.sarif \
            --fail-on high
      - name: Upload results to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```
`mcp-targets.txt` is one URL per line (`#` comments allowed). Findings show up
in the repo's **Security → Code scanning** tab via the SARIF upload.

## 3. GitLab CI

```yaml
mcp-authscan:
  image: python:3.12-slim
  script:
    - pip install mcp-authscan
    - mcp-authscan scan --targets mcp-targets.txt --fail-on high
```

## 4. Local one-off / pre-commit

```bash
# scan a single server
mcp-authscan scan https://your-mcp-server

# scan a fleet, JSON report for your own tooling
mcp-authscan scan --targets mcp-targets.txt --format json -o report.json
```

## Options worth knowing

- `--checks all` — add the opt-in RCE-precondition checks (unauthenticated MCP
  config endpoint; missing Host/Origin validation).
- `-H "X-Research: your-tag"` — attach an identifying header some bug-bounty
  programs require on all testing traffic (repeatable).
- `--fail-on {none,info,low,medium,high,critical}` — tune how strict the gate is.
- `--concurrency N` — parallelism for fleet scans.

## No live server to try it on?

Run a reference MCP server locally and scan `localhost` — fully safe:
```bash
# in one shell
npx -y supergateway --stdio "npx -y @modelcontextprotocol/server-filesystem /tmp" --port 8000
# in another
mcp-authscan scan http://localhost:8000
```
