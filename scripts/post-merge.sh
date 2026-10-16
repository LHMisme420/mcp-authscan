#!/usr/bin/env bash
set -euo pipefail

# Replit's Nix-managed Python is externally managed; package installation is
# handled by the workspace package manager, so this hook verifies it read-only.
python3 - <<'PY'
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import re
import sys

missing = []
for raw in Path("requirements.txt").read_text().splitlines():
    line = raw.partition("#")[0].strip()
    if not line:
        continue
    match = re.match(r"^([A-Za-z0-9_.-]+)", line)
    if not match:
        missing.append(f"cannot parse requirement: {line}")
        continue
    package_name = match.group(1)
    try:
        version(package_name)
    except PackageNotFoundError:
        missing.append(f"{package_name} is not installed")

if missing:
    print("Missing or incompatible Python dependencies:", file=sys.stderr)
    print("\n".join(f"- {item}" for item in missing), file=sys.stderr)
    sys.exit(1)
PY

python3 -m pip check
python3 -m compileall -q app.py app_full.py mcp_authscan tests/test_findings_refresh.py

# Bundling externalizes Node packages, so a passing build does not establish
# that a newly merged runtime dependency exists in this workspace.
node --input-type=module <<'JS'
import fs from 'node:fs';
import path from 'node:path';
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const missing = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })
  .filter(name => !fs.existsSync(path.join('node_modules', name, 'package.json')));
if (missing.length) {
  console.error('Missing declared Node dependencies; restore them with Replit package management before restarting:');
  for (const name of missing) console.error(`- ${name}`);
  process.exit(1);
}
JS
