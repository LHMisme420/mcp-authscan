#!/usr/bin/env bash
set -euo pipefail

# Reconcile merged runtime requirements through the same writable-prefix
# installer as the deployment build. Never install into the Nix interpreter.
# Preserve configured registries, including the package firewall.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ -z "${UV_DEFAULT_INDEX:-${UV_INDEX_URL:-}}" && -n "${PIP_INDEX_URL:-}" ]]; then
  export UV_INDEX_URL="$PIP_INDEX_URL"
fi
if [[ -z "${UV_INDEX:-${UV_EXTRA_INDEX_URL:-}}" && -n "${PIP_EXTRA_INDEX_URL:-}" ]]; then
  export UV_EXTRA_INDEX_URL="$PIP_EXTRA_INDEX_URL"
fi
export PYTHONUSERBASE="${PYTHONUSERBASE:-$PWD/.pythonlibs}"
python_executable="$(command -v python3)"
python_prefix="$("$python_executable" -c 'import site; print(site.getuserbase())')"
case "${python_prefix%/}" in
  .pythonlibs|*/.pythonlibs) ;;
  *) echo "Refusing dependency installation outside the managed .pythonlibs prefix." >&2; exit 1 ;;
esac
uv pip install --prefix "$python_prefix" --python "$python_executable" --requirement requirements-runtime.txt
python3 -m compileall -q app.py mcp_authscan

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
