#!/usr/bin/env bash
# Rebuild every conformance client from the pinned locks and re-run the credential_binding
# and metadata_issuer columns of matrix.json. token_response_iss is NOT_REQUIRED (never graded);
# conformance_authiss needs a driver that follows /authorize.
# Output: conformance/.work/matrix.json, diffed against the published matrix.json.
# Usage: conformance/run_rows.sh [CLIENT ...]   (default: all four clients)
set -euo pipefail
CONF="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$CONF")"
PYTHON="${PYTHON:-python3}"
for n in mcp-1.29.1 mcp-1.30.0 fastmcp-4.1.2; do
  if [ ! -x "$CONF/.envs/$n/bin/python" ]; then
    "$PYTHON" -m venv "$CONF/.envs/$n"
    "$CONF/.envs/$n/bin/pip" install -q -r "$CONF/requirements/$n.lock.txt"
  fi
done
(cd "$CONF" && npm ci --silent --no-audit --no-fund)
rm -rf "$CONF/.work" && mkdir -p "$CONF/.work"
cp "$CONF"/fixtures/*.py "$CONF"/fixtures/*.mjs "$CONF/.work/"
cp "$ROOT/matrix.json" "$CONF/.work/matrix.json"
export HARNESS="$CONF/.work" MATRIX="$CONF/.work/matrix.json"
cd "$ROOT"
"$PYTHON" -m mcp_authscan.conformance_binding "$@"
if diff -u "$ROOT/matrix.json" "$MATRIX"; then
  echo "REPRODUCED: re-run matches published matrix.json"
else
  echo "DIFFERS: re-run does not match published matrix.json (diff above)"; exit 1
fi
