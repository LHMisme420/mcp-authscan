#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

# The interpreter-only Python module does not own dependency installation.
# Install both dependency sets explicitly, without invoking the Nix pip wrapper.
npm ci --include=dev

# Preserve configured package registries, including the pip registry when no
# UV-specific equivalent is configured. Never replace it with a public mirror.
if [[ -z "${UV_DEFAULT_INDEX:-${UV_INDEX_URL:-}}" && -n "${PIP_INDEX_URL:-}" ]]; then
  export UV_INDEX_URL="$PIP_INDEX_URL"
fi
if [[ -z "${UV_INDEX:-${UV_EXTRA_INDEX_URL:-}}" && -n "${PIP_EXTRA_INDEX_URL:-}" ]]; then
  export UV_EXTRA_INDEX_URL="$PIP_EXTRA_INDEX_URL"
fi

export PYTHONUSERBASE="${PYTHONUSERBASE:-$PWD/.pythonlibs}"
python_executable="$(command -v python3)"
python_prefix="$("$python_executable" -c 'import site; print(site.getuserbase())')"
# Prefix mode installs ordinary libraries and scripts; it does not create a venv
# or write into Nix's immutable Python installation.
uv pip install --prefix "$python_prefix" --python "$python_executable" --requirement requirements.txt

npm run build
