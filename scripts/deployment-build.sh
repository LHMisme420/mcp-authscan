#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

# Install both dependency sets explicitly. Production PIP_USER/PIP_PREFIX also
# cover hosting builders that run a pre-install despite the skip setting.
npm ci --include=dev

# Use the Python module and the module's writable prefix, not the Nix pip
# executable's disabled user-site mode or the immutable system installation.
# --prefix preserves both site-packages and the managed bin/Gunicorn layout.
python_prefix="$(python3 -c 'import site; print(site.getuserbase())')"
env PIP_USER=0 python3 -m pip install --prefix "$python_prefix" --requirement requirements.txt

npm run build
