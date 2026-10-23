---
name: Imported Python setup
description: Dependency installation behavior encountered when setting up this imported repository on Replit.
---

Replit's Python package installation can discover dependencies from optional scripts as well as the requested package list. Old Python toolchains can force outdated releases that the package firewall blocks.

**Why:** Setup required a supported Python toolchain and newer releases of the same dependencies; the installation also inferred packages used outside the main dashboard.

Post-merge scripts run under Replit's Nix-managed Python, where system-wide `pip install` is rejected as externally managed. Use Replit's package manager for installation; keep post-merge hooks read-only by checking declared versions and compiling the app.

**Why:** A direct `pip install -r requirements.txt` in the merge hook failed with PEP 668 even though the project dependencies were installed and valid.

**How to apply:** If an installation is blocked, check runtime compatibility and the dependency chain before retrying. Upgrade the relevant direct dependency rather than bypassing the package firewall. Inspect the resulting requirements for duplicate entries. In post-merge scripts, use `pip` only for read-only checks, not installs.

Hosting's Nix `pip` executable can force user-site packages off even when
the workspace's `python3` enables them. Pip 26 rejects a requested user install
in that state; changing only to `python3 -m pip --user` can instead hit PEP 668.

**Why:** Two real publishing attempts stopped during automatic dependency
installation before the application build. Both failures were reproducible
locally, independently of application code and the findings writer.

**How to apply:** Diagnose the actual installer wrapper, not just Python imports.
Use the managed writable Python prefix rather than user-install mode or Nix's
immutable system location. Do not disable system protection or the package
firewall. When replacing hosting's automatic installer, explicitly retain both
Node and Python dependency installation; successful local compilation alone
does not verify a cold dependency install in the next publish.

After merges, verify the actual workflow run command serves HTTP, not just that modules import or compile.

**Why:** Import-based Flask tests and compilation passed even when the executable startup guard was absent; the workflow exited successfully without starting a server. Similarly, Node bundles built with external packages can compile successfully while a required runtime dependency is missing.

**How to apply:** Check the workflow process, startup output, and HTTP readiness once after a merge. A successful post-merge hook does not by itself establish that the application starts.

Restricted Python subprocesses must not assume the parent runtime's installed
packages are discoverable. Test them without Python package-path settings and
signing credentials, not just inside the richer application test environment.

**Why:** A publishing attempt passed compilation and isolated startup tests but
failed inside the fresh SQLite initializer. The helper imported Flask while
discarding Python package-discovery configuration; the tests supplied a package
path that hid this production difference.

**How to apply:** Keep schema-only initialization standard-library-only and shared
with the application. Do not fix helper imports by passing all runtime secrets or
weakening the PostgreSQL startup guard.
