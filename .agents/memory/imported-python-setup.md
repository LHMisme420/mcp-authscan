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

Do not assume the documented hosting skip flag actually prevented pre-build
installs on this project.

**Why:** A failed release contained the committed custom build script and
`enabledForHosting = false`, yet still ran the automatic pip step and failed
before reaching that script. This was not stale source or an uncommitted fix.

Production pip settings were also insufficient in a subsequent real publish,
despite being present in both the failed revision and production configuration.
The same command passed a local read-only dependency check with those settings.

**Why:** The managed pre-build installer still selected a user install and failed
before running the application build. Available logs did not reveal whether the
production environment was unavailable to that phase or overridden by it.

**How to apply:** Inspect the failed revision's own configuration before blaming
an old build. Do not treat a passing local pip command, a saved production
setting, or a successful application build as proof that managed pre-install
works. If the same failure persists after verifying those controls, stop blind
republishes and investigate the platform installer rather than changing app
startup, finding storage, signing secrets, or dependency versions without evidence.

For the hybrid web deployment, keep the Python interpreter separate from its
package installer: use the interpreter-only runtime and an explicit UV prefix
install under the Node build, not the full Python tools module.

**Why:** The full tools module's managed pip step repeatedly failed before the
application build and did not respond to the documented skip flag or saved
production pip settings. A real empty-prefix install using UV succeeded without
changing the requirements, disabling system protection, or creating a venv.
However, the next actual publish still invoked pip for the root requirements,
now failing with PEP 668. Interpreter-only configuration does not suppress that
legacy pre-build phase.

**How to apply:** Keep Python's minor version consistent with the prefix layout.
Explicitly expose both user-site libraries and their executable directory; do
not assume the former tools module's environment injection still exists.
Preserve configured registries rather than substituting public mirrors. Verify
imports and startup against the fresh prefix, not cached workspace libraries.
The plain pip command resolved requirements through the firewall in a read-only
check after shared prefix settings were applied, with a non-fatal bootstrap
warning. However, an actual publish still failed with PEP 668 even though those
shared settings and the hosting skip flag were committed in the failed revision.

**Why:** Neither a passing workspace pip check nor production/shared pip settings
proved that the separate managed pre-build installer honored them.

**How to apply:** Do not repeat environment-only fixes or claim that they resolved
publishing. Preserve the explicit Python-install boundary: native package tools
may recreate the default root pip manifest, which this project intentionally
avoids because it was used by the failing automatic step. Keep CI and dependency
checks pointed at the explicit runtime requirements. Only real publishing logs
can confirm that hosting reached the custom build without the legacy pip step.

## Verify package callback results in a prefix-managed interpreter

Do not assume a successful Python package callback updated either the source
requirements or the active distribution metadata.

**Why:** With pip's writable prefix and disabled user-site discovery, a native
package callback downloaded patched wheels but left old dist-info alongside the
new wheels, reported the old versions as installed, and did not update the main
requirements. Reinstalling the resolved prefix through UV removed the stale
metadata. The callback also inferred system build dependencies even though the
selected image-library wheel already bundled its native libraries.

**How to apply:** Inspect the dependency-file diff, actual imported module
versions, and all advertised versions for each changed distribution. Reconcile
the prefix using its existing managed build script, not manual metadata deletion.
Deduplicate identical discovery paths when checking versions. Remove only newly
inferred, unnecessary system packages; preserve the project's original packages.

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
