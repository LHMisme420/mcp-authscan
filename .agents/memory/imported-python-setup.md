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

The automatic builder also detects standalone PEP 621 metadata: removing the
default pip manifest switched it to `uv lock`/`uv sync`, which still attempted
installation into the immutable interpreter prefix.

**Why:** The CLI packaging project was independently discovered before the web
app's explicit dependency build. Disabling one installer did not disable the
other. In an isolated probe, `managed = false` did not suppress UPM detection;
both UV lock and sync failed instead of skipping an unmanaged project.

**How to apply:** Keep web deployment inputs separate from standalone packaging
metadata without breaking repository-side CLI builds. A real publish with the
root CLI metadata excluded in `.replitignore` still ran automatic UV lock/sync
and attempted Nix-store writes. Do not rely on publishing ignore rules to disable
pre-build dependency discovery.

**Why:** A filtered local source copy built and passed startup checks, but hosting
still discovered the packaging project during its earlier installation phase.

**How to apply:** Stop treating local filtered-build success as proof of a
managed-installer fix. Require actual pre-build logs showing the corrected
writable environment before claiming publishing is repaired. Do not create a
separate virtual environment or weaken storage/authentication to bypass this.

## Distinguish managed UV settings from separate environments

Replit's public Python Tools module explicitly defines
`UV_PROJECT_ENVIRONMENT=$REPL_HOME/.pythonlibs`,
`UV_PYTHON_DOWNLOADS=never`, and `UV_PYTHON_PREFERENCE=only-system`.
Using the managed `.pythonlibs` path is distinct from introducing a separate
`.venv`.

**Why:** The public module source declares the full Python Tools module, not the
interpreter-only variant. Its environment definitions do not prove what a
particular hosting installation phase inherits. Astral documents UV's default
project environment as `.venv`, not the system prefix; missing configuration
alone therefore does not explain observed Nix-store writes.

A real publish with all three UV settings explicitly configured in shared
environment variables still attempted installation into the Nix interpreter
prefix. The build used the updated source, so stale code did not explain this.

**How to apply:** Check the exact module variant and effective installer
environment. Explicit shared UV settings alone did not correct hosting's
automatic install target. The failure log does not show whether those settings
were missing, overridden, or resolved differently; do not infer which occurred
solely from the destination path. Preview health and configuration tests cannot
verify this earlier hosting phase.

## Control project detection through source layout

Keep standalone Python packaging metadata out of a Node web project's root
when the managed install phase cannot be redirected by environment settings.
Co-locate nested CLI metadata with its package sources, preserving the existing
Python import name rather than duplicating or moving runtime code.

**Why:** Publishing exclusions and shared UV settings did not prevent automatic
Nix-store writes. Removing the actual root Python project metadata changed local
UPM detection to Node/npm. A nested project must still produce complete source,
wheel, and editable distributions; relocating metadata alone can break those.

**How to apply:** Keep lint, typing, and coverage configuration discoverable in
their standard root files without recreating a root Python project. Verify
distribution contents and CLI execution outside the checkout, and require real
publishing logs before declaring the hosting failure resolved.

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
