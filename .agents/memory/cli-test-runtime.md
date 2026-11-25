---
name: CLI test runtime metadata
description: Runtime Python imports can succeed while the root CLI cannot start without installed distribution metadata.
---

Run CLI fixtures with the repository distribution installed, not merely the
Flask runtime dependencies.

**Why:** the web runtime imported successfully while the real CLI stopped before
probing with `PackageNotFoundError` for its distribution version. That exit 1
can look like the expected findings exit if a harness checks only the return
code.

**How to apply:** preserve the CLI version checks; install the repository with
the configured package manager. Require a valid emitted report and expected
verdict/exit fields as well as the process exit code in CLI demonstrations.
Never substitute invented package metadata or suppress the version lookup.

On the Nix runner, also check the installed console script's interpreter and
the interpreter used to create nested test environments. A Nix-wrapped Python
can generate launchers targeting the base interpreter instead of the intended
environment, so `python -m` succeeds while the console command cannot import
the package.

**Why:** this produced misleading exit-code failures even after the editable
distribution was installed successfully.

**How to apply:** prefer an isolated test environment created with the
underlying Python executable, and use its interpreter and installed launcher
together. Fixing a launcher alone is insufficient when a packaging test
reinstalls it through the wrapped interpreter. Do not change grading or
exit-code expectations to compensate for an environment failure.
