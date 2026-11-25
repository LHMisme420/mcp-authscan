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

A venv installed for another worktree is not clean isolation for the current
checkout: `python -m` can import the current directory while its installed console
script imports the other editable checkout.

**Why:** this produced different version and help output in module-versus-console
tests despite using the same venv.

**How to apply:** check both import locations before attributing such failures to a
feature change; future release-suite environments should target the checkout
being tested.
