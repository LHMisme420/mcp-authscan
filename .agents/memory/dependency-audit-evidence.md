---
name: Dependency audit evidence
description: Distinguishing patched source dependencies from failed platform scans and live releases.
---

A failed platform dependency scanner is neither a clean scan nor evidence that
already-patched packages need another upgrade.

**Why:** The managed audit failed before inspection with `OSV_SCAN_FAILED`
(scanner exit 127), although the resolved dependencies and Python requirements
already excluded the reported versions. Independent advisory checks were usable.

**How to apply:** Check the resolved dependency graph and all Python requirements
includes before changing packages. If the managed scanner is unavailable, use
independent current advisory evidence and regression tests, and disclose the
scanner limitation. Do not claim the Security pane was refreshed or the published
app was updated merely because workspace dependency checks passed.
