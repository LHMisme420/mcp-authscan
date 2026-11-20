"""Which mcp-authscan release carries which probe set.

A report records ``probe_set_version`` and no scanner release version, so
this table is how a reader gets from a report to the release that produced
it, using only the installed package:

    python -m mcp_authscan.releases report.json
    python -m mcp_authscan.releases --stamp 2026.11.16.1

PROBE_SET_RELEASES maps every probe-set stamp to the PyPI releases whose
wheel ships it. Entries through 1.1.24 were read from the published wheels
on PyPI (sha256-checked against PyPI's digests) on 2026-11-19, not from the
CHANGELOG. The stamp history is not monotonic: 1.1.22 shipped 2026.11.11.1
and 1.1.23 went back to 2026.11.10.1, so a stamp can name several releases.
A stamp names code only when the wheel was built from a commit: the yanked
1.1.25 wheel carries 2026.11.16.1 over uncommitted probe code, so a report
stamped 2026.11.16.1 from 1.1.25 is not reproducible from any commit.
Releases before 1.1.1 carry no stamp. Each new release adds its own entry
(tests/test_releases.py fails if the running stamp/version pair is absent).
"""
import json
import sys

PROBE_SET_RELEASES = {
    "1.1.0": ["1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6"],
    "2026.10.31.4": ["1.1.8"],
    "2026.11.01.4": ["1.1.9"],
    "2026.11.01.7": ["1.1.10", "1.1.11"],
    "2026.11.02.1": ["1.1.12", "1.1.13", "1.1.14"],
    "2026.11.02.2": ["1.1.15", "1.1.16", "1.1.17", "1.1.18", "1.1.19"],
    "2026.11.02.4": ["1.1.20"],
    "2026.11.10.1": ["1.1.21", "1.1.23", "1.1.24"],
    "2026.11.11.1": ["1.1.22"],
    # 1.1.25 on PyPI (yanked) carries this stamp over probe code that matches
    # no commit. No release ships the committed 2026.11.16.1 probes. See
    # CHANGELOG.md [1.1.25].
    "2026.11.16.1": ["1.1.25"],
    "2026.11.19.3": ["1.1.26", "1.1.27", "1.1.28", "1.1.29", "1.1.30", "1.1.31"],
}


def releases_for(stamp):
    """Releases that ship probe set ``stamp`` (oldest first); [] if none known."""
    return list(PROBE_SET_RELEASES.get(stamp, []))


def installed():
    """(release version, probe set version) of the installed package."""
    from mcp_authscan import __version__
    from mcp_authscan.monolith import PROBE_SET_VERSION
    return __version__, PROBE_SET_VERSION


def describe(stamp):
    version, current = installed()
    known = releases_for(stamp)
    return {
        "probe_set_version": stamp,
        "releases": known,
        "installed_release": version,
        "installed_probe_set_version": current,
        "installed_matches": stamp == current and version in known,
    }


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 2 and argv[0] == "--stamp":
        stamp = argv[1]
    elif len(argv) == 1 and not argv[0].startswith("-"):
        with open(argv[0], encoding="utf-8") as fh:
            stamp = json.load(fh).get("probe_set_version")
        if not isinstance(stamp, str):
            print("report has no probe_set_version", file=sys.stderr)
            return 2
    elif not argv:
        version, current = installed()
        print(json.dumps({"installed_release": version, "installed_probe_set_version": current,
                          "releases_with_this_probe_set": releases_for(current)}, indent=2))
        return 0
    else:
        print("usage: python -m mcp_authscan.releases [REPORT.json | --stamp STAMP]", file=sys.stderr)
        return 2
    info = describe(stamp)
    print(json.dumps(info, indent=2))
    return 0 if info["releases"] else 1


if __name__ == "__main__":
    sys.exit(main())
