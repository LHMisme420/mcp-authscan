"""PROBE_SET_VERSION must change whenever the probe set does (CHANGELOG.md "Probe set stamps").

The stamp is YYYY.MM.DD.N: the America/New_York date the probe set changed and a per-day
counter from 1. tests/probe_set_fingerprints.json records, for every stamp, the fingerprint of
the probe set it names (tests/probe_set_fingerprint.py says what that covers). A change to the
probe set without a new stamp fails here, as does a reused stamp or fingerprint, a malformed or
future-dated stamp, or a README that names another probe set.

To bump: set PROBE_SET_VERSION in mcp_authscan/monolith.py, run
`python3 -m tests.probe_set_fingerprint`, and add the stamp with that fingerprint and its
components to tests/probe_set_fingerprints.json.
"""
import ast
import datetime
import json
import re
from pathlib import Path

from tests.probe_set_fingerprint import fingerprint

ROOT = Path(__file__).resolve().parent.parent
RECORD = ROOT / "tests" / "probe_set_fingerprints.json"
STAMP = re.compile(r"^(\d{4})\.(\d{2})\.(\d{2})\.([1-9]\d*)$")


def current_stamp():
    tree = ast.parse((ROOT / "mcp_authscan" / "monolith.py").read_text(encoding="utf-8"))
    values = [n.value.value for n in tree.body if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "PROBE_SET_VERSION" for t in n.targets)]
    assert len(values) == 1, "PROBE_SET_VERSION must be assigned exactly once in monolith.py"
    return values[0]


def recorded():
    def no_duplicates(pairs):
        keys = [k for k, _ in pairs]
        dup = sorted({k for k in keys if keys.count(k) > 1})
        assert not dup, "duplicate keys in %s: %s" % (RECORD.name, dup)
        return dict(pairs)
    return json.loads(RECORD.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)["stamps"]


def today_new_york():
    try:
        from zoneinfo import ZoneInfo
        return datetime.datetime.now(ZoneInfo("America/New_York")).date()
    except ImportError:   # Python 3.8: no zoneinfo; EST is never ahead of New York's date
        return (datetime.datetime.utcnow() - datetime.timedelta(hours=5)).date()


def _date(stamp):
    m = STAMP.match(stamp)
    assert m, "stamp %r is not YYYY.MM.DD.N (N from 1)" % stamp
    return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def test_current_stamp_is_recorded_with_this_probe_set():
    stamp = current_stamp()
    stamps = recorded()
    fp, hashes = fingerprint()
    assert stamp in stamps, ("PROBE_SET_VERSION %s has no entry in %s; probe set fingerprint is %s"
                             % (stamp, RECORD.name, fp))
    changed = sorted(k for k, v in hashes.items() if stamps[stamp]["components"].get(k) != v)
    assert stamps[stamp]["fingerprint"] == fp, (
        "the probe set changed (%s) but PROBE_SET_VERSION is still %s: bump the stamp and record "
        "fingerprint %s" % (", ".join(changed) or "fingerprint", stamp, fp))


def test_recorded_stamps_are_well_formed_and_unique():
    stamps = recorded()
    assert stamps
    for stamp in stamps:
        _date(stamp)
    assert len(set(stamps)) == len(stamps)


def test_recorded_fingerprints_are_unique():
    fps = [entry["fingerprint"] for entry in recorded().values()]
    dup = sorted({f for f in fps if fps.count(f) > 1})
    assert not dup, "one probe set recorded under two stamps: %s" % dup


def test_current_stamp_is_not_dated_in_the_future():
    stamp, today = current_stamp(), today_new_york()
    assert _date(stamp) <= today, "PROBE_SET_VERSION %s is dated after today (%s, America/New_York)" % (
        stamp, today.isoformat())


def test_readme_names_the_current_probe_set():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    named = set(re.findall(r"probe set (\d{4}\.\d{2}\.\d{2}(?:\.\d+)?)", readme))
    assert named == {current_stamp()}, "README names probe set %s, PROBE_SET_VERSION is %s" % (
        sorted(named), current_stamp())
