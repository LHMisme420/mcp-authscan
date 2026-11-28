"""conformance/watch.py: version ordering, previous-version lookup, and import safety."""
import importlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("watch", ROOT / "conformance" / "watch.py")
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


def test_previous_picks_highest_older_version_per_column():
    seen = {("python-sdk", "1.29.1"): {"credential_binding": "FAIL", "metadata_issuer": "FAIL"},
            ("python-sdk", "1.30.0"): {"credential_binding": "FAIL", "metadata_issuer": "PASS"},
            ("python-sdk", "2.3.0"): {"credential_binding": "FAIL"},
            ("fastmcp", "4.1.2"): {"credential_binding": "PASS"}}
    assert watch.previous(seen, "python-sdk", "2.10.0") == {"version": "2.3.0", "credential_binding": "FAIL"}
    # 2.3.0 has no metadata_issuer, so the previous measurement of that column is 1.30.0
    assert watch.previous(seen, "python-sdk", "2.10.0", "metadata_issuer") == {"version": "1.30.0", "metadata_issuer": "PASS"}
    assert watch.previous(seen, "typescript-sdk", "1.0.0") is None
    assert not watch.complete(seen, "python-sdk", "2.3.0") and watch.complete(seen, "python-sdk", "1.30.0")


def test_version_order_is_numeric():
    assert watch.vkey("2.10.0") > watch.vkey("2.9.9") > watch.vkey("1.30.0")


def test_measured_includes_matrix_and_log():
    seen = watch.measured()
    for row in json.loads((ROOT / "matrix.json").read_text()):
        kind, _, ver = row["client"].partition(" ")
        for c in watch.COLUMNS:
            assert seen[(kind, ver)][c] == row[c]


def test_log_records_are_complete_and_locked():
    log = ROOT / "conformance" / "watch" / "log.jsonl"
    for line in log.read_text().splitlines():
        r = json.loads(line)
        assert r["credential_binding"] in {"PASS", "FAIL", "NOT_OBSERVED"}
        assert r.get("metadata_issuer", "PASS") in {"PASS", "FAIL", "EXCLUDED"}
        lock = ROOT / r["lock"]
        assert lock.exists(), r["lock"]
        import hashlib
        assert hashlib.sha256(lock.read_bytes()).hexdigest() == r["lock_sha256"]


def test_binding_module_import_does_not_run():
    # Importing must not execute main() (the watch imports it).
    mod = importlib.import_module("mcp_authscan.conformance_binding")
    assert callable(mod.binding) and callable(mod.drive)


def test_summary_line_flags_changes():
    r = {"client": "python-sdk", "version": "2.4.0", "credential_binding": "PASS", "metadata_issuer": "PASS",
         "previous": {"credential_binding": {"version": "2.3.0", "credential_binding": "FAIL"}, "metadata_issuer": None},
         "changed": ["credential_binding"]}
    assert watch.summary_line(r) == ("- python-sdk 2.4.0: credential_binding PASS (previous 2.3.0: FAIL) **CHANGED**; "
                                     "metadata_issuer PASS")


def test_metadata_check_registered():
    from mcp_authscan import conformance_binding as cb
    assert set(cb.CHECKS) == set(watch.COLUMNS)
