"""report_verify CLI: one line per report, and unreadable reports never crash it."""
from mcp_authscan import report_verify


def test_missing_report_prints_not_reproducible(tmp_path, capsys):
    rc = report_verify.main([str(tmp_path / "absent.json")])
    lines = capsys.readouterr().out.splitlines()
    assert rc == 1
    assert len(lines) == 1 and lines[0].startswith("NOT REPRODUCIBLE "), lines


def test_corrupt_report_prints_not_reproducible(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    rc = report_verify.main([str(bad)])
    lines = capsys.readouterr().out.splitlines()
    assert rc == 1
    assert len(lines) == 1 and lines[0].startswith("NOT REPRODUCIBLE "), lines


def test_exactly_one_line_per_report(tmp_path, capsys):
    report_verify.main([str(tmp_path / "a.json"), str(tmp_path / "b.json")])
    assert len(capsys.readouterr().out.splitlines()) == 2
