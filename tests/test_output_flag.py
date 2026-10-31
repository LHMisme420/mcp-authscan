from mcp_authscan import monolith


def test_open_tee_writes_to_file(tmp_path):
    out = tmp_path / "r.txt"
    t = monolith.open_tee(str(out))
    t.write("hello\n")
    t.flush()
    assert out.read_text() == "hello\n"
