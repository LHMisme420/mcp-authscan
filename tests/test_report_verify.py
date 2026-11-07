import json
from mcp_authscan import report_verify as rv
def base():
    p={"target":"http://127.0.0.1:9100/mcp","scan_mode":"LIVE_ENDPOINT_ASSESSMENT","probe_set_version":"2026.11.07.2","probes":["b","a"],"counts":{"pass":1},"coverage":{},"completed":["a","b"],"not_implemented":[],"not_tested":[],"scope":"local","exit_contract":"2026.11.02.4","exit_condition":"findings","exit_code":1,"fail_on":"high","authorization":"self","hash_scheme":rv.HASH_SCHEME}
    f=[{"severity":"HIGH","rule":"MCPC-1","title":"t","endpoint":"http://x/mcp","severity_basis":"b"}]
    p["findings"]=f
    p["report_hash"],_=rv.compute(p,f)
    return p
def test_match(tmp_path):
    p=base()
    fp=tmp_path/"r.json"
    fp.write_text(json.dumps(p))
    assert rv.verify(str(fp))[0]=="MATCH"
def test_scheme_mismatch(tmp_path):
    p=base()
    p["hash_scheme"]="verdict-v2"
    fp=tmp_path/"r.json"
    fp.write_text(json.dumps(p))
    assert rv.verify(str(fp))[0]=="NOT_REPRODUCIBLE"
def test_tampered(tmp_path):
    p=base()
    p["counts"]={"pass":2}
    fp=tmp_path/"r.json"
    fp.write_text(json.dumps(p))
    assert rv.verify(str(fp))[0]=="MISMATCH"
def test_missing_hash(tmp_path):
    p=base()
    del p["report_hash"]
    fp=tmp_path/"r.json"
    fp.write_text(json.dumps(p))
    assert rv.verify(str(fp))[0]=="NOT_REPRODUCIBLE"
