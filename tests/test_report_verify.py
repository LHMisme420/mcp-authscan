import json
from mcp_authscan import report_verify as rv
def base():
    p={"target":"http://127.0.0.1:9100/mcp","status":"completed","total_checks":1,"findings_count":1,"probe_set_version":"2026.11.07.2","coverage":1.0,"severity_counts":{"CRITICAL":0,"HIGH":1,"MEDIUM":0,"LOW":0,"INFO":0},"schema_version":3,"hash_scheme":rv.HASH_SCHEME}
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
    p["total_checks"]=2
    fp=tmp_path/"r.json"
    fp.write_text(json.dumps(p))
    assert rv.verify(str(fp))[0]=="MISMATCH"
def test_missing_hash(tmp_path):
    p=base()
    del p["report_hash"]
    fp=tmp_path/"r.json"
    fp.write_text(json.dumps(p))
    assert rv.verify(str(fp))[0]=="NOT_REPRODUCIBLE"
