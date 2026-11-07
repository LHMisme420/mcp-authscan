import json,sys,hashlib
HASH_SCHEME="verdict-v3"
HASHED_KEYS=("target","scan_mode","probe_set_version","probes","counts","coverage","completed","not_implemented","not_tested","scope","exit_contract","exit_condition","exit_code","fail_on","authorization","hash_scheme")
FINDING_KEYS=("severity","rule","title","endpoint","severity_basis")
def compute(payload,findings):
    hashed={k:payload[k] for k in HASHED_KEYS if k in payload}
    if isinstance(hashed.get("probes"),list):
        hashed["probes"]=sorted(str(p) for p in hashed["probes"])
    hashed["findings"]=sorted(({k:f[k] for k in FINDING_KEYS if k in f} for f in findings),key=lambda d: json.dumps(d,sort_keys=True))
    return hashlib.sha256(json.dumps(hashed,sort_keys=True).encode()).hexdigest(),sorted(hashed)
def verify(path):
    payload=json.load(open(path))
    claimed=payload.get("report_hash")
    if not claimed:
        return "NOT_REPRODUCIBLE","no report_hash in file"
    if payload.get("hash_scheme")!=HASH_SCHEME:
        return "NOT_REPRODUCIBLE","hash_scheme is %r, this code computes %r"%(payload.get("hash_scheme"),HASH_SCHEME)
    missing=[k for k in HASHED_KEYS if k not in payload]
    if missing:
        return "NOT_REPRODUCIBLE","missing covered keys: "+",".join(missing)
    got,covered=compute(payload,payload.get("findings") or [])
    if got==claimed:
        return "MATCH",claimed
    return "MISMATCH","claimed %s, recomputed %s over %d covered fields"%(claimed,got,len(covered))
