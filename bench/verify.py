import sys
from mcp_authscan.report_verify import verify
if len(sys.argv)<2:
    print("usage: python3 bench/verify.py REPORT.json")
    sys.exit(2)
status,detail=verify(sys.argv[1])
print(status)
print(detail)
sys.exit(0 if status=="MATCH" else (1 if status=="MISMATCH" else 3))
