#!/bin/bash
set -e
cd /home/claude/mcp-authscan
pkill -9 python3 2>/dev/null || true

echo "======================================================================"
echo "EXIT CODE PROOF — All Seven Codes (0-6) with Actual Output"
echo "======================================================================"
echo ""

# EXIT 0: Clean scan
echo "========== EXIT 0 =========="
echo "Clean scan (no findings at or above --fail-on threshold)"
python3 test_fixture_coverage_100.py 9000 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:9000/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private 2>&1 | tail -3
pkill -9 python3 2>/dev/null || true
python3 mcp_authscan.py http://127.0.0.1:9000/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1; echo "EXIT $?"
echo ""

# EXIT 1: Findings at threshold
echo "========== EXIT 1 =========="
echo "HIGH severity finding (password grant accepted, 7/7 verdicts)"
python3 test_fixture_with_findings.py 9002 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:9002/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private --fail-on high 2>&1 | tail -3
pkill -9 python3 2>/dev/null || true
python3 mcp_authscan.py http://127.0.0.1:9002/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private --fail-on high >/dev/null 2>&1; echo "EXIT $?"
echo ""

# EXIT 2: Authorization validation failed (missing --auth-basis)
echo "========== EXIT 2 =========="
echo "Authorization validation failed (missing --auth-basis field)"
python3 mcp_authscan.py http://127.0.0.1:9000/mcp \
  --authorized-by "Leroy H. Mason" --contact "security@vata.local" \
  --allow-private 2>&1 | tail -3
python3 mcp_authscan.py http://127.0.0.1:9000/mcp \
  --authorized-by "Leroy H. Mason" --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1; echo "EXIT $?"
echo ""

# EXIT 3: Target unreachable
echo "========== EXIT 3 =========="
echo "Target unreachable (connection refused on dead port)"
python3 mcp_authscan.py http://127.0.0.1:9999/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private 2>&1 | tail -3
python3 mcp_authscan.py http://127.0.0.1:9999/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1; echo "EXIT $?"
echo ""

# EXIT 4: Preflight failed
echo "========== EXIT 4 =========="
echo "Preflight failed (POST /initialize returns 200 HTML, not MCP)"
python3 test_fixture_not_mcp.py 9003 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:9003/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private 2>&1 | tail -3
pkill -9 python3 2>/dev/null || true
python3 mcp_authscan.py http://127.0.0.1:9003/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1; echo "EXIT $?"
echo ""

# EXIT 5: Incomplete assessment
echo "========== EXIT 5 =========="
echo "Incomplete assessment (5/7 verdicts reached, 2 excluded)"
python3 test_fixture_coverage_incomplete.py 9001 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:9001/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private 2>&1 | tail -3
pkill -9 python3 2>/dev/null || true
python3 mcp_authscan.py http://127.0.0.1:9001/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1; echo "EXIT $?"
echo ""

# EXIT 6: Usage error
echo "========== EXIT 6 =========="
echo "Usage error (invalid --fail-on argument)"
python3 mcp_authscan.py http://127.0.0.1:9000/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --fail-on invalid 2>&1 | tail -3
python3 mcp_authscan.py http://127.0.0.1:9000/mcp \
  --authorized-by "Leroy H. Mason" --auth-basis "Written consent" --contact "security@vata.local" \
  --fail-on invalid >/dev/null 2>&1; echo "EXIT $?"
echo ""

echo "======================================================================"
echo "END OF EXIT CODE PROOF"
echo "======================================================================"
