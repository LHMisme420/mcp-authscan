#!/bin/bash
# Exit Code Proof — All Six Codes
# Run from repo root: ./proof_all_exit_codes.sh
# Proves mcp-authscan exit code semantics with raw echo $? output

set +e
cd "$(dirname "$0")"

echo "======================================================================"
echo "EXIT CODE PROOF — All Six Codes with Raw echo \$? Output"
echo "======================================================================"
echo ""

# Cleanup
pkill -9 -f test_server 2>/dev/null
pkill -9 -f http.server 2>/dev/null
sleep 1

# EXIT 0: Scan completed, no findings at threshold
echo "========== EXIT 0 =========="
echo "Scan completed, no findings at or above --fail-on threshold"
python3 test_server.py 8000 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:8000/mcp \
  --authorized-by "Leroy H. Mason" \
  --auth-basis "Written consent" \
  --contact "security@vata.local" \
  --fail-on critical \
  --allow-private >/dev/null 2>&1
echo $?
pkill -9 -f test_server 2>/dev/null
sleep 1
echo ""

# EXIT 1: Scan completed, findings at threshold
echo "========== EXIT 1 =========="
echo "Scan completed, findings at or above --fail-on threshold"
python3 test_server.py 8000 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:8000/mcp \
  --authorized-by "Leroy H. Mason" \
  --auth-basis "Written consent" \
  --contact "security@vata.local" \
  --fail-on high \
  --allow-private >/dev/null 2>&1
echo $?
pkill -9 -f test_server 2>/dev/null
sleep 1
echo ""

# EXIT 2: Authorization validation failed
echo "========== EXIT 2 =========="
echo "Authorization validation failed (refused, fail-closed)"
python3 mcp_authscan.py http://127.0.0.1:8000/mcp \
  --authorized-by "Test" \
  --auth-basis "test" \
  --contact "test@test.com" \
  --allow-private >/dev/null 2>&1
echo $?
echo ""

# EXIT 3: Target unreachable
echo "========== EXIT 3 =========="
echo "Target unreachable (connection refused)"
python3 mcp_authscan.py http://127.0.0.1:9999/mcp \
  --authorized-by "Leroy H. Mason" \
  --auth-basis "Written consent" \
  --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1
echo $?
echo ""

# EXIT 4: Preflight failed
echo "========== EXIT 4 =========="
echo "Preflight failed (target not an MCP server)"
python3 -m http.server 9998 >/dev/null 2>&1 &
sleep 1
python3 mcp_authscan.py http://127.0.0.1:9998/mcp \
  --authorized-by "Leroy H. Mason" \
  --auth-basis "Written consent" \
  --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1
echo $?
pkill -9 -f http.server 2>/dev/null
sleep 1
echo ""

# EXIT 5a: Discovery incomplete (easy path)
echo "========== EXIT 5a =========="
echo "Zero probes: discovery fails (metadata fetch fails)"
python3 test_server.py 9997 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:9997/mcp \
  --authorized-by "Leroy H. Mason" \
  --auth-basis "Written consent" \
  --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1
echo $?
pkill -9 -f test_server 2>/dev/null
sleep 1
echo ""

# EXIT 5b: All probes NOT_OBSERVED (hard path - ad04967 fix)
echo "========== EXIT 5b =========="
echo "Zero probes: discovery succeeds with valid resource, all probes return 404"
echo "(test_server_zero_probes: passes preflight+discovery, 404 on all probes)"
python3 test_server_zero_probes.py 8000 >/dev/null 2>&1 &
sleep 2
python3 mcp_authscan.py http://127.0.0.1:8000/mcp \
  --authorized-by "Leroy H. Mason" \
  --auth-basis "Written consent" \
  --contact "security@vata.local" \
  --allow-private >/dev/null 2>&1
echo $?
pkill -9 -f test_server_zero_probes 2>/dev/null
sleep 1
echo ""

# EXIT 6: Usage error
echo "========== EXIT 6 =========="
echo "Usage error (bad argument)"
python3 mcp_authscan.py --invalid-flag >/dev/null 2>&1
echo $?
echo ""

echo "======================================================================"
echo "END OF EXIT CODE PROOF"
echo "======================================================================"
