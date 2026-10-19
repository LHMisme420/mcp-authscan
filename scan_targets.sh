#!/bin/bash

# Pre-flight cleanup
rm -rf /tmp/scan_* 2>/dev/null

# Tier 1 targets
declare -A targets=(
  [anthropic]="anthropics/anthropic-sdk-python"
  [openai]="openai/openai-python"
  [azure]="Azure/azure-sdk-for-python"
  [mistral]="mistralai/client-python"
  [cohere]="cohere-ai/cohere-python"
)

echo "=== VATA MCP OAuth Issuer Binding Scan - Tier 1 ===" 
echo "Date: $(date)"
echo ""

for name in "${!targets[@]}"; do
  repo="${targets[$name]}"
  tmpdir="/tmp/scan_$name"
  
  echo ">>> Scanning: $repo"
  
  # Clone shallow
  git clone --depth 1 "https://github.com/$repo.git" "$tmpdir" 2>&1 | grep -E "Cloning|fatal" || echo "    ✓ Cloned"
  
  if [ -d "$tmpdir" ]; then
    # Count MCP files
    mcp_count=$(find "$tmpdir" -name "*.py" -exec grep -l "from mcp\|import.*mcp" {} \; 2>/dev/null | wc -l)
    
    if [ "$mcp_count" -gt 0 ]; then
      echo "    ✓ Found MCP code: $mcp_count files"
      
      # Look for OAuth wrappers
      oauth_files=$(find "$tmpdir" -name "*.py" -exec grep -l "ClientCredentials\|class.*OAuthProvider" {} \; 2>/dev/null)
      
      if [ -n "$oauth_files" ]; then
        echo "    ✓ Found OAuth wrapper:"
        echo "$oauth_files" | head -3 | sed 's|^|        |'
        
        # Check for issuer= in __init__
        issuer_exposed=0
        while IFS= read -r file; do
          if grep -A 20 "def __init__" "$file" 2>/dev/null | grep -q "issuer"; then
            ((issuer_exposed++))
          fi
        done <<< "$oauth_files"
        
        if [ "$issuer_exposed" -eq 0 ]; then
          echo "    ❌ VULNERABLE: issuer= NOT exposed"
          echo "$repo|VULNERABLE|OAuth wrapper missing issuer binding" >> /tmp/scan_results.csv
        else
          echo "    ✓ Safe: issuer= parameter exposed"
          echo "$repo|SAFE|issuer= parameter found" >> /tmp/scan_results.csv
        fi
      else
        echo "    ○ No OAuth wrapper found (only SDK usage)"
      fi
    else
      echo "    ○ No MCP code found"
    fi
    
    rm -rf "$tmpdir"
  else
    echo "    ✗ Clone failed"
  fi
  
  echo ""
done

echo "=== Results saved to /tmp/scan_results.csv ==="
cat /tmp/scan_results.csv 2>/dev/null || echo "No results yet"
