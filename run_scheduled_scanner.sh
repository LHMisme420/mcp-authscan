#!/bin/bash

echo "🚀 VATA Automated Scanner - Scheduled Mode"
echo "Scanning every 5 minutes..."
echo ""

while true; do
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running scan..."
  python3 ~/vata/mcp-authscan/automated_scanner.py
  
  # Wait 5 minutes
  sleep 300
done
