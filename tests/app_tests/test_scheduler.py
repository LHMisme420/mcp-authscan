#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/claude/vata/mcp-authscan')

from schedule_scans import AutomatedScanner

print("✅ AUTOMATED SCANNING SCHEDULER")
print("")
print("Configuration:")
print("  📅 Daily scan: Every day at 3:00 AM UTC")
print("  📅 Weekly scan: Every Monday at 9:00 AM UTC")
print("")
print("What it does:")
print("  🔍 Scans MCP servers for vulnerabilities")
print("  📊 Logs findings to database")
print("  ⚠️  Tracks compliance scores")
print("  📈 Maintains historical trends")
print("")
print("To start scheduler in background:")
print("  python3 schedule_scans.py &")
print("")
print("Logs will be saved and emailable to your team")

# Show what a scan would log
from historical_tracking import create_history_table
create_history_table()
print("")
print("✅ History tracking initialized")
