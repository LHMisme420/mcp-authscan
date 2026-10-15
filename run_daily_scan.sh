#!/bin/bash
cd ~/vata/mcp-authscan
source venv/bin/activate
python3 mcp_server_scanner.py >> scanner.log 2>&1
