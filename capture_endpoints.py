#!/usr/bin/env python3
"""
K Health API Endpoint Extractor
Paste the Network tab console output, get structured endpoints
"""
import json
import sys

print("""
INSTRUCTIONS:
1. Open khealth.com in your browser
2. Press F12 (Dev Tools)
3. Click Network tab
4. Use the K Health app (login, search, etc)
5. Right-click any request to otel-http.khealth.com or api.khealth.com
6. Select "Copy as cURL"
7. Paste it below (one per line, type 'done' when finished)
""")

endpoints = []
print("\n[*] Enter requests (paste cURL commands, type 'done' when finished):\n")

while True:
    try:
        line = input()
        if line.lower() == 'done':
            break
        
        # Extract URL from curl command
        if 'https://' in line:
            start = line.find('https://')
            end = line.find(' ', start)
            if end == -1:
                end = len(line)
            url = line[start:end].replace("'", "")
            
            # Extract method
            method = 'GET'
            if '-X POST' in line or '--request POST' in line:
                method = 'POST'
            elif '-X PUT' in line:
                method = 'PUT'
            elif '-X DELETE' in line:
                method = 'DELETE'
            
            endpoints.append({
                'url': url,
                'method': method,
                'raw': line[:100]  # First 100 chars of curl
            })
            print(f"  ✅ Found: {method} {url}")
    except KeyboardInterrupt:
        break

# Save
with open('khealth_endpoints.json', 'w') as f:
    json.dump(endpoints, f, indent=2)

print(f"\n✅ Found {len(endpoints)} endpoints")
print("Saved to khealth_endpoints.json\n")

# Show them
for ep in endpoints:
    print(f"{ep['method']:6} {ep['url']}")
