#!/usr/bin/env python3
import requests
import json

print("[*] Anthropic GraphQL Endpoint Testing\n")

url = "https://status.anthropic.com/graphql"

# Test simple query first
print("[1] Testing basic GraphQL connectivity\n")

queries_to_test = [
    ("Simple query", "{ __typename }"),
    ("Schema introspection", """{ __schema { types { name kind } } }"""),
    ("Query available fields", """{ __schema { queryType { fields { name } } } }"""),
]

for name, query in queries_to_test:
    try:
        r = requests.post(
            url, 
            json={"query": query},
            timeout=5,
            verify=False
        )
        
        print(f"[{r.status_code}] {name}")
        
        if r.status_code == 200:
            try:
                data = r.json()
                if "data" in data:
                    print(f"     Data: {json.dumps(data['data'])[:200]}")
                if "errors" in data:
                    print(f"     Errors: {data['errors'][0]['message'][:100]}")
            except:
                print(f"     Response: {r.text[:200]}")
        print()
    except Exception as e:
        print(f"[✗] {name}: {str(e)[:80]}\n")

# Try to discover what's actually available
print("[2] Attempting to discover endpoint capabilities\n")

discovery_queries = [
    "query { statusPage { name } }",
    "query { incident { title description } }",
    "query { component { name status } }",
    "query { services { name } }",
    "query { monitors { id name } }",
]

for q in discovery_queries:
    try:
        r = requests.post(url, json={"query": q}, timeout=5, verify=False)
        data = r.json()
        if data.get("data") and data["data"] != {}:
            print(f"[✅] Found data: {q}")
            print(f"     {data['data']}")
            print()
    except:
        pass

