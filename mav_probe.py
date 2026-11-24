import json, requests, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "mav-probe", "version": "1"}
    }
}
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream"
}

def probe(url, timeout=10):
    result = {"url": url, "get": None, "post_init": None}
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
        result["get"] = r.status_code
    except Exception as e:
        result["get"] = f"err:{type(e).__name__}"
    try:
        r = requests.post(url, data=json.dumps(INIT), headers=HEADERS,
                          timeout=timeout, allow_redirects=False)
        result["post_init"] = r.status_code
    except Exception as e:
        result["post_init"] = f"err:{type(e).__name__}"
    return result

# One URL per line in remote_urls.txt
urls = [line.strip() for line in open("remote_urls.txt") if line.strip()]

results = []
with ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(probe, u) for u in urls]
    for fut in as_completed(futures):
        results.append(fut.result())
        time.sleep(0.05)

get_codes = Counter(r["get"] for r in results)
post_codes = Counter(r["post_init"] for r in results)
mav = sum(1 for r in results if r["get"] in (405, 400, 406) and r["post_init"] == 401)

print(f"n={len(results)}")
print("GET:", get_codes)
print("POST initialize:", post_codes)
print(f"GET method-refusal + POST 401: {mav}")

# Optional: write full results
with open("mav_results.json", "w") as f:
    json.dump(results, f, indent=2)
