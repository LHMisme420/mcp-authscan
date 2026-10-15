#!/usr/bin/env python3
import requests

print("[*] Testing Chia wallet integrations\n")

# Known Chia wallet/exchange endpoints
endpoints = {
    "Chia Official": [
        "https://wallet.chia.net/api",
        "https://wallets.chia.net",
    ],
    "Gate.io": [
        "https://api.gateio.ws/api/v4/spot/currencies/xch",
    ],
    "Crypto.com": [
        "https://api.crypto.com/v1/public/ticker?instrument_name=XCH",
    ],
}

for exchange, urls in endpoints.items():
    print(f"\n[*] {exchange}:")
    for url in urls:
        try:
            r = requests.get(url, timeout=5)
            print(f"  [{r.status_code}] {url}")
            if r.status_code == 200 and len(r.text) < 500:
                print(f"      Response: {r.text[:150]}")
        except:
            pass

