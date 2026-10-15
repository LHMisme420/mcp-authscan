#!/usr/bin/env python3
import requests
import json

print("[*] Testing Chia Full Node RPC endpoints\n")

nodes = [
    "http://localhost:8555",  # Local node
    "http://127.0.0.1:8555",
    "https://mainnet.chia.net:8555",
    "https://api.chia.net:8555",
]

# Standard Chia RPC methods
rpc_methods = [
    ("get_blockchain_state", {}),
    ("get_block", {"header_hash": "0x" + "0" * 64}),
    ("get_wallet_balance", {}),
    ("get_full_blocks", {}),
    ("get_coin_records_by_puzzle_hash", {}),
]

for node in nodes:
    print(f"[*] Testing {node}")
    
    for method, params in rpc_methods:
        try:
            payload = {
                "jsonrpc": "2.0",
                "id": "test",
                "method": method,
                "params": params
            }
            
            r = requests.post(
                node,
                json=payload,
                timeout=3,
                verify=False
            )
            
            if r.status_code == 200:
                print(f"    ✅ {method}: {r.status_code}")
                data = r.json()
                if "result" in data:
                    print(f"       Response: {str(data['result'])[:100]}")
            else:
                print(f"    [{r.status_code}] {method}")
        except Exception as e:
            pass

