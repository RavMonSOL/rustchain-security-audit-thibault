# New Security Findings — TX-Handler Vulnerabilities

## Summary

Three new vulnerabilities discovered in RustChain's transaction handler (`node/rustchain_tx_handler.py`):

| ID | Title | Severity | CVSS |
|----|-------|----------|------|
| TX-001 | Double-Spend via Concurrent Pending Submission | Critical | 9.0 |
| TX-002 | Balance Underflow on Concurrent Confirmation | High | 7.5 |
| TX-003 | Pending Pool DoS via Mass Submissions | Medium | 6.5 |

---

## TX-001: Double-Spend via TOCTOU

**Attack:** Submit two transactions concurrently before either is recorded in `pending_transactions`. Both pass balance check, both enter pool. Balance effectively spent twice.

**Prerequisites:**
- Attacker has funded wallet
- Node is vulnerable (no exclusive lock during validate+insert)

**PoC:** `poc_double_spend.py`

```bash
# Generate test wallet if needed (seeds DB with 10 RTC)
python3 poc_double_spend.py --db /path/to/rustchain_v2.db

# Or use existing wallet
python3 poc_double_spend.py --node http://node:8088 \
    --wallet RTCxxxxxxxx --private-key <hex> --threads 20
```

**Expected vulnerable output:**
```
[!] VULNERABILITY CONFIRMED!
[!] Total pending would exceed balance: 20000000 uRTC > 10000000 uRTC
[!] CRITICAL: 5 concurrent transactions were accepted
```

**Fix:** Wrap `validate_transaction` + `INSERT` in a single `BEGIN EXCLUSIVE` transaction.

---

## TX-002: Balance Underflow on Concurrent Confirmation

**Attack:** Two transactions from same sender confirmed concurrently read the same balance and both subtract, causing negative balance.

**Prerequisites:**
- Two pending transactions from same wallet
- Block producer confirms them concurrently (multithreaded)

**PoC:** `poc_balance_underflow.py`

```bash
python3 poc_balance_underflow.py --db /root/rustchain/rustchain_v2.db
```

This directly manipulates the SQLite DB to simulate concurrent confirmation without going through the API.

**Expected output:**
```
[+] Final balance: -XXXX uRTC
[!] VULNERABILITY CONFIRMED: Balance is below expected!
```

**Fix:**
- Add `CHECK (balance_urtc >= 0)` constraint
- Confirm transactions inside exclusive transaction with re-validation

---

## TX-003: Pending Pool DoS

**Attack:** Submit thousands of minimum-value transactions to flood the pending pool, exhausting DB size and mempool scanning.

**PoC:** `poc_mempool_flood.py`

```bash
python3 poc_mempool_flood.py --node http://localhost:8088 \
    --wallet RTCxxxxxxxx --count 10000 --amount 0.1 --threads 50
```

**Expected vulnerable output:**
```
[+] Completed in 45.2s
[+] Successful submissions: 9800/10000
[*] Pending transactions in mempool: 9800
[!] VULNERABILITY: Mempool exceeds reasonable size
[!] No rate limiting observed — vulnerable to flooding
```

**Fix:**
- Limit pending transactions per address (e.g., 16)
- Rate limit `/tx/submit` endpoint
- Enforce minimum transaction amount

---

## Testing Against a Local Node

### 1. Start a local RustChain node for testing:

```bash
cd /home/beta/.openclaw/beta/rustchain-analysis
# If build script exists:
./install.sh --dev
# Or using docker:
docker-compose -f docker-compose.miner.yml up -d
```

### 2. Verify node is running:

```bash
curl -s http://localhost:8088/health | head -20
# or
curl -s http://localhost:8088/api/miners | jq .
```

### 3. Create a test wallet (if needed):

Use the browser wizard or run:
```bash
python3 -c "
from node.rustchain_crypto import generate_wallet_keypair
print(generate_wallet_keypair())
"
```

### 4. Fund the wallet:

Use faucet or manual DB insert:
```sql
INSERT INTO balances (wallet, balance_urtc) VALUES ('RTC...', 1000000000);
```

### 5. Run PoCs:

```bash
# Double-spend (shows race condition)
python3 poc_double_spend.py --node http://localhost:8088 --wallet RTCxxxx

# Mempool flood (requires node with no rate limit)
python3 poc_mempool_flood.py --node http://localhost:8088 --wallet RTCxxxx --count 500

# Balance underflow (direct DB, offline)
python3 poc_balance_underflow.py --db /root/rustchain/rustchain_v2.db
```

---

## Detection & Monitoring

To detect active exploitation:

1. **Monitor for duplicate nonces from same address:**
   ```sql
   SELECT from_addr, nonce, COUNT(*) FROM pending_transactions
   GROUP BY from_addr, nonce HAVING COUNT(*) > 1;
   ```

2. **Check for negative balances:**
   ```sql
   SELECT wallet FROM balances WHERE balance_urtc < 0;
   ```

3. **Alert on mempool size > 1000:**
   ```sql
   SELECT COUNT(*) FROM pending_transactions WHERE status='pending';
   ```

4. **Log concurrent confirmations:** Add logging to `confirm_transaction` to detect overlapping calls.

---

## Related Work

- Red Team Report: Pending Transfer Exploits (`security/pending-transfer/report.md`)
- Bounty #1980: Pending Transfer Edge Cases (150 RTC)
- PR #2004: P2P Block Validation (different code path)

---

## Responsible Disclosure

These PoCs are provided for authorized security testing only. Do not run against production nodes without explicit permission.

If you discover these vulnerabilities in the wild, report them responsibly to the RustChain maintainer via GitHub Security Advisory.
