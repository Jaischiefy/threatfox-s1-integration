# Test IOC Cleanup - Dry Run Report

**Generated:** 2026-07-15 18:00 UTC

## Summary

- **Total fake test IOCs to delete:** 259
- **External ID pattern:** `threatfox-test-000` through `threatfox-test-258`
- **Values:** Cycling through 5 public DNS resolver IPs
- **Source:** `ThreatFox` (mislabeled test data)

## Test IOC Details

| UUID | Value | Type | External ID | Created | Expires |
|------|-------|------|-------------|---------|---------|
| d292958dd852bad27f14697e8da4eb49 | 8.8.8.8 | IPV4 | threatfox-test-000 | 2026-07-15T17:26:17Z | 2026-07-22T17:26:17Z |
| 6919bdbeec096cc2c733bd26f791a239 | 1.1.1.1 | IPV4 | threatfox-test-001 | 2026-07-15T17:26:17Z | 2026-07-22T17:26:17Z |
| e4cd0f0c0c296103f3119fc5a61c8321 | 208.67.222.222 | IPV4 | threatfox-test-002 | 2026-07-15T17:26:17Z | 2026-07-22T17:26:17Z |
| f07790e5407ed77d89e7bfa6b9f6b0b1 | 9.9.9.9 | IPV4 | threatfox-test-003 | 2026-07-15T17:26:17Z | 2026-07-22T17:26:17Z |
| 47e8f2c92fdfc7e80f98a21099868c6c | 208.67.222.123 | IPV4 | threatfox-test-004 | 2026-07-15T17:26:17Z | 2026-07-22T17:26:17Z |
| ... (254 more records) | ... | IPV4 | threatfox-test-005 through threatfox-test-258 | 2026-07-15T17:26:17Z | 2026-07-22T17:26:17Z |

## Cleanup Command

```bash
# Dry-run: view test IOCs without deleting
python main.py cleanup-test-iocs

# Permanent deletion: requires typed confirmation
python main.py cleanup-test-iocs --confirm-delete
# Confirmation text: "DELETE 259 TEST IOCS"
```

## Scope

**DELETE ONLY:**
- ✅ source = "ThreatFox"
- ✅ externalId starts with "threatfox-test-"

**DO NOT DELETE:**
- ❌ Real ThreatFox IOCs (threatfox-1851044, etc.)
- ❌ Other sources (OTX, Tenable, etc.)
- ❌ Non-test values

## Safety Checks

The cleanup command:
1. Queries S1 for IOCs matching BOTH conditions above
2. Lists all matching IOCs in dry-run (no deletion)
3. Requires explicit typed confirmation: "DELETE 259 TEST IOCS"
4. Expires (rather than deletes) IOCs via PATCH to set validUntil = now
5. Reports deleted count and failures

## Post-Cleanup Reconciliation

After cleanup:
1. Query S1 for the 250 real ThreatFox IOCs in local SQLite
2. Recover UUIDs for any found in S1
3. Report missing, duplicated, or recovered IOCs
4. Do NOT re-import until reconciliation complete

## Real IOCs Waiting

**In SQLite, pending S1 UUID recovery:**
- 150 DNS indicators
- 81 URL indicators
- 19 SHA-256 hashes
- **Total: 250 real malicious IOCs**

All validated and ready for upload once safeguards are confirmed.

