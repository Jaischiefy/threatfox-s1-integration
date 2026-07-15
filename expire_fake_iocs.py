#!/usr/bin/env python3
"""Expire fake test IOCs by setting validUntil to now."""

import asyncio
import os
from datetime import datetime, timezone
from dotenv import load_dotenv
import httpx

async def expire_iocs():
    """Expire all fake test IOCs."""
    load_dotenv()
    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")

    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        # Get all ThreatFox IOCs
        response = await client.get(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs",
            params={"source": "ThreatFox", "limit": 1000}
        )

        if response.status_code != 200:
            print(f"❌ Failed to fetch IOCs: {response.text}")
            return

        data = response.json()
        all_iocs = data.get("data", [])

        # Find test IOCs
        test_iocs = [ioc for ioc in all_iocs if "externalId" in ioc and ioc["externalId"].startswith("threatfox-test-")]

        print(f"Found {len(test_iocs)} test IOCs to expire\n")

        if not test_iocs:
            print("✅ No test IOCs found")
            return

        # Expire each test IOC by setting validUntil to now
        expired = 0
        failed = 0
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"

        for ioc in test_iocs:
            ioc_id = ioc.get("uuid")
            external_id = ioc.get("externalId")
            value = ioc.get("value")

            try:
                patch_response = await client.patch(
                    f"{console_url}/web/api/v2.1/threat-intelligence/iocs/{ioc_id}",
                    json={"validUntil": now}
                )

                if patch_response.status_code in [200, 204]:
                    print(f"✅ Expired: {value} ({external_id})")
                    expired += 1
                else:
                    print(f"❌ Failed to expire {external_id}: {patch_response.status_code}")
                    print(f"   Response: {patch_response.text[:200]}")
                    failed += 1

            except Exception as e:
                print(f"❌ Error expiring {external_id}: {str(e)}")
                failed += 1

        print(f"\n{'='*70}")
        print(f"Expiration Complete: {expired} expired, {failed} failed")
        print(f"{'='*70}")

asyncio.run(expire_iocs())
