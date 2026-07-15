#!/usr/bin/env python3
"""Delete fake test IOCs from S1."""

import asyncio
import os
from dotenv import load_dotenv
import httpx

async def cleanup():
    """Delete all fake test IOCs."""
    load_dotenv()
    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")

    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        # Get all test IOCs by searching for ThreatFox source
        response = await client.get(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs",
            params={"source": "ThreatFox", "limit": 1000}
        )

        if response.status_code != 200:
            print(f"❌ Failed to fetch IOCs: {response.text}")
            return

        data = response.json()
        all_iocs = data.get("data", [])

        # Find test IOCs (externalId matches pattern "threatfox-test-NNN")
        test_iocs = [ioc for ioc in all_iocs if "externalId" in ioc and ioc["externalId"].startswith("threatfox-test-")]

        print(f"Found {len(test_iocs)} test IOCs to delete\n")

        if not test_iocs:
            print("✅ No test IOCs found")
            return

        # Delete each test IOC
        deleted = 0
        failed = 0

        for ioc in test_iocs:
            ioc_id = ioc.get("uuid")
            external_id = ioc.get("externalId")
            value = ioc.get("value")

            try:
                del_response = await client.delete(
                    f"{console_url}/web/api/v2.1/threat-intelligence/iocs/{ioc_id}",
                )

                if del_response.status_code in [200, 204]:
                    print(f"✅ Deleted: {value} ({external_id})")
                    deleted += 1
                else:
                    print(f"❌ Failed to delete {external_id}: {del_response.status_code}")
                    failed += 1

            except Exception as e:
                print(f"❌ Error deleting {external_id}: {str(e)}")
                failed += 1

        print(f"\n{'='*70}")
        print(f"Cleanup Complete: {deleted} deleted, {failed} failed")
        print(f"{'='*70}")

asyncio.run(cleanup())
