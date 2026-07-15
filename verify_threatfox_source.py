#!/usr/bin/env python3
"""Verify live ThreatFox API response."""

import asyncio
import os
from dotenv import load_dotenv
from threatfox_api import ThreatFoxClient

async def verify():
    """Fetch fresh ThreatFox data."""
    load_dotenv()
    api_key = os.getenv("THREATFOX_AUTH_KEY")

    async with ThreatFoxClient(api_key) as client:
        response = await client.fetch_iocs(days=1)

        print(f"Query Status: {response.get('query_status')}")
        print(f"Total IOCs fetched: {len(response.get('data', []))}")
        print()

        # Analyze the first few IOCs
        iocs = response.get("data", [])[:5]
        print("Sample IOCs from ThreatFox API:")
        for ioc in iocs:
            print(f"  Value: {ioc.get('ioc')}")
            print(f"  Type: {ioc.get('ioc_type')}")
            print(f"  Confidence: {ioc.get('confidence_level')}")
            print()

        # Count by type
        type_counts = {}
        for ioc in response.get("data", []):
            t = ioc.get("ioc_type", "UNKNOWN")
            type_counts[t] = type_counts.get(t, 0) + 1

        print("Type distribution:")
        for t, count in sorted(type_counts.items()):
            print(f"  {t}: {count}")

asyncio.run(verify())
