#!/usr/bin/env python3
"""Check if our imported IOCs are actually in S1."""

import asyncio
import os
from dotenv import load_dotenv
import httpx

async def check():
    """Check for our test IOCs."""
    load_dotenv()
    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")

    # Search for IOCs we imported (source="ThreatFox")
    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        # GET IOCs with ThreatFox source
        response = await client.get(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs?source=ThreatFox&limit=5",
        )
        
        if response.status_code == 200:
            data = response.json()
            iocs = data.get("data", [])
            total = data.get("pagination", {}).get("totalItems", 0)
            
            print(f"✅ Found {total} ThreatFox IOCs in S1\n")
            if iocs:
                print("Sample IOCs:")
                for ioc in iocs[:3]:
                    print(f"  - Value: {ioc.get('value')}")
                    print(f"    Type: {ioc.get('type')}")
                    print(f"    Source: {ioc.get('source')}")
                    print()
        else:
            print(f"❌ Error: {response.text[:200]}")

asyncio.run(check())
