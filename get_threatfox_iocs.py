#!/usr/bin/env python3
import asyncio, os
from dotenv import load_dotenv
import httpx

async def get():
    load_dotenv()
    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")

    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        response = await client.get(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs?source=ThreatFox&limit=10",
        )
        data = response.json()
        iocs = data.get("data", [])
        print(f"Found {len(iocs)} ThreatFox IOCs (showing first 10):\n")
        for ioc in iocs[:10]:
            print(f"Value: {ioc.get('value')}")
            print(f"  externalId: {ioc.get('externalId')}")
            print(f"  uuid: {ioc.get('uuid')}")
            print()

asyncio.run(get())
