#!/usr/bin/env python3
"""Test S1 API GET endpoint for IOCs."""

import asyncio
import os
import json
from dotenv import load_dotenv
import httpx

async def test_get():
    """Test GET IOCs endpoint."""
    load_dotenv()
    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")

    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        # Try GET to verify token works
        response = await client.get(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs?limit=1",
        )
        print(f"GET /threat-intelligence/iocs - Status: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            count = data.get("pagination", {}).get("totalItems", "unknown")
            print(f"✅ API token works. Total IOCs in system: {count}")
        else:
            print(f"❌ {response.text[:200]}")

asyncio.run(test_get())
