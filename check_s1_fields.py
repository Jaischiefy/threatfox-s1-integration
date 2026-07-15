#!/usr/bin/env python3
import asyncio, os, json
from dotenv import load_dotenv
import httpx

async def check():
    load_dotenv()
    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")

    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        response = await client.get(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs?limit=1",
        )
        data = response.json()
        ioc = data.get("data", [{}])[0]
        print("S1 IOC field names:")
        for key in ioc.keys():
            print(f"  {key}: {ioc[key]}")

asyncio.run(check())
