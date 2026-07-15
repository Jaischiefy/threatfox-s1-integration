#!/usr/bin/env python3
"""Create a safe test IOC for S1 alert validation."""

import asyncio
import os
import json
from dotenv import load_dotenv
import httpx

async def create_test_ioc():
    """Create a safe test IOC via direct API call."""
    load_dotenv()

    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")
    account_id = os.getenv("S1_ACCOUNT_ID")

    # Test IOC payload - try with DOMAIN type
    test_ioc_value = "soc-test-jai-validation-20260715.internal"
    test_ioc_payload = {
        "data": {
            "type": "DOMAIN",  # Try DOMAIN instead of DNS
            "value": test_ioc_value,
            "source": "SOC-TEST",
            "externalId": "soc-test-jai-20260715-001",
            "method": "EQUALS",
        }
    }

    print("📝 Creating test IOC (trying DOMAIN type):")
    print(f"   Value: {test_ioc_value}")
    print(f"   Type: DOMAIN")

    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        response = await client.post(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs",
            json=test_ioc_payload,
        )

        if response.status_code == 200:
            result = response.json()
            s1_uuid = result.get("data", {}).get("uuid")
            print(f"\n✅ Test IOC created!")
            print(f"   UUID: {s1_uuid}")
            print(f"   Value: {test_ioc_value}")
            print(f"\n🔍 Next: nslookup {test_ioc_value} from a test endpoint")
        else:
            print(f"❌ Status {response.status_code}: {response.text[:200]}")

asyncio.run(create_test_ioc())
