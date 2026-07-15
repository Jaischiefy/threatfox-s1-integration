#!/usr/bin/env python3
"""Debug S1 IOC API with correct payload structure."""

import asyncio
import os
import json
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import httpx

async def test_ioc_api():
    """Test IOC creation with corrected payload."""
    load_dotenv()

    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")
    account_id = os.getenv("S1_ACCOUNT_ID")

    # Calculate 24-hour expiration - try different formats
    now_utc = datetime.now(timezone.utc)
    expires_utc = now_utc + timedelta(hours=24)
    # Try ISO format without the extra Z (isoformat already includes timezone)
    iso_format = expires_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # Test payload - try with "EXACT" method instead of "EQUALS"
    test_ioc_payload = {
        "data": [
            {
                "source": "SOC-TEST",
                "externalId": "soc-test-jai-validation-20260715",
                "type": "DNS",
                "value": "testdomain.example.com",
                "method": "EXACT",  # Try EXACT instead of EQUALS
            }
        ]
    }

    print("📝 Attempting S1 IOC creation:")
    print(f"   Endpoint: POST /web/api/v2.1/threat-intelligence/iocs")
    print(f"   Payload:")
    print(json.dumps(test_ioc_payload, indent=2))
    print()

    async with httpx.AsyncClient(
        timeout=30,
        verify=True,
        headers={
            "Authorization": f"ApiToken {api_token}",
            "Content-Type": "application/json",
        },
    ) as client:
        try:
            response = await client.post(
                f"{console_url}/web/api/v2.1/threat-intelligence/iocs",
                json=test_ioc_payload,
            )

            print(f"Response Status: {response.status_code}\n")

            try:
                body = response.json()
                print(json.dumps(body, indent=2))
            except:
                print(response.text)

            if response.status_code == 200:
                data = response.json()
                iocs_created = data.get("data", [])
                if iocs_created:
                    ioc = iocs_created[0]
                    print(f"\n✅ IOC created successfully!")
                    print(f"   UUID: {ioc.get('uuid')}")
                    print(f"   External ID: {ioc.get('externalID')}")
                    print(f"   Value: {ioc.get('value')}")

        except Exception as e:
            print(f"❌ Exception: {str(e)}")

asyncio.run(test_ioc_api())
