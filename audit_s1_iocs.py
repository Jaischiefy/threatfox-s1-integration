#!/usr/bin/env python3
"""Audit all ThreatFox IOCs in SentinelOne."""

import asyncio
import os
import json
from datetime import datetime
from dotenv import load_dotenv
import httpx

async def audit_iocs():
    """Export all ThreatFox IOCs from S1."""
    load_dotenv()
    console_url = os.getenv("S1_CONSOLE_URL").rstrip("/")
    api_token = os.getenv("S1_API_TOKEN")

    async with httpx.AsyncClient(timeout=30, verify=True, headers={
        "Authorization": f"ApiToken {api_token}",
        "Content-Type": "application/json",
    }) as client:
        # Get all ThreatFox IOCs (max limit is 1000)
        response = await client.get(
            f"{console_url}/web/api/v2.1/threat-intelligence/iocs",
            params={
                "source": "ThreatFox",
                "limit": 1000,  # Max allowed
            }
        )

        if response.status_code != 200:
            print(f"❌ Failed to fetch IOCs: {response.text[:200]}")
            return

        data = response.json()
        all_iocs = data.get("data", [])

        print(f"\n✅ Fetched {len(all_iocs)} ThreatFox IOCs\n")

        # Identify benign/public DNS resolvers
        benign_ips = {
            "8.8.8.8", "8.8.4.4",           # Google DNS
            "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
            "9.9.9.9", "149.112.112.112",   # Quad9 DNS
            "208.67.222.222", "208.67.220.220",  # OpenDNS
        }

        benign_count = 0
        valid_count = 0
        audit_report = []

        for ioc in all_iocs:
            value = ioc.get("value", "")
            ioc_type = ioc.get("type", "")
            is_benign = value in benign_ips

            if is_benign:
                benign_count += 1
            else:
                valid_count += 1

            audit_report.append({
                "s1_id": ioc.get("uuid"),
                "value": value,
                "type": ioc_type,
                "source": ioc.get("source"),
                "external_id": ioc.get("externalId"),
                "created": ioc.get("createdAt"),
                "expires": ioc.get("validUntil"),
                "is_benign": is_benign,
            })

        # Print summary
        print("=" * 70)
        print("AUDIT SUMMARY")
        print("=" * 70)
        print(f"Total ThreatFox IOCs: {len(all_iocs)}")
        print(f"Benign/Public DNS resolvers: {benign_count}")
        print(f"Potentially valid IOCs: {valid_count}")
        print()

        # Print benign IOCs
        if benign_count > 0:
            print("BENIGN IOCs DETECTED:")
            for ioc in audit_report:
                if ioc["is_benign"]:
                    print(f"  {ioc['value']:20} | Type: {ioc['type']:10} | External ID: {ioc['external_id']}")

        print()
        print("SAMPLE VALID IOCs (first 5):")
        for ioc in audit_report:
            if not ioc["is_benign"]:
                print(f"  {ioc['value']:40} | Type: {ioc['type']:10}")
                if len([x for x in audit_report if not x["is_benign"]]) >= 5:
                    break

        print()
        print("=" * 70)
        print("CLEANUP DRY-RUN LIST")
        print("=" * 70)
        for ioc in audit_report:
            if ioc["is_benign"]:
                print(f"  DELETE: {ioc['value']} (S1 UUID: {ioc['s1_id']}, External ID: {ioc['external_id']})")

        # Save full audit to file
        with open("/tmp/ioc_audit_report.json", "w") as f:
            json.dump(audit_report, f, indent=2)

        print(f"\n📄 Full audit saved to /tmp/ioc_audit_report.json")

asyncio.run(audit_iocs())
