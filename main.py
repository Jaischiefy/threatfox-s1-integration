#!/usr/bin/env python3
"""ThreatFox to SentinelOne Threat Intelligence Integration CLI."""

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from dotenv import load_dotenv

from ioc_validator import IOCValidator
from logger import get_logger, setup_logging
from sentinelone_api import SentinelOneClient, verify_sentinelone_auth
from state import StateDatabase
from threatfox_api import fetch_threatfox_iocs

# Load environment
load_dotenv()

import os

logger = get_logger("main")


class Config:
    """Configuration container."""

    def __init__(self):
        """Load configuration from environment."""
        # Required
        self.threatfox_auth_key = os.getenv("THREATFOX_AUTH_KEY", "")
        self.s1_console_url = os.getenv("S1_CONSOLE_URL", "")
        self.s1_api_token = os.getenv("S1_API_TOKEN", "")
        self.s1_account_id = os.getenv("S1_ACCOUNT_ID")
        self.s1_site_id = os.getenv("S1_SITE_ID")

        # Optional
        self.min_confidence = int(os.getenv("MIN_CONFIDENCE", "90"))
        self.ioc_max_age_hours = int(os.getenv("IOC_MAX_AGE_HOURS", "24"))
        self.ip_expiration_days = int(os.getenv("IP_EXPIRATION_DAYS", "7"))
        self.domain_expiration_days = int(os.getenv("DOMAIN_EXPIRATION_DAYS", "14"))
        self.url_expiration_days = int(os.getenv("URL_EXPIRATION_DAYS", "14"))
        self.hash_expiration_days = int(os.getenv("HASH_EXPIRATION_DAYS", "30"))
        self.max_imports_per_run = int(os.getenv("MAX_IMPORTS_PER_RUN", "250"))
        self.batch_size = int(os.getenv("BATCH_SIZE", "25"))
        self.log_level = os.getenv("LOG_LEVEL", "INFO")
        self.dry_run = os.getenv("DRY_RUN", "true").lower() == "true"
        self.state_db = os.getenv("STATE_DB", "threatfox_s1.db")
        self.log_dir = os.getenv("LOG_DIR", "logs")

    def validate(self) -> bool:
        """Validate required configuration."""
        errors = []

        if not self.threatfox_auth_key:
            errors.append("THREATFOX_AUTH_KEY not set")
        if not self.s1_console_url:
            errors.append("S1_CONSOLE_URL not set")
        if not self.s1_api_token:
            errors.append("S1_API_TOKEN not set")
        if not (self.s1_account_id or self.s1_site_id):
            errors.append("S1_ACCOUNT_ID or S1_SITE_ID required")

        if errors:
            for error in errors:
                click.secho(f"❌ {error}", fg="red")
            return False

        return True


@click.group()
@click.pass_context
def cli(ctx):
    """ThreatFox to SentinelOne Threat Intelligence Integration."""
    # Load config
    config = Config()
    setup_logging(config.log_dir, config.log_level)

    # Store in context
    ctx.ensure_object(dict)
    ctx.obj["config"] = config


@cli.command()
@click.pass_context
def inspect(ctx):
    """Inspect configuration and state."""
    config = ctx.obj["config"]

    click.echo("\n" + "=" * 70)
    click.echo("ThreatFox to SentinelOne Integration - Configuration")
    click.echo("=" * 70)

    # Configuration
    click.echo("\n📋 Configuration:")
    click.echo(f"  ThreatFox API Key:     {'✅ SET' if config.threatfox_auth_key else '❌ NOT SET'}")
    click.echo(f"  S1 Console URL:        {config.s1_console_url}")
    click.echo(f"  S1 API Token:          {'✅ SET' if config.s1_api_token else '❌ NOT SET'}")
    click.echo(f"  S1 Account ID:         {config.s1_account_id or 'Not set'}")
    click.echo(f"  S1 Site ID:            {config.s1_site_id or 'Not set'}")
    click.echo(f"  Min Confidence:        {config.min_confidence}%")
    click.echo(f"  IOC Max Age:           {config.ioc_max_age_hours} hours")
    click.echo(f"  Batch Size:            {config.batch_size}")
    click.echo(f"  Dry-Run Mode:          {'✅ ENABLED' if config.dry_run else '❌ DISABLED'}")
    click.echo(f"  State DB:              {config.state_db}")

    # Validate
    if not config.validate():
        click.secho("\n❌ Configuration validation failed!", fg="red")
        return

    # Database
    click.echo(f"\n📊 Database:")
    try:
        with StateDatabase(config.state_db) as db:
            stats = db.get_stats()
            click.echo(f"  Total Active IOCs:     {stats['total_active']}")
            click.echo(f"  By Source:             {stats['by_source']}")
            click.echo(f"  By Type:               {stats['by_type']}")
            click.echo(f"  Expired IOCs:          {stats['expired']}")
            click.echo(f"  Last Import:           {stats['last_import'] or 'Never'}")
    except Exception as e:
        click.secho(f"  ❌ Error: {str(e)}", fg="red")

    click.echo(f"\n✅ Configuration looks good!\n")


@cli.command()
@click.option("--dry-run", is_flag=True, default=True, help="Don't write to S1")
@click.pass_context
def fetch(ctx, dry_run):
    """Fetch indicators from ThreatFox (no S1 write)."""
    config = ctx.obj["config"]

    if not config.validate():
        return

    click.echo(f"\n🔍 Fetching indicators from ThreatFox...")
    click.echo(f"   Max age: {config.ioc_max_age_hours} hours")
    click.echo(f"   Min confidence: {config.min_confidence}%\n")

    try:
        # Fetch from ThreatFox
        iocs_raw = asyncio.run(
            fetch_threatfox_iocs(config.threatfox_auth_key, max(1, min(config.ioc_max_age_hours // 24, 7)))
        )
        click.echo(f"   ✅ Fetched {len(iocs_raw)} indicators\n")

        # Validate
        validator = IOCValidator()
        valid_iocs, errors = validator.validate_batch(
            iocs_raw,
            min_confidence=config.min_confidence,
            max_age_hours=config.ioc_max_age_hours,
            ip_expiration_days=config.ip_expiration_days,
            domain_expiration_days=config.domain_expiration_days,
            url_expiration_days=config.url_expiration_days,
            hash_expiration_days=config.hash_expiration_days,
        )

        click.echo(f"   ✅ Valid: {len(valid_iocs)}")
        click.echo(f"   ❌ Invalid: {len(errors)}\n")

        # Show sample
        if valid_iocs:
            click.echo("   Sample IOCs:")
            for ioc in valid_iocs[:5]:
                click.echo(f"     • {ioc.type:10} {ioc.value:30} (confidence: {ioc.confidence}%)")
            if len(valid_iocs) > 5:
                click.echo(f"     ... and {len(valid_iocs) - 5} more")

    except Exception as e:
        click.secho(f"\n❌ Error: {str(e)}", fg="red")
        logger.error("Fetch error", error=str(e))


@cli.command()
@click.option(
    "--confirm-write",
    is_flag=True,
    help="Actually write to S1 (requires explicit confirmation)",
)
@click.pass_context
def import_iocs(ctx, confirm_write):
    """Import indicators to SentinelOne."""
    config = ctx.obj["config"]

    if not config.validate():
        return

    dry_run = not confirm_write and config.dry_run

    if dry_run:
        click.secho("⚠️  DRY-RUN MODE - No writes will be made", fg="yellow")
        click.echo("   Use --confirm-write to actually import IOCs\n")

    click.echo(f"🚀 Importing ThreatFox indicators to SentinelOne...\n")

    start_time = time.time()

    try:
        # Fetch from ThreatFox
        iocs_raw = asyncio.run(
            fetch_threatfox_iocs(config.threatfox_auth_key, max(1, min(config.ioc_max_age_hours // 24, 7)))
        )

        # Validate
        validator = IOCValidator()
        valid_iocs, errors = validator.validate_batch(
            iocs_raw,
            min_confidence=config.min_confidence,
            max_age_hours=config.ioc_max_age_hours,
            ip_expiration_days=config.ip_expiration_days,
            domain_expiration_days=config.domain_expiration_days,
            url_expiration_days=config.url_expiration_days,
            hash_expiration_days=config.hash_expiration_days,
        )

        click.echo(f"   Fetched: {len(iocs_raw)}")
        click.echo(f"   Valid:   {len(valid_iocs)}")
        click.echo(f"   Invalid: {len(errors)}\n")

        # Check against state
        with StateDatabase(config.state_db) as db:
            to_import = []
            skipped = 0
            for ioc in valid_iocs:
                if not db.is_ioc_imported(ioc.external_id):
                    to_import.append(ioc)
                else:
                    skipped += 1

            click.echo(f"   New:     {len(to_import)}")
            click.echo(f"   Skipped: {skipped} (already imported)\n")

            # Limit imports
            if len(to_import) > config.max_imports_per_run:
                click.secho(
                    f"   ⚠️  Capping at MAX_IMPORTS_PER_RUN ({config.max_imports_per_run})",
                    fg="yellow",
                )
                to_import = to_import[: config.max_imports_per_run]

            if not to_import:
                click.echo("   ✅ No new indicators to import")
                return

            # SAFEGUARD: Reject test external IDs
            test_iocs = [ioc for ioc in to_import if ioc.external_id.startswith("threatfox-test-")]
            if test_iocs:
                click.secho(
                    f"\n❌ SECURITY BLOCK: Found {len(test_iocs)} test IOCs",
                    fg="red",
                )
                for ioc in test_iocs[:3]:
                    click.echo(f"     • {ioc.external_id}")
                if len(test_iocs) > 3:
                    click.echo(f"     ... and {len(test_iocs) - 3} more")
                click.echo("\n   Use: python main.py cleanup-test-iocs")
                return

            # SAFEGUARD: Require explicit confirmation for bulk imports
            if len(to_import) > 25 and not confirm_write:
                click.secho(
                    f"\n⚠️  Large import: {len(to_import)} IOCs",
                    fg="yellow",
                )
                click.echo("   Use --confirm-write to proceed with this bulk import")
                return

            # Import to S1
            click.echo(f"   📤 Importing {len(to_import)} IOCs to SentinelOne...\n")

            async def do_import():
                async with SentinelOneClient(
                    config.s1_console_url,
                    config.s1_api_token,
                    account_id=config.s1_account_id,
                    site_id=config.s1_site_id,
                ) as s1_client:
                    return await s1_client.create_iocs_batch(
                        to_import,
                        batch_size=config.batch_size,
                        dry_run=dry_run,
                    )

            result = asyncio.run(do_import())

            click.echo(f"   ✅ Created:  {result['created']}")
            click.echo(f"   ✏️  Updated:  {result['updated']}")
            click.echo(f"   ❌ Failed:   {result['failed']}")

            if result["errors"]:
                click.secho("\n   Errors:", fg="red")
                for error in result["errors"][:5]:
                    click.echo(f"     • {error}")
                if len(result["errors"]) > 5:
                    click.echo(f"     ... and {len(result['errors']) - 5} more")

            # Record in state
            if not dry_run:
                duration = time.time() - start_time
                # Track each successfully created IOC with S1 UUID
                # Build map of external_id -> S1 UUID from response
                s1_uuid_map = {}
                for created_ioc in result.get("created_iocs", []):
                    ext_id = created_ioc.get("externalId")
                    s1_uuid = created_ioc.get("uuid")
                    if ext_id and s1_uuid:
                        s1_uuid_map[ext_id] = s1_uuid

                for ioc in to_import:
                    db.add_ioc(
                        external_id=ioc.external_id,
                        ioc_type=ioc.type,
                        value=ioc.value,
                        source=ioc.source,
                        s1_uuid=s1_uuid_map.get(ioc.external_id),  # Use S1 UUID if available
                        confidence=ioc.confidence,
                        valid_until=ioc.valid_until,
                    )
                db.record_import(
                    source="ThreatFox",
                    iocs_fetched=len(iocs_raw),
                    iocs_valid=len(valid_iocs),
                    iocs_created=result["created"],
                    iocs_updated=result["updated"],
                    iocs_failed=result["failed"],
                    duration_seconds=duration,
                )
                click.secho(f"\n✅ Import completed in {duration:.1f}s", fg="green")
            else:
                click.echo(f"\n⏭️  Dry-run complete (no data written)")

    except Exception as e:
        click.secho(f"\n❌ Error: {str(e)}", fg="red")
        logger.error("Import error", error=str(e))


@cli.command()
@click.pass_context
def status(ctx):
    """Show integration status and statistics."""
    config = ctx.obj["config"]

    click.echo("\n" + "=" * 70)
    click.echo("Integration Status")
    click.echo("=" * 70 + "\n")

    try:
        with StateDatabase(config.state_db) as db:
            stats = db.get_stats()
            last_import = db.get_last_import_time()

            click.echo(f"📊 IOC Statistics:")
            click.echo(f"   Total Active:      {stats['total_active']}")
            click.echo(f"   Last Import:       {last_import or 'Never'}")
            click.echo(f"   Expired:           {stats['expired']}")

            if stats["by_source"]:
                click.echo(f"\n   By Source:")
                for source, count in sorted(stats["by_source"].items()):
                    click.echo(f"      • {source:20} {count:5} IOCs")

            if stats["by_type"]:
                click.echo(f"\n   By Type:")
                for ioc_type, count in sorted(stats["by_type"].items()):
                    click.echo(f"      • {ioc_type:20} {count:5} IOCs")

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg="red")

    click.echo()


@cli.command()
@click.pass_context
def test_s1_auth(ctx):
    """Test SentinelOne API authentication."""
    config = ctx.obj["config"]

    if not config.validate():
        return

    click.echo("\n🔐 Testing SentinelOne API Authentication...\n")

    try:
        result = asyncio.run(
            verify_sentinelone_auth(config.s1_console_url, config.s1_api_token)
        )

        if result:
            click.secho("✅ Authentication successful!", fg="green")
        else:
            click.secho("❌ Authentication failed", fg="red")

    except Exception as e:
        click.secho(f"❌ Error: {str(e)}", fg="red")
        logger.error("Auth test error", error=str(e))

    click.echo()


@cli.command()
@click.option("--limit", default=5, help="Number of test IOCs to import")
@click.option(
    "--confirm-write",
    is_flag=True,
    help="Actually write to S1",
)
@click.pass_context
def test_ioc_import(ctx, limit, confirm_write):
    """Test IOC import with sample indicators (DRY-RUN ONLY)."""
    config = ctx.obj["config"]

    if not config.validate():
        return

    # SAFETY: Never write test IOCs to S1
    if confirm_write:
        click.secho(
            "❌ ERROR: test-ioc-import cannot be used with --confirm-write",
            fg="red",
        )
        click.echo(
            "   This command uses test data and should only run in DRY-RUN mode."
        )
        click.echo("   Use 'import-iocs' to import real ThreatFox data.")
        return

    click.secho("🧪 Test IOC Import (DRY-RUN ONLY)", fg="yellow")
    click.echo(f"   Testing with {limit} sample indicators...\n")

    # Create sample IOCs (public IPs for testing)
    test_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "9.9.9.9", "208.67.222.123"]
    sample_iocs = [
        {
            "type": "IPV4",
            "value": test_ips[i % len(test_ips)],
            "source": "ThreatFox",
            "id": f"threatfox-test-{i:03d}",
            "confidence": 95,
            "threat_type": "C2",
        }
        for i in range(limit)
    ]

    click.echo(f"   Sample IOCs (RFC5737 documentation range):")
    for ioc in sample_iocs:
        click.echo(f"     • {ioc['type']} {ioc['value']}")

    try:
        # Validate
        validator = IOCValidator()
        valid_iocs, errors = validator.validate_batch(
            sample_iocs,
            ip_expiration_days=config.ip_expiration_days,
        )

        click.echo(f"\n   Validated: {len(valid_iocs)} IOCs")
        if errors:
            click.echo(f"   Errors: {errors}\n")
        else:
            click.echo()

        if not valid_iocs:
            click.secho("   ❌ No valid IOCs", fg="red")
            return

        # Import
        async def do_test_import():
            async with SentinelOneClient(
                config.s1_console_url,
                config.s1_api_token,
                account_id=config.s1_account_id,
            ) as s1_client:
                return await s1_client.create_iocs_batch(
                    valid_iocs,
                    batch_size=config.batch_size,
                    dry_run=dry_run,
                )

        result = asyncio.run(do_test_import())

        click.echo("   📤 Sample payload (DRY-RUN):")
        for ioc in valid_iocs[:2]:
            import json

            payload = {
                "type": ioc.type,
                "value": ioc.value,
                "source": ioc.source,
                "externalId": ioc.external_id,
                "method": ioc.method,
                "validUntil": ioc.valid_until.isoformat() if ioc.valid_until else None,
            }
            click.echo(f"\n     {json.dumps(payload, indent=2)}")

    except Exception as e:
        click.secho(f"\n❌ Error: {str(e)}", fg="red")
        logger.error("Test import error", error=str(e))

    click.echo()


@cli.command()
@click.option(
    "--confirm-delete",
    is_flag=True,
    help="Permanently delete test IOCs",
)
@click.pass_context
def cleanup_test_iocs(ctx, confirm_delete):
    """Remove test IOCs from SentinelOne (threatfox-test-* only)."""
    config = ctx.obj["config"]

    if not config.validate():
        return

    click.secho("🧹 Cleanup Test IOCs", fg="yellow")
    click.echo("   Searching for test IOCs in SentinelOne...\n")

    # Fetch all ThreatFox IOCs
    async def do_cleanup():
        async with SentinelOneClient(
            config.s1_console_url,
            config.s1_api_token,
            account_id=config.s1_account_id,
        ) as s1_client:
            response = await s1_client.client.get(
                f"{config.s1_console_url}/web/api/v2.1/threat-intelligence/iocs",
                params={"source": "ThreatFox", "limit": 1000},
            )

            if response.status_code != 200:
                click.secho("❌ Failed to fetch IOCs from S1", fg="red")
                return

            all_iocs = response.json().get("data", [])
            test_iocs = [
                ioc for ioc in all_iocs
                if ioc.get("externalId", "").startswith("threatfox-test-")
            ]

            if not test_iocs:
                click.secho("✅ No test IOCs found", fg="green")
                return

            # Report cleanup list
            click.secho(f"\nFound {len(test_iocs)} test IOCs:\n", fg="yellow")
            for ioc in test_iocs[:10]:
                click.echo(f"  {ioc.get('value'):30} | {ioc.get('externalId'):25} | UUID: {ioc.get('uuid')[:16]}...")
            if len(test_iocs) > 10:
                click.echo(f"  ... and {len(test_iocs) - 10} more")

            if not confirm_delete:
                click.echo("\n   ℹ️  Use --confirm-delete to permanently remove these IOCs")
                return

            # Require explicit confirmation
            confirmation = click.prompt(
                "\n⚠️  This will permanently delete 259 test IOCs. Type the exact confirmation",
                type=str,
            )

            if confirmation != "DELETE 259 TEST IOCS":
                click.secho("❌ Confirmation mismatch. Deletion cancelled.", fg="red")
                return

            # Delete test IOCs (via PATCH to expire them)
            deleted = 0
            failed = 0
            now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z"

            for ioc in test_iocs:
                try:
                    del_response = await s1_client.client.patch(
                        f"{config.s1_console_url}/web/api/v2.1/threat-intelligence/iocs/{ioc.get('uuid')}",
                        json={"validUntil": now_iso},
                    )

                    if del_response.status_code in [200, 204]:
                        deleted += 1
                    else:
                        failed += 1
                except Exception:
                    failed += 1

            click.secho(f"\n✅ Cleanup complete: {deleted} expired, {failed} failed\n", fg="green")

    asyncio.run(do_cleanup())


if __name__ == "__main__":
    cli(obj={})
