"""SentinelOne Threat Intelligence API client."""

import asyncio
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from ioc_validator import NormalizedIOC
from logger import get_logger

logger = get_logger("sentinelone")


class SentinelOneClient:
    """Client for SentinelOne Threat Intelligence API."""

    def __init__(
        self,
        console_url: str,
        api_token: str,
        account_id: Optional[str] = None,
        site_id: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """Initialize SentinelOne client."""
        # Validate HTTPS scheme
        parsed = urlparse(console_url)
        if parsed.scheme != "https":
            raise ValueError(
                f"S1_CONSOLE_URL must use HTTPS, got: {parsed.scheme}://"
            )

        self.console_url = console_url.rstrip("/")
        self.api_token = api_token
        self.account_id = account_id
        self.site_id = site_id
        self.timeout = httpx.Timeout(timeout)
        self.client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        """Async context manager entry."""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=True,
            headers={
                "Authorization": f"ApiToken {self.api_token}",
                "Content-Type": "application/json",
                "User-Agent": "threatfox-s1-integration/0.1.0",
            },
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

    async def verify_auth(self) -> bool:
        """Verify API authentication works."""
        if not self.client:
            raise RuntimeError("Client not initialized")

        try:
            # Try a simple GET to verify auth
            response = await self.client.get(
                f"{self.console_url}/web/api/v2.1/threat-intelligence/iocs?limit=1"
            )

            if response.status_code == 200:
                logger.info("SentinelOne authentication verified")
                return True
            elif response.status_code == 401:
                logger.error("SentinelOne authentication failed: Invalid token")
                return False
            else:
                logger.error(
                    "SentinelOne auth verification failed",
                    status_code=response.status_code,
                )
                return False

        except Exception as e:
            logger.error("SentinelOne auth verification error", error=str(e))
            return False

    async def create_ioc(self, ioc: NormalizedIOC, dry_run: bool = True) -> Optional[dict[str, Any]]:
        """
        Create a single IOC in SentinelOne.

        Args:
            ioc: Normalized IOC
            dry_run: If True, don't actually write

        Returns:
            API response or None if failed/dry-run
        """
        if not self.client:
            raise RuntimeError("Client not initialized")

        payload = self._build_ioc_payload(ioc)

        if dry_run:
            logger.info(
                "DRY RUN: Would create IOC",
                external_id=ioc.external_id,
                type=ioc.type,
                value=ioc.value,
                payload=payload,
            )
            return None

        logger.info("Creating IOC in SentinelOne", external_id=ioc.external_id)

        try:
            response = await self.client.post(
                f"{self.console_url}/web/api/v2.1/threat-intelligence/iocs",
                json={"data": payload},
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(
                    "IOC created successfully",
                    external_id=ioc.external_id,
                    uuid=result.get("data", {}).get("uuid"),
                )
                return result.get("data")
            else:
                error_detail = self._extract_error(response)
                logger.error(
                    "Failed to create IOC",
                    external_id=ioc.external_id,
                    status_code=response.status_code,
                    error=error_detail,
                )
                return None

        except Exception as e:
            logger.error("IOC creation error", external_id=ioc.external_id, error=str(e))
            return None

    async def create_iocs_batch(
        self,
        iocs: list[NormalizedIOC],
        batch_size: int = 25,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """
        Create multiple IOCs in batches.

        Returns:
            Summary: {created, updated, failed, errors}
        """
        if not self.client:
            raise RuntimeError("Client not initialized")

        summary = {"created": 0, "updated": 0, "failed": 0, "errors": []}

        # Process in batches
        for i in range(0, len(iocs), batch_size):
            batch = iocs[i : i + batch_size]
            batch_results = await self._create_batch(batch, dry_run)
            summary["created"] += batch_results.get("created", 0)
            summary["updated"] += batch_results.get("updated", 0)
            summary["failed"] += batch_results.get("failed", 0)
            summary["errors"].extend(batch_results.get("errors", []))

        return summary

    async def _create_batch(
        self,
        iocs: list[NormalizedIOC],
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Create a batch of IOCs."""
        if not self.client:
            raise RuntimeError("Client not initialized")

        payloads = [self._build_ioc_payload(ioc) for ioc in iocs]

        if dry_run:
            logger.info(
                "DRY RUN: Would create IOCs",
                count=len(iocs),
                payloads=payloads[:1],  # Log first one only
            )
            return {"created": 0, "updated": 0, "failed": 0, "errors": []}

        logger.info("Creating IOCs", count=len(iocs), sample_payload=payloads[0] if payloads else None)

        try:
            response = await self.client.post(
                f"{self.console_url}/web/api/v2.1/threat-intelligence/iocs",
                json={
                    "filter": {"accountIds": [self.account_id]} if self.account_id else {},
                    "data": payloads,
                },
            )

            if response.status_code == 200:
                logger.info("IOCs created successfully", count=len(iocs))
                return {
                    "created": len(iocs),
                    "updated": 0,
                    "failed": 0,
                    "errors": [],
                }
            else:
                error_detail = self._extract_error(response)
                logger.error(
                    "IOC creation failed",
                    status_code=response.status_code,
                    error=error_detail,
                )
                return {
                    "created": 0,
                    "updated": 0,
                    "failed": len(iocs),
                    "errors": [{"batch": error_detail}],
                }

        except Exception as e:
            logger.error("IOC creation error", error=str(e))
            return {
                "created": 0,
                "updated": 0,
                "failed": len(iocs),
                "errors": [{"batch": str(e)}],
            }

    async def get_iocs(self, ioc_type: Optional[str] = None, limit: int = 100) -> list[dict[str, Any]]:
        """Get list of imported IOCs."""
        if not self.client:
            raise RuntimeError("Client not initialized")

        try:
            params = {"limit": limit}
            if ioc_type:
                params["type"] = ioc_type

            response = await self.client.get(
                f"{self.console_url}/web/api/v2.1/threat-intelligence/iocs",
                params=params,
            )

            if response.status_code == 200:
                result = response.json()
                return result.get("data", [])
            else:
                logger.error("Failed to get IOCs", status_code=response.status_code)
                return []

        except Exception as e:
            logger.error("Error fetching IOCs", error=str(e))
            return []

    async def get_ioc_by_external_id(self, external_id: str) -> Optional[dict[str, Any]]:
        """Get IOC by external ID."""
        iocs = await self.get_iocs(limit=1000)
        for ioc in iocs:
            if ioc.get("externalId") == external_id:
                return ioc
        return None

    @staticmethod
    def _build_ioc_payload(ioc: NormalizedIOC) -> dict[str, Any]:
        """Build API payload for IOC creation."""
        payload = {
            "type": ioc.type,
            "value": ioc.value,
            "source": ioc.source,
            "externalId": ioc.external_id,
            "method": ioc.method,
            "name": f"{ioc.type} indicator from {ioc.source}",
            "description": f"{ioc.source} threat intelligence indicator",
        }

        if ioc.valid_until:
            payload["validUntil"] = ioc.valid_until.replace(microsecond=0, tzinfo=None).isoformat() + "Z"

        return payload

    @staticmethod
    def _extract_error(response: httpx.Response) -> str:
        """Extract error message from API response."""
        try:
            data = response.json()
            if "errors" in data:
                errors = data.get("errors", [])
                if errors and isinstance(errors, list):
                    return errors[0].get("detail", str(errors[0]))
            return data.get("message", str(response.text))
        except Exception:
            return response.text or f"HTTP {response.status_code}"


async def verify_sentinelone_auth(
    console_url: str,
    api_token: str,
) -> bool:
    """Verify SentinelOne API authentication."""
    async with SentinelOneClient(console_url, api_token) as client:
        return await client.verify_auth()
