"""ThreatFox API client for fetching threat indicators."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx

from logger import get_logger

logger = get_logger("threatfox")


class ThreatFoxClient:
    """Client for ThreatFox API."""

    BASE_URL = "https://threatfox-api.abuse.ch"
    ENDPOINT = "/api/v1/"

    def __init__(self, api_key: str, timeout: float = 30.0):
        """Initialize ThreatFox client."""
        self.api_key = api_key.strip() if api_key else ""
        self.timeout = httpx.Timeout(timeout)
        self.client: Optional[httpx.AsyncClient] = None
        logger.info(
            "ThreatFox client initialized",
            auth_key_present=bool(self.api_key),
            auth_key_length=len(self.api_key),
        )

    async def __aenter__(self):
        """Async context manager entry."""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=True,
            headers={"User-Agent": "threatfox-s1-integration/0.1.0"},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.client:
            await self.client.aclose()

    async def fetch_iocs(
        self,
        days: int = 1,
        **kwargs,
    ) -> dict[str, Any]:
        """
        Fetch indicators from ThreatFox.

        Args:
            days: Number of days to look back (1-7, default: 1)
            **kwargs: Additional filter parameters

        Returns:
            Raw API response
        """
        if not self.client:
            raise RuntimeError("Client not initialized. Use 'async with ThreatFoxClient(...) as client:'")

        # Clamp days to ThreatFox API limit (1-7)
        days = max(1, min(days, 7))
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d")

        payload = {
            "query": "get_iocs",
            "days": days,
        }

        logger.info(
            "Fetching IOCs from ThreatFox",
            days=days,
            cutoff_date=cutoff_str,
            auth_key_present=bool(self.api_key),
            auth_key_length=len(self.api_key) if self.api_key else 0,
        )

        try:
            response = await self.client.post(
                f"{self.BASE_URL}{self.ENDPOINT}",
                json=payload,
                headers={"Auth-Key": self.api_key.strip()},
            )

            if response.status_code == 401:
                logger.error(
                    "ThreatFox Auth-Key rejected (401 Unauthorized)",
                    status_code=response.status_code,
                )
                raise RuntimeError(
                    "ThreatFox API authentication failed. Check Auth-Key in configuration."
                )

            response.raise_for_status()
            result = response.json()

            if result.get("query_status") == "ok":
                iocs = result.get("data", [])
                logger.info(
                    "Successfully fetched IOCs from ThreatFox",
                    count=len(iocs) if isinstance(iocs, list) else 0,
                )
                return result
            else:
                error_msg = result.get("error", "Unknown error")
                logger.error(
                    "ThreatFox API error",
                    query_status=result.get("query_status"),
                    error=error_msg,
                )
                raise RuntimeError(f"ThreatFox API error: {error_msg}")

        except httpx.TimeoutException:
            logger.error("ThreatFox API timeout")
            raise
        except httpx.RequestError as e:
            logger.error("ThreatFox API request error", error=str(e))
            raise

    def parse_iocs(self, api_response: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Parse IOCs from ThreatFox API response.

        Returns:
            List of normalized IOC dictionaries
        """
        iocs = []
        data = api_response.get("data", [])

        # Handle list format (current API returns data as list)
        if isinstance(data, list):
            for idx, ioc_data in enumerate(data):
                try:
                    ioc_id = ioc_data.get("id", idx)
                    parsed = {
                        "id": f"threatfox-{ioc_id}",
                        "threatfox_id": ioc_id,
                        "type": self._map_ioc_type(ioc_data.get("ioc_type")),
                        "value": ioc_data.get("ioc", ""),
                        "threat_type": ioc_data.get("threat_type"),
                        "malware_family": ioc_data.get("malware_printable"),
                        "confidence": ioc_data.get("confidence_level"),
                        "first_seen": self._parse_date(ioc_data.get("first_seen")),
                        "last_seen": self._parse_date(ioc_data.get("last_seen")),
                        "reporter": ioc_data.get("reporter"),
                        "tags": ioc_data.get("tags", []),
                        "source": "ThreatFox",
                        "reference_url": f"https://threatfox.abuse.ch/browse/ioc/{ioc_id}/",
                    }
                    iocs.append(parsed)
                except Exception as e:
                    logger.warning("Failed to parse IOC", index=idx, error=str(e))
        # Handle dict format (legacy)
        elif isinstance(data, dict):
            for ioc_id, ioc_data in data.items():
                try:
                    parsed = {
                        "id": f"threatfox-{ioc_id}",
                        "threatfox_id": ioc_id,
                        "type": self._map_ioc_type(ioc_data.get("ioc_type")),
                        "value": ioc_data.get("ioc", ""),
                        "threat_type": ioc_data.get("threat_type"),
                        "malware_family": ioc_data.get("malware_printable"),
                        "confidence": ioc_data.get("confidence_level"),
                        "first_seen": self._parse_date(ioc_data.get("first_seen")),
                        "last_seen": self._parse_date(ioc_data.get("last_seen")),
                        "reporter": ioc_data.get("reporter"),
                        "tags": ioc_data.get("tags", []),
                        "source": "ThreatFox",
                        "reference_url": f"https://threatfox.abuse.ch/browse/ioc/{ioc_id}/",
                    }
                    iocs.append(parsed)
                except Exception as e:
                    logger.warning("Failed to parse IOC", ioc_id=ioc_id, error=str(e))
        else:
            logger.warning("Unexpected ThreatFox response format", type=type(data).__name__)

        logger.info("Parsed IOCs from ThreatFox response", count=len(iocs))
        return iocs

    @staticmethod
    def _map_ioc_type(threatfox_type: Optional[str]) -> str:
        """Map ThreatFox IOC type to standard type."""
        if not threatfox_type:
            return "UNKNOWN"

        type_map = {
            "ipv4": "IPV4",
            "domain": "DOMAIN",
            "url": "URL",
            "md5_hash": "MD5",
            "sha256_hash": "SHA256",
            "sha1_hash": "SHA1",
        }

        return type_map.get(threatfox_type.lower(), threatfox_type.upper())

    @staticmethod
    def _parse_date(timestamp: Optional[str]) -> Optional[datetime]:
        """Parse ThreatFox timestamp to datetime."""
        if not timestamp:
            return None

        try:
            # ThreatFox uses UNIX timestamp
            if isinstance(timestamp, (int, float)):
                return datetime.fromtimestamp(timestamp, tz=timezone.utc)
            # Or ISO format
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None


async def fetch_threatfox_iocs(
    api_key: str,
    days: int = 1,
    **kwargs,
) -> list[dict[str, Any]]:
    """
    Fetch and parse IOCs from ThreatFox.

    Args:
        api_key: ThreatFox API key
        days: Number of days to look back
        **kwargs: Additional parameters

    Returns:
        List of parsed IOCs
    """
    async with ThreatFoxClient(api_key) as client:
        response = await client.fetch_iocs(days=days, **kwargs)
        return client.parse_iocs(response)
