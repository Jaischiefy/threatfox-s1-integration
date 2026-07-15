"""IOC validation and normalization."""

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

from logger import get_logger

logger = get_logger("validator")


@dataclass
class NormalizedIOC:
    """Normalized indicator of compromise."""

    type: str  # IPV4, DOMAIN, HOSTNAME, URL, SHA256
    value: str
    source: str
    external_id: str
    method: str = "EQUALS"
    name: Optional[str] = None
    description: Optional[str] = None
    valid_until: Optional[datetime] = None
    enabled: bool = True
    threat_type: Optional[str] = None
    malware_family: Optional[str] = None
    confidence: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reporter: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    reference_url: Optional[str] = None


class IOCValidator:
    """Validates and normalizes indicators of compromise."""

    # Private/reserved IP ranges and public DNS resolvers to reject
    PRIVATE_RANGES = [
        ipaddress.IPv4Network("0.0.0.0/8"),       # This network
        ipaddress.IPv4Network("10.0.0.0/8"),      # RFC1918 private
        ipaddress.IPv4Network("127.0.0.0/8"),     # Loopback
        ipaddress.IPv4Network("169.254.0.0/16"),  # Link-local
        ipaddress.IPv4Network("172.16.0.0/12"),   # RFC1918 private
        ipaddress.IPv4Network("192.0.0.0/24"),    # TEST-NET-1
        ipaddress.IPv4Network("192.0.2.0/24"),    # Documentation (RFC5737)
        ipaddress.IPv4Network("192.88.99.0/24"),  # Deprecation notice
        ipaddress.IPv4Network("192.168.0.0/16"),  # RFC1918 private
        ipaddress.IPv4Network("198.18.0.0/15"),   # Benchmark testing
        ipaddress.IPv4Network("198.51.100.0/24"), # TEST-NET-2
        ipaddress.IPv4Network("203.0.113.0/24"),  # TEST-NET-3
        ipaddress.IPv4Network("224.0.0.0/4"),     # Multicast
        ipaddress.IPv4Network("240.0.0.0/4"),     # Reserved
        ipaddress.IPv4Network("255.255.255.255/32"),  # Broadcast
    ]

    # Public DNS resolver IPs (known benign) - reject as test artifacts
    PUBLIC_DNS_RESOLVERS = {
        "8.8.8.8",          # Google DNS
        "8.8.4.4",          # Google DNS
        "1.1.1.1",          # Cloudflare DNS
        "1.0.0.1",          # Cloudflare DNS
        "9.9.9.9",          # Quad9 DNS
        "149.112.112.112",  # Quad9 DNS
        "208.67.222.222",   # OpenDNS
        "208.67.220.220",   # OpenDNS
    }

    @staticmethod
    def is_routable_ipv4(value: str) -> bool:
        """Check if IPv4 is routable (not private, reserved, etc)."""
        try:
            ip = ipaddress.IPv4Address(value)
            for private_range in IOCValidator.PRIVATE_RANGES:
                if ip in private_range:
                    return False
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_ipv4(value: str) -> bool:
        """Validate IPv4 address format."""
        try:
            ipaddress.IPv4Address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_sha256(value: str) -> bool:
        """Validate SHA-256 hash (64 hex characters)."""
        return bool(re.match(r"^[a-fA-F0-9]{64}$", value))

    @staticmethod
    def is_valid_domain(value: str) -> bool:
        """Validate domain/hostname format."""
        # Basic domain validation: allow letters, numbers, hyphens, dots
        # Must have at least one dot (except for special cases)
        pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$"
        return bool(re.match(pattern, value)) and len(value) <= 253

    @staticmethod
    def is_valid_url(value: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(value)
            return all([result.scheme, result.netloc])
        except Exception:
            return False

    @staticmethod
    def normalize_ipv4(value: str) -> Optional[str]:
        """Normalize IPv4 address."""
        if not IOCValidator.is_valid_ipv4(value):
            return None
        if not IOCValidator.is_routable_ipv4(value):
            logger.debug("Rejecting non-routable IPv4", value=value)
            return None
        if value in IOCValidator.PUBLIC_DNS_RESOLVERS:
            logger.debug("Rejecting public DNS resolver", value=value)
            return None
        return value.strip().lower()

    @staticmethod
    def normalize_domain(value: str) -> Optional[str]:
        """Normalize domain/hostname."""
        if not value:
            return None
        # Remove trailing dot and convert to lowercase
        normalized = value.rstrip(".").lower().strip()
        if not IOCValidator.is_valid_domain(normalized):
            logger.debug("Invalid domain format", value=value)
            return None
        return normalized

    @staticmethod
    def normalize_url(value: str) -> Optional[str]:
        """Normalize URL."""
        if not value:
            return None
        normalized = value.strip()
        if not IOCValidator.is_valid_url(normalized):
            logger.debug("Invalid URL format", value=value)
            return None
        # Ensure lowercase scheme and hostname, but preserve path case
        try:
            result = urlparse(normalized)
            normalized_url = f"{result.scheme.lower()}://{result.netloc.lower()}{result.path}{result.params}{'?' + result.query if result.query else ''}{'#' + result.fragment if result.fragment else ''}"
            return normalized_url
        except Exception:
            return None

    @staticmethod
    def normalize_hash(value: str) -> Optional[str]:
        """Normalize SHA-256 hash."""
        if not value:
            return None
        normalized = value.strip().upper()
        if not IOCValidator.is_valid_sha256(normalized):
            logger.debug("Invalid SHA-256 format", value=value)
            return None
        return normalized

    @classmethod
    def normalize(
        cls,
        ioc_type: str,
        value: str,
        source: str,
        external_id: str,
        confidence: Optional[int] = None,
        threat_type: Optional[str] = None,
        malware_family: Optional[str] = None,
        first_seen: Optional[datetime] = None,
        last_seen: Optional[datetime] = None,
        reporter: Optional[str] = None,
        tags: Optional[list[str]] = None,
        reference_url: Optional[str] = None,
        min_confidence: int = 90,
        max_age_hours: int = 24,
        ip_expiration_days: int = 7,
        domain_expiration_days: int = 14,
        url_expiration_days: int = 14,
        hash_expiration_days: int = 30,
    ) -> Optional[NormalizedIOC]:
        """Validate and normalize an IOC."""

        ioc_type_upper = ioc_type.upper()

        # Validate type (map DOMAIN/HOSTNAME to DNS for S1 compatibility)
        if ioc_type_upper == "DOMAIN" or ioc_type_upper == "HOSTNAME":
            ioc_type_upper = "DNS"

        if ioc_type_upper not in ["IPV4", "DNS", "URL", "SHA256"]:
            logger.debug("Unsupported IOC type", ioc_type=ioc_type)
            return None

        # Check age
        if last_seen:
            age = datetime.now(timezone.utc) - last_seen
            if age > timedelta(hours=max_age_hours):
                logger.debug("IOC too old", external_id=external_id, age_hours=age.total_seconds() / 3600)
                return None

        # Normalize value based on type
        if ioc_type_upper == "IPV4":
            normalized_value = cls.normalize_ipv4(value)
        elif ioc_type_upper == "DNS":
            normalized_value = cls.normalize_domain(value)
        elif ioc_type_upper == "URL":
            normalized_value = cls.normalize_url(value)
        elif ioc_type_upper == "SHA256":
            normalized_value = cls.normalize_hash(value)
        else:
            return None

        if not normalized_value:
            logger.debug("Normalization failed", ioc_type=ioc_type, value=value)
            return None

        # Check confidence threshold
        if confidence is not None and confidence < min_confidence:
            logger.debug("Confidence below threshold", external_id=external_id, confidence=confidence, min_confidence=min_confidence)
            return None

        # Calculate expiration date
        if ioc_type_upper == "IPV4":
            expiration_days = ip_expiration_days
        elif ioc_type_upper in ["DOMAIN", "HOSTNAME"]:
            expiration_days = domain_expiration_days
        elif ioc_type_upper == "URL":
            expiration_days = url_expiration_days
        elif ioc_type_upper == "SHA256":
            expiration_days = hash_expiration_days
        else:
            expiration_days = 7

        valid_until = datetime.now(timezone.utc) + timedelta(days=expiration_days)

        return NormalizedIOC(
            type=ioc_type_upper,
            value=normalized_value,
            source=source,
            external_id=external_id,
            method="EQUALS",
            threat_type=threat_type,
            malware_family=malware_family,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            reporter=reporter,
            tags=tags or [],
            reference_url=reference_url,
            valid_until=valid_until,
        )

    @classmethod
    def validate_batch(
        cls,
        iocs: list[dict],
        **normalization_args,
    ) -> tuple[list[NormalizedIOC], dict[str, str]]:
        """
        Validate a batch of IOCs.

        Returns: (valid_iocs, errors_by_id)
        """
        valid = []
        errors = {}

        for ioc in iocs:
            try:
                normalized = cls.normalize(
                    ioc_type=ioc.get("type", ""),
                    value=ioc.get("value", ""),
                    source=ioc.get("source", ""),
                    external_id=ioc.get("id", ""),
                    **{k: ioc.get(k) for k in ["confidence", "threat_type", "malware_family", "first_seen", "last_seen", "reporter", "tags", "reference_url"] if k in ioc},
                    **normalization_args,
                )

                if normalized:
                    valid.append(normalized)
                else:
                    errors[ioc.get("id", "unknown")] = "Validation failed"
            except Exception as e:
                errors[ioc.get("id", "unknown")] = str(e)

        return valid, errors
