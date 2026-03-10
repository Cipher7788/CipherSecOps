"""AbuseIPDB threat intelligence provider."""

import logging

import httpx

from server.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 10.0


class AbuseIPDBProvider(ThreatIntelProvider):
    """Query AbuseIPDB for IP reputation data."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._headers = {"Key": api_key, "Accept": "application/json"}

    async def check_ip(self, ip: str) -> ThreatIntelResult:
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(_ABUSEIPDB_URL, headers=self._headers, params=params)
                resp.raise_for_status()
                data = resp.json().get("data", {})
                confidence_score: int = data.get("abuseConfidenceScore", 0)
                is_malicious = confidence_score >= 50
                tags = data.get("usageType", "").split(",") if data.get("usageType") else []
                return ThreatIntelResult(
                    is_malicious=is_malicious,
                    confidence=round(confidence_score / 100.0, 2),
                    tags=[t.strip() for t in tags if t.strip()],
                    source=f"AbuseIPDB/ip/{ip}",
                    raw=data,
                )
        except Exception as exc:
            logger.warning("AbuseIPDB check failed for %s: %s", ip, exc)
            return ThreatIntelResult(is_malicious=False, confidence=0.0, source="AbuseIPDB")

    async def check_hash(self, file_hash: str) -> ThreatIntelResult:
        """AbuseIPDB does not support file hash lookups."""
        logger.debug("AbuseIPDB does not support hash lookups; skipping %s", file_hash)
        return ThreatIntelResult(is_malicious=False, confidence=0.0, source="AbuseIPDB")

    async def check_domain(self, domain: str) -> ThreatIntelResult:
        """AbuseIPDB does not support domain lookups directly."""
        logger.debug("AbuseIPDB does not support domain lookups; skipping %s", domain)
        return ThreatIntelResult(is_malicious=False, confidence=0.0, source="AbuseIPDB")
