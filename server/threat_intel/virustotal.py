"""VirusTotal v3 threat intelligence provider."""

import logging
from typing import List

import httpx

from server.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 15.0
# Number of AV engines flagging as malicious/suspicious to be considered a hit
_MALICIOUS_THRESHOLD = 3


class VirusTotalProvider(ThreatIntelProvider):
    """Query VirusTotal API v3 for IP, file hash, and URL reputation."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._headers = {"x-apikey": api_key, "Accept": "application/json"}

    def _parse_stats(self, data: dict, source: str) -> ThreatIntelResult:
        attrs = data.get("data", {}).get("attributes", {})
        stats: dict = attrs.get("last_analysis_stats", {})
        malicious: int = stats.get("malicious", 0)
        suspicious: int = stats.get("suspicious", 0)
        total: int = sum(stats.values()) or 1
        hit_count = malicious + suspicious
        is_malicious = malicious >= _MALICIOUS_THRESHOLD
        confidence = round(hit_count / total, 2)
        tags: List[str] = list(attrs.get("tags", []))
        return ThreatIntelResult(
            is_malicious=is_malicious,
            confidence=confidence,
            tags=tags,
            source=source,
            raw=data,
        )

    async def check_ip(self, ip: str) -> ThreatIntelResult:
        url = f"{_VT_BASE}/ip_addresses/{ip}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
                return self._parse_stats(resp.json(), f"VirusTotal/ip/{ip}")
        except Exception as exc:
            logger.warning("VirusTotal IP check failed for %s: %s", ip, exc)
            return ThreatIntelResult(is_malicious=False, confidence=0.0, source="VirusTotal")

    async def check_hash(self, file_hash: str) -> ThreatIntelResult:
        url = f"{_VT_BASE}/files/{file_hash}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
                return self._parse_stats(resp.json(), f"VirusTotal/file/{file_hash}")
        except Exception as exc:
            logger.warning("VirusTotal hash check failed for %s: %s", file_hash, exc)
            return ThreatIntelResult(is_malicious=False, confidence=0.0, source="VirusTotal")

    async def check_domain(self, domain: str) -> ThreatIntelResult:
        url = f"{_VT_BASE}/domains/{domain}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
                return self._parse_stats(resp.json(), f"VirusTotal/domain/{domain}")
        except Exception as exc:
            logger.warning("VirusTotal domain check failed for %s: %s", domain, exc)
            return ThreatIntelResult(is_malicious=False, confidence=0.0, source="VirusTotal")
