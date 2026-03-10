"""AlienVault OTX threat intelligence provider."""

import logging
from typing import List

import httpx

from server.threat_intel.base import ThreatIntelProvider, ThreatIntelResult

logger = logging.getLogger(__name__)

_OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"
_TIMEOUT = 10.0


class AlienVaultProvider(ThreatIntelProvider):
    """Query AlienVault OTX for indicators of compromise."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._headers = {"X-OTX-API-KEY": api_key, "Accept": "application/json"}

    def _build_url(self, indicator_type: str, indicator: str, section: str = "general") -> str:
        return f"{_OTX_BASE}/{indicator_type}/{indicator}/{section}"

    def _parse_general(self, data: dict, source: str) -> ThreatIntelResult:
        pulse_count: int = data.get("pulse_info", {}).get("count", 0)
        tags: List[str] = []
        for pulse in data.get("pulse_info", {}).get("pulses", []):
            tags.extend(pulse.get("tags", []))
        is_malicious = pulse_count > 0
        confidence = min(1.0, pulse_count / 10.0) if is_malicious else 0.0
        return ThreatIntelResult(
            is_malicious=is_malicious,
            confidence=round(confidence, 2),
            tags=list(set(tags))[:20],
            source=source,
            raw=data,
        )

    async def check_ip(self, ip: str) -> ThreatIntelResult:
        url = self._build_url("IPv4", ip, "general")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
                return self._parse_general(resp.json(), f"AlienVault/IPv4/{ip}")
        except Exception as exc:
            logger.warning("AlienVault IP check failed for %s: %s", ip, exc)
            return ThreatIntelResult(is_malicious=False, confidence=0.0, source="AlienVault")

    async def check_hash(self, file_hash: str) -> ThreatIntelResult:
        url = self._build_url("file", file_hash, "general")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
                return self._parse_general(resp.json(), f"AlienVault/file/{file_hash}")
        except Exception as exc:
            logger.warning("AlienVault hash check failed for %s: %s", file_hash, exc)
            return ThreatIntelResult(is_malicious=False, confidence=0.0, source="AlienVault")

    async def check_domain(self, domain: str) -> ThreatIntelResult:
        url = self._build_url("domain", domain, "general")
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, headers=self._headers)
                resp.raise_for_status()
                return self._parse_general(resp.json(), f"AlienVault/domain/{domain}")
        except Exception as exc:
            logger.warning("AlienVault domain check failed for %s: %s", domain, exc)
            return ThreatIntelResult(is_malicious=False, confidence=0.0, source="AlienVault")
