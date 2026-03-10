"""Abstract base class for threat intelligence providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ThreatIntelResult:
    is_malicious: bool
    confidence: float  # 0.0 – 1.0
    tags: List[str] = field(default_factory=list)
    source: str = ""
    raw: Optional[dict] = field(default=None, repr=False)


class ThreatIntelProvider(ABC):
    """Abstract threat intelligence provider."""

    @abstractmethod
    async def check_ip(self, ip: str) -> ThreatIntelResult:
        """Check an IP address against the provider's database."""

    @abstractmethod
    async def check_hash(self, file_hash: str) -> ThreatIntelResult:
        """Check a file hash (MD5/SHA-1/SHA-256) against the provider's database."""

    @abstractmethod
    async def check_domain(self, domain: str) -> ThreatIntelResult:
        """Check a domain against the provider's database."""
