"""
Agent configuration — centralises all tuneable settings and platform detection.
"""

import logging
import os
import platform
import sys
import uuid
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_RAW_PLATFORM = sys.platform  # "win32", "linux", "darwin", "android" (rare)


def _detect_platform() -> str:
    """Normalise the platform name to one of: windows | linux | darwin | android."""
    p = _RAW_PLATFORM.lower()
    if p.startswith("win"):
        return "windows"
    if p.startswith("darwin"):
        return "darwin"
    if "android" in p or "android" in platform.version().lower():
        return "android"
    return "linux"


PLATFORM: str = _detect_platform()


# ---------------------------------------------------------------------------
# Configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """All runtime settings for the CipherSecOps agent."""

    # ---- Server connectivity ------------------------------------------------
    server_url: str = field(
        default_factory=lambda: os.environ.get(
            "CIPHERSECOPS_SERVER_URL", "https://localhost:8443"
        )
    )
    agent_id: str = field(
        default_factory=lambda: os.environ.get(
            "CIPHERSECOPS_AGENT_ID", str(uuid.uuid4())
        )
    )

    # ---- Poll intervals (seconds) -------------------------------------------
    interval_system: int = int(os.environ.get("AGENT_INTERVAL_SYSTEM", "30"))
    interval_network: int = int(os.environ.get("AGENT_INTERVAL_NETWORK", "15"))
    interval_logs: int = int(os.environ.get("AGENT_INTERVAL_LOGS", "60"))
    interval_integrity: int = int(os.environ.get("AGENT_INTERVAL_INTEGRITY", "300"))

    # ---- JWT authentication -------------------------------------------------
    jwt_token: Optional[str] = field(
        default_factory=lambda: os.environ.get("CIPHERSECOPS_JWT_TOKEN")
    )
    jwt_algorithm: str = "HS256"
    jwt_expiry_seconds: int = 3600

    # ---- Telemetry / batching ----------------------------------------------
    batch_size: int = int(os.environ.get("AGENT_BATCH_SIZE", "50"))
    flush_interval: int = int(os.environ.get("AGENT_FLUSH_INTERVAL", "10"))
    max_retries: int = int(os.environ.get("AGENT_MAX_RETRIES", "3"))
    retry_backoff_base: float = 2.0  # seconds; doubles on each retry

    # ---- TLS / HTTPS -------------------------------------------------------
    verify_ssl: bool = os.environ.get("AGENT_VERIFY_SSL", "true").lower() != "false"
    ca_bundle: Optional[str] = os.environ.get("AGENT_CA_BUNDLE")

    # ---- Logging -----------------------------------------------------------
    log_level: str = os.environ.get("AGENT_LOG_LEVEL", "INFO").upper()

    # ---- Integrity checker --------------------------------------------------
    baseline_db_path: str = os.environ.get(
        "AGENT_BASELINE_DB", os.path.join(os.path.dirname(__file__), "baseline_db.json")
    )

    # ---- Platform (read-only convenience) -----------------------------------
    platform: str = field(default_factory=lambda: PLATFORM)

    # ---- WebSocket (future use) ---------------------------------------------
    websocket_url: Optional[str] = field(
        default_factory=lambda: os.environ.get("CIPHERSECOPS_WS_URL")
    )

    def __post_init__(self) -> None:
        numeric_level = getattr(logging, self.log_level, logging.INFO)
        logging.basicConfig(
            level=numeric_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        logger.debug(
            "AgentConfig initialised — platform=%s agent_id=%s server=%s",
            self.platform,
            self.agent_id,
            self.server_url,
        )

    @property
    def auth_headers(self) -> dict:
        """Return HTTP headers carrying the JWT bearer token (if configured)."""
        if self.jwt_token:
            return {"Authorization": f"Bearer {self.jwt_token}"}
        return {}


# ---------------------------------------------------------------------------
# Module-level default instance (can be overridden at startup)
# ---------------------------------------------------------------------------

default_config = AgentConfig()
