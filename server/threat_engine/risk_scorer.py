"""Risk scoring for detected threats."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from server.threat_engine.rules import Rule

logger = logging.getLogger(__name__)

# Severity → base weight
_SEVERITY_WEIGHTS: Dict[str, int] = {
    "low": 10,
    "medium": 30,
    "high": 60,
    "critical": 90,
}

_RISK_LEVELS = [
    (85, "Critical"),
    (60, "High"),
    (30, "Medium"),
    (0,  "Low"),
]


class RiskScorer:
    """Computes a normalised risk score (0–100) for a threat detection."""

    def __init__(self, agent_reputation: Dict[str, float] | None = None) -> None:
        # agent_reputation maps agent_id → reputation multiplier (0.5–1.5).
        # A lower reputation means a higher-risk agent.
        self._agent_reputation: Dict[str, float] = agent_reputation or {}

    def score(self, event: Dict[str, Any], matched_rules: List[Rule]) -> int:
        """Return a risk score in [0, 100]."""
        if not matched_rules:
            return 0

        # --- Base score from highest-severity matched rule ---
        max_severity_weight = max(
            _SEVERITY_WEIGHTS.get(r.severity, 10) for r in matched_rules
        )

        # --- Bonus for multiple rule matches (each extra rule adds 5 pts, capped at 20) ---
        multi_rule_bonus = min((len(matched_rules) - 1) * 5, 20)

        # --- Recency bonus: events within last 60 s get +10 ---
        ts_raw = event.get("timestamp")
        recency_bonus = 0
        if ts_raw:
            try:
                if isinstance(ts_raw, str):
                    ts = datetime.fromisoformat(ts_raw)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                elif isinstance(ts_raw, datetime):
                    ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=timezone.utc)
                else:
                    ts = None
                if ts and (datetime.now(timezone.utc) - ts) < timedelta(seconds=60):
                    recency_bonus = 10
            except Exception:
                pass

        # --- Agent reputation penalty ---
        agent_id = event.get("agent_id", "")
        reputation = self._agent_reputation.get(agent_id, 1.0)
        reputation_multiplier = max(0.5, min(1.5, 2.0 - reputation))

        raw = (max_severity_weight + multi_rule_bonus + recency_bonus) * reputation_multiplier
        final = int(min(100, max(0, raw)))
        logger.debug(
            "Risk score for agent=%s: base=%d multi=%d recency=%d rep=%.2f → %d",
            agent_id, max_severity_weight, multi_rule_bonus, recency_bonus, reputation_multiplier, final,
        )
        return final

    @staticmethod
    def get_risk_level(score: int) -> str:
        """Translate a numeric score into a human-readable risk level."""
        for threshold, label in _RISK_LEVELS:
            if score >= threshold:
                return label
        return "Low"

    def update_agent_reputation(self, agent_id: str, reputation: float) -> None:
        """Set reputation score for an agent (0.0 = untrusted, 1.0 = trusted)."""
        self._agent_reputation[agent_id] = max(0.0, min(1.0, reputation))
