"""Rule-based AI decision engine for threat assessment and response recommendation."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity and signal weights
# ---------------------------------------------------------------------------

_SEVERITY_SCORES: Dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 5,
}

_EVENT_TYPE_WEIGHTS: Dict[str, float] = {
    "process_create": 1.2,
    "network_connect": 1.1,
    "file_write": 1.0,
    "dns_query": 0.9,
    "auth_failure": 1.3,
    "registry_write": 1.1,
    "module_load": 0.8,
    "default": 1.0,
}

_RISK_LEVEL_ACTIONS: Dict[str, List[str]] = {
    "Critical": ["isolate_endpoint", "collect_forensics", "alert_soc", "create_incident_ticket"],
    "High":     ["collect_forensics", "alert_soc", "create_incident_ticket"],
    "Medium":   ["alert_soc", "create_incident_ticket"],
    "Low":      ["alert_soc"],
}


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ThreatAssessment:
    risk_score: int                        # 0–100
    confidence: float                      # 0.0–1.0
    risk_level: str                        # Low / Medium / High / Critical
    recommended_actions: List[str]
    explanation: str
    assessed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    signal_breakdown: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AIDecisionEngine:
    """
    Correlates multiple telemetry signals using weighted rule-based scoring
    and produces a ThreatAssessment with recommended response actions.
    """

    def correlate_signals(self, events: List[Dict[str, Any]]) -> ThreatAssessment:
        """
        Analyse a list of telemetry event dicts and return a ThreatAssessment.

        Each event dict should contain at minimum:
            - event_type: str
            - severity: str
            - agent_id: str
            - data: dict (optional)
        """
        if not events:
            return ThreatAssessment(
                risk_score=0,
                confidence=0.0,
                risk_level="Low",
                recommended_actions=[],
                explanation="No events provided for analysis.",
            )

        total_weighted_score = 0.0
        total_weight = 0.0
        severity_counts: Dict[str, int] = {}
        event_type_counts: Dict[str, int] = {}
        agent_ids: set = set()

        for event in events:
            sev = str(event.get("severity", "info")).lower()
            etype = str(event.get("event_type", "default")).lower()
            agent_id = event.get("agent_id", "unknown")

            base_score = _SEVERITY_SCORES.get(sev, 5)
            weight = _EVENT_TYPE_WEIGHTS.get(etype, _EVENT_TYPE_WEIGHTS["default"])

            total_weighted_score += base_score * weight
            total_weight += weight

            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            event_type_counts[etype] = event_type_counts.get(etype, 0) + 1
            agent_ids.add(agent_id)

        # Average weighted score normalised to 0–100
        avg_score = (total_weighted_score / total_weight) if total_weight else 0.0

        # Volume bonus: many signals in a short window increase confidence
        volume_multiplier = min(1.5, 1.0 + (len(events) - 1) * 0.05)
        raw_score = avg_score * volume_multiplier

        # Multi-agent bonus: threats spanning multiple agents are more significant
        if len(agent_ids) > 1:
            raw_score *= 1.1

        risk_score = int(min(100, max(0, raw_score)))
        risk_level = self._get_risk_level(risk_score)
        confidence = self._compute_confidence(events, risk_score)
        recommended_actions = _RISK_LEVEL_ACTIONS.get(risk_level, [])
        explanation = self._build_explanation(
            risk_score, risk_level, severity_counts, event_type_counts, agent_ids
        )

        return ThreatAssessment(
            risk_score=risk_score,
            confidence=round(confidence, 2),
            risk_level=risk_level,
            recommended_actions=recommended_actions,
            explanation=explanation,
            signal_breakdown={
                "event_count": len(events),
                "unique_agents": len(agent_ids),
                "severity_counts": severity_counts,
                "event_type_counts": event_type_counts,
            },
        )

    @staticmethod
    def _get_risk_level(score: int) -> str:
        if score >= 85:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 30:
            return "Medium"
        return "Low"

    @staticmethod
    def _compute_confidence(events: List[Dict[str, Any]], risk_score: int) -> float:
        """Confidence is boosted by event volume and high-severity signals."""
        base_confidence = risk_score / 100.0
        # More events → higher confidence, capped at a 20% boost
        volume_boost = min(0.20, len(events) * 0.02)
        # High/critical events further increase confidence
        high_count = sum(1 for e in events if e.get("severity") in {"high", "critical"})
        severity_boost = min(0.15, high_count * 0.05)
        return min(1.0, base_confidence + volume_boost + severity_boost)

    @staticmethod
    def _build_explanation(
        risk_score: int,
        risk_level: str,
        severity_counts: Dict[str, int],
        event_type_counts: Dict[str, int],
        agent_ids: set,
    ) -> str:
        sev_summary = ", ".join(f"{k}={v}" for k, v in sorted(severity_counts.items()))
        top_events = sorted(event_type_counts.items(), key=lambda x: x[1], reverse=True)[:3]
        event_summary = ", ".join(f"{k}({v})" for k, v in top_events)
        agents_str = f"{len(agent_ids)} agent(s)"
        total_events = sum(severity_counts.values())
        return (
            f"Risk level is {risk_level} (score={risk_score}/100) based on {total_events} "
            f"event(s) across {agents_str}. Severity distribution: [{sev_summary}]. "
            f"Top event types: [{event_summary}]."
        )
