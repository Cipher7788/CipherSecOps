"""Core threat analyzer."""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from server.threat_engine.risk_scorer import RiskScorer
from server.threat_engine.rules import Rule, match_rules

logger = logging.getLogger(__name__)


@dataclass
class ThreatDetection:
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: Optional[str]
    risk_score: int
    risk_level: str
    description: str
    agent_id: str
    event_type: str
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatAnalyzer:
    """Orchestrates rule matching, risk scoring, DB persistence and playbook triggering."""

    def __init__(self) -> None:
        self._scorer = RiskScorer()

    async def analyze(
        self, event: Any, db: AsyncSession
    ) -> List[ThreatDetection]:
        """
        Analyse a TelemetryEvent ORM object.
        Returns a list of ThreatDetection instances (one per matched rule).
        """
        event_dict: Dict[str, Any] = {
            "event_type": event.event_type,
            "severity": event.severity,
            "agent_id": event.agent_id,
            "timestamp": event.timestamp,
            "data": event.data or {},
        }
        # Flatten data fields into top-level for rule conditions
        event_dict.update(event.data or {})

        matched_rules: List[Rule] = match_rules(event_dict)
        if not matched_rules:
            return []

        detections: List[ThreatDetection] = []
        for rule in matched_rules:
            risk_score = self._scorer.score(event_dict, [rule])
            risk_level = RiskScorer.get_risk_level(risk_score)

            detection = ThreatDetection(
                rule_id=rule.id,
                rule_name=rule.name,
                severity=rule.severity,
                mitre_technique=rule.mitre_technique,
                risk_score=risk_score,
                risk_level=risk_level,
                description=rule.description,
                agent_id=event.agent_id,
                event_type=event.event_type,
                tags=rule.tags,
            )
            detections.append(detection)

            await self._persist_threat(detection, db)
            await self._trigger_playbook(detection)

        logger.info(
            "Analyzed event id=%s agent=%s: %d threats detected",
            getattr(event, "id", "?"),
            event.agent_id,
            len(detections),
        )
        return detections

    async def _persist_threat(self, detection: ThreatDetection, db: AsyncSession) -> None:
        """Write a Threat record to the database."""
        from server.models import Threat

        threat = Threat(
            agent_id=detection.agent_id,
            title=detection.rule_name,
            description=detection.description,
            severity=detection.severity,
            status="open",
            mitre_technique=detection.mitre_technique,
            risk_score=float(detection.risk_score),
        )
        db.add(threat)
        await db.flush()
        logger.debug(
            "Threat persisted: rule=%s agent=%s score=%d",
            detection.rule_id, detection.agent_id, detection.risk_score,
        )

    async def _trigger_playbook(self, detection: ThreatDetection) -> None:
        """Trigger an automated playbook response if a template is available."""
        try:
            from server.playbooks.engine import PlaybookEngine

            engine = PlaybookEngine()
            playbook_map = {
                "Reverse Shell Detected": "reverse_shell",
                "Brute Force Login Attempt": "brute_force",
                "File Integrity Violation": "file_integrity",
                "Crypto Miner Activity": "crypto_miner",
            }
            template_name = playbook_map.get(detection.rule_name)
            if template_name:
                context = {
                    "agent_id": detection.agent_id,
                    "severity": detection.severity,
                    "risk_score": detection.risk_score,
                    "rule_id": detection.rule_id,
                }
                await engine.execute(template_name, context)
                logger.info(
                    "Playbook '%s' triggered for agent=%s", template_name, detection.agent_id
                )
        except Exception as exc:
            logger.error("Playbook trigger failed: %s", exc, exc_info=True)
