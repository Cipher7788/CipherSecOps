"""Available playbook actions that can be invoked during automated response."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger(__name__)


async def isolate_endpoint(agent_id: str) -> Dict[str, Any]:
    """
    Send an isolation command to the agent via WebSocket.
    In a full deployment this would also update the agent status in the DB.
    """
    logger.warning("ACTION: Isolating endpoint agent_id=%s", agent_id)
    from server.websocket import manager

    await manager.send_to_client(
        agent_id,
        {"command": "isolate", "agent_id": agent_id,
         "timestamp": datetime.now(timezone.utc).isoformat()},
    )
    return {"action": "isolate_endpoint", "agent_id": agent_id, "status": "sent"}


async def kill_process(agent_id: str, pid: int) -> Dict[str, Any]:
    """Send a kill-process command to the agent."""
    logger.warning("ACTION: Killing process pid=%d on agent_id=%s", pid, agent_id)
    from server.websocket import manager

    await manager.send_to_client(
        agent_id,
        {"command": "kill_process", "pid": pid,
         "timestamp": datetime.now(timezone.utc).isoformat()},
    )
    return {"action": "kill_process", "agent_id": agent_id, "pid": pid, "status": "sent"}


async def alert_soc(message: str, severity: str) -> Dict[str, Any]:
    """Send a SOC alert notification (broadcasts to all dashboard clients)."""
    logger.info("ACTION: SOC alert severity=%s message=%r", severity, message)
    from server.websocket import manager

    await manager.broadcast(
        {
            "type": "soc_alert",
            "severity": severity,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    return {"action": "alert_soc", "severity": severity, "status": "sent"}


async def create_incident_ticket(title: str, description: str, severity: str) -> Dict[str, Any]:
    """Create an incident record directly in the database."""
    logger.info("ACTION: Creating incident ticket title=%r severity=%s", title, severity)
    from server.database import AsyncSessionLocal
    from server.models import Incident

    async with AsyncSessionLocal() as db:
        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            status="open",
            affected_agents=[],
        )
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        incident_id = incident.id

    return {"action": "create_incident_ticket", "incident_id": incident_id, "status": "created"}


async def block_ip(ip: str) -> Dict[str, Any]:
    """
    Add an IP to the platform blocklist and broadcast to all agents.
    In production this would persist to Redis or a DB blocklist table.
    """
    logger.warning("ACTION: Blocking IP %s", ip)
    from server.websocket import manager

    await manager.broadcast(
        {"command": "block_ip", "ip": ip, "timestamp": datetime.now(timezone.utc).isoformat()}
    )
    return {"action": "block_ip", "ip": ip, "status": "broadcasted"}


async def collect_forensics(agent_id: str) -> Dict[str, Any]:
    """Trigger a forensic data collection request on the target agent."""
    logger.info("ACTION: Collecting forensics from agent_id=%s", agent_id)
    from server.websocket import manager

    await manager.send_to_client(
        agent_id,
        {"command": "collect_forensics", "agent_id": agent_id,
         "timestamp": datetime.now(timezone.utc).isoformat()},
    )
    return {"action": "collect_forensics", "agent_id": agent_id, "status": "requested"}
