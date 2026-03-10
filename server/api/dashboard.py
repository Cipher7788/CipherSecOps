"""Dashboard summary API router."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Agent, TelemetryEvent, Threat

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Return high-level platform statistics for the dashboard."""
    total_agents = (await db.execute(select(func.count(Agent.id)))).scalar_one()
    active_agents = (
        await db.execute(select(func.count(Agent.id)).where(Agent.status == "online"))
    ).scalar_one()
    isolated_agents = (
        await db.execute(select(func.count(Agent.id)).where(Agent.status == "isolated"))
    ).scalar_one()

    total_threats = (await db.execute(select(func.count(Threat.id)))).scalar_one()
    open_threats = (
        await db.execute(select(func.count(Threat.id)).where(Threat.status == "open"))
    ).scalar_one()
    critical_threats = (
        await db.execute(
            select(func.count(Threat.id)).where(
                Threat.severity == "critical", Threat.status == "open"
            )
        )
    ).scalar_one()

    avg_risk = (await db.execute(select(func.avg(Threat.risk_score)))).scalar_one() or 0.0

    # Events in last 24 h
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    events_24h = (
        await db.execute(
            select(func.count(TelemetryEvent.id)).where(TelemetryEvent.timestamp >= since)
        )
    ).scalar_one()

    return {
        "agents": {
            "total": total_agents,
            "active": active_agents,
            "isolated": isolated_agents,
            "offline": total_agents - active_agents - isolated_agents,
        },
        "threats": {
            "total": total_threats,
            "open": open_threats,
            "critical": critical_threats,
        },
        "risk_score": round(float(avg_risk), 1),
        "events_last_24h": events_24h,
    }


@router.get("/timeline")
async def timeline(
    hours: int = Query(24, ge=1, le=168),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return recent telemetry events for timeline display."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    result = await db.execute(
        select(TelemetryEvent)
        .where(TelemetryEvent.timestamp >= since)
        .order_by(TelemetryEvent.timestamp.desc())
        .limit(200)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "agent_id": e.agent_id,
            "event_type": e.event_type,
            "severity": e.severity,
            "timestamp": e.timestamp.isoformat(),
        }
        for e in events
    ]


@router.get("/threat-map")
async def threat_map(db: AsyncSession = Depends(get_db)) -> List[Dict[str, Any]]:
    """Return geographic threat distribution (placeholder — enriched by threat intel)."""
    result = await db.execute(
        select(Agent.ip_address, func.count(Threat.id).label("threat_count"))
        .join(Threat, Agent.agent_id == Threat.agent_id, isouter=True)
        .where(Agent.ip_address.isnot(None))
        .group_by(Agent.ip_address)
        .limit(100)
    )
    rows = result.all()
    return [
        {
            "ip": row.ip_address,
            "threat_count": row.threat_count or 0,
            # Geo coordinates would be resolved by threat-intel enrichment layer
            "lat": None,
            "lon": None,
        }
        for row in rows
    ]


@router.get("/top-threats")
async def top_threats(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return the most frequently occurring threat types."""
    result = await db.execute(
        select(Threat.title, func.count(Threat.id).label("count"), func.avg(Threat.risk_score).label("avg_risk"))
        .group_by(Threat.title)
        .order_by(func.count(Threat.id).desc())
        .limit(limit)
    )
    rows = result.all()
    return [
        {
            "title": row.title,
            "count": row.count,
            "avg_risk_score": round(float(row.avg_risk or 0), 2),
        }
        for row in rows
    ]
