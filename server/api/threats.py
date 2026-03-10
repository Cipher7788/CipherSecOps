"""Threats API router."""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Threat, ThreatResponse, ThreatStatusUpdate

logger = logging.getLogger(__name__)
router = APIRouter()

_VALID_STATUSES = {"open", "investigating", "resolved"}


@router.get("/stats")
async def threat_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Return aggregated threat statistics."""
    total_result = await db.execute(select(func.count(Threat.id)))
    total = total_result.scalar_one()

    open_result = await db.execute(
        select(func.count(Threat.id)).where(Threat.status == "open")
    )
    open_count = open_result.scalar_one()

    critical_result = await db.execute(
        select(func.count(Threat.id)).where(Threat.severity == "critical")
    )
    critical_count = critical_result.scalar_one()

    avg_risk_result = await db.execute(select(func.avg(Threat.risk_score)))
    avg_risk = avg_risk_result.scalar_one() or 0.0

    severity_rows = await db.execute(
        select(Threat.severity, func.count(Threat.id)).group_by(Threat.severity)
    )
    severity_breakdown: Dict[str, int] = {row[0]: row[1] for row in severity_rows}

    return {
        "total": total,
        "open": open_count,
        "critical": critical_count,
        "avg_risk_score": round(float(avg_risk), 2),
        "by_severity": severity_breakdown,
    }


@router.get("", response_model=List[ThreatResponse])
async def list_threats(
    agent_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List threats with optional filtering and pagination."""
    query = (
        select(Threat)
        .offset(skip)
        .limit(limit)
        .order_by(Threat.created_at.desc())
    )
    if agent_id:
        query = query.where(Threat.agent_id == agent_id)
    if severity:
        query = query.where(Threat.severity == severity)
    if status:
        query = query.where(Threat.status == status)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{threat_id}", response_model=ThreatResponse)
async def get_threat(threat_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific threat by ID."""
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if threat is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")
    return threat


@router.patch("/{threat_id}/status", response_model=ThreatResponse)
async def update_threat_status(
    threat_id: int,
    payload: ThreatStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update the status of a threat (open → investigating → resolved)."""
    if payload.status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid status. Choose from: {_VALID_STATUSES}",
        )
    result = await db.execute(select(Threat).where(Threat.id == threat_id))
    threat = result.scalar_one_or_none()
    if threat is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")

    threat.status = payload.status
    await db.flush()
    await db.refresh(threat)
    logger.info("Threat %d status updated to %s", threat_id, payload.status)
    return threat
