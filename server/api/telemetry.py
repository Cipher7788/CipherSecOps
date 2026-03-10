"""Telemetry ingestion API router."""

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import TelemetryEvent, TelemetryEventCreate, TelemetryEventResponse

logger = logging.getLogger(__name__)
router = APIRouter()


async def _run_threat_analysis(event_ids: List[int], db_session_factory) -> None:
    """Background task: analyse newly ingested events for threats."""
    try:
        from server.threat_engine.analyzer import ThreatAnalyzer

        analyzer = ThreatAnalyzer()
        async with db_session_factory() as db:
            result = await db.execute(
                select(TelemetryEvent).where(TelemetryEvent.id.in_(event_ids))
            )
            events = result.scalars().all()
            for event in events:
                threats = await analyzer.analyze(event, db)
                logger.info(
                    "Threat analysis: event_id=%d produced %d detections",
                    event.id,
                    len(threats),
                )
                event.processed = True
            await db.commit()
    except Exception as exc:
        logger.error("Background threat analysis failed: %s", exc, exc_info=True)


@router.post("", response_model=TelemetryEventResponse, status_code=status.HTTP_201_CREATED)
async def ingest_event(
    payload: TelemetryEventCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a single telemetry event and queue it for threat analysis."""
    event = TelemetryEvent(
        agent_id=payload.agent_id,
        event_type=payload.event_type,
        severity=payload.severity,
        data=payload.data,
        timestamp=payload.timestamp or datetime.now(timezone.utc),
        processed=False,
    )
    db.add(event)
    await db.flush()
    await db.refresh(event)

    from server.database import AsyncSessionLocal

    background_tasks.add_task(_run_threat_analysis, [event.id], AsyncSessionLocal)
    logger.debug(
        "Ingested event id=%d type=%s agent=%s", event.id, payload.event_type, payload.agent_id
    )
    return event


@router.post(
    "/batch", response_model=List[TelemetryEventResponse], status_code=status.HTTP_201_CREATED
)
async def ingest_batch(
    payload: List[TelemetryEventCreate],
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Ingest a batch of telemetry events."""
    if not payload:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty batch")
    if len(payload) > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Batch size exceeds 1000"
        )

    events = [
        TelemetryEvent(
            agent_id=e.agent_id,
            event_type=e.event_type,
            severity=e.severity,
            data=e.data,
            timestamp=e.timestamp or datetime.now(timezone.utc),
            processed=False,
        )
        for e in payload
    ]
    db.add_all(events)
    await db.flush()
    for evt in events:
        await db.refresh(evt)

    event_ids = [e.id for e in events]
    from server.database import AsyncSessionLocal

    background_tasks.add_task(_run_threat_analysis, event_ids, AsyncSessionLocal)
    logger.info("Batch ingested: %d events", len(events))
    return events


@router.get("", response_model=List[TelemetryEventResponse])
async def list_events(
    agent_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    processed: Optional[bool] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=1000),
    db: AsyncSession = Depends(get_db),
):
    """List telemetry events with optional filtering."""
    query = (
        select(TelemetryEvent)
        .offset(skip)
        .limit(limit)
        .order_by(TelemetryEvent.timestamp.desc())
    )
    if agent_id:
        query = query.where(TelemetryEvent.agent_id == agent_id)
    if event_type:
        query = query.where(TelemetryEvent.event_type == event_type)
    if severity:
        query = query.where(TelemetryEvent.severity == severity)
    if processed is not None:
        query = query.where(TelemetryEvent.processed == processed)

    result = await db.execute(query)
    return result.scalars().all()
