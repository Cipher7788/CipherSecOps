"""Playbooks API router."""

import logging
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import (
    Playbook,
    PlaybookCreate,
    PlaybookExecuteRequest,
    PlaybookResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("", response_model=List[PlaybookResponse])
async def list_playbooks(
    is_active: bool = None,
    db: AsyncSession = Depends(get_db),
):
    """List all playbooks."""
    query = select(Playbook).order_by(Playbook.id)
    if is_active is not None:
        query = query.where(Playbook.is_active == is_active)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("", response_model=PlaybookResponse, status_code=status.HTTP_201_CREATED)
async def create_playbook(payload: PlaybookCreate, db: AsyncSession = Depends(get_db)):
    """Create a new playbook."""
    playbook = Playbook(
        name=payload.name,
        description=payload.description,
        trigger=payload.trigger,
        steps=payload.steps,
        is_active=payload.is_active,
    )
    db.add(playbook)
    await db.flush()
    await db.refresh(playbook)
    logger.info("Playbook created: id=%d name=%r", playbook.id, playbook.name)
    return playbook


@router.get("/{playbook_id}", response_model=PlaybookResponse)
async def get_playbook(playbook_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific playbook."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    return playbook


@router.post("/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: int,
    payload: PlaybookExecuteRequest,
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Trigger execution of a playbook with the provided context."""
    result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    playbook = result.scalar_one_or_none()
    if playbook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Playbook not found")
    if not playbook.is_active:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Playbook is inactive and cannot be executed",
        )

    from server.playbooks.engine import PlaybookEngine

    engine = PlaybookEngine()
    execution_result = await engine.execute_steps(playbook.steps, payload.context)
    logger.info("Playbook %d (%s) executed: %s", playbook_id, playbook.name, execution_result.get("status"))
    return {"playbook_id": playbook_id, "playbook_name": playbook.name, **execution_result}
