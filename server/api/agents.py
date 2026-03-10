"""Agents API router."""

import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import (
    Agent,
    AgentRegisterRequest,
    AgentResponse,
    HeartbeatRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/register", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(payload: AgentRegisterRequest, db: AsyncSession = Depends(get_db)):
    """Register a new agent or update an existing one."""
    result = await db.execute(select(Agent).where(Agent.agent_id == payload.agent_id))
    existing = result.scalar_one_or_none()

    if existing:
        # Re-registration: update fields and mark online
        existing.hostname = payload.hostname
        existing.platform = payload.platform
        existing.ip_address = payload.ip_address
        existing.version = payload.version
        existing.status = "online"
        existing.last_seen = datetime.now(timezone.utc)
        await db.flush()
        logger.info("Agent re-registered: %s", payload.agent_id)
        return existing

    agent = Agent(
        agent_id=payload.agent_id,
        hostname=payload.hostname,
        platform=payload.platform,
        ip_address=payload.ip_address,
        version=payload.version,
        status="online",
        last_seen=datetime.now(timezone.utc),
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    logger.info("New agent registered: %s (%s)", payload.agent_id, payload.hostname)
    return agent


@router.post("/{agent_id}/heartbeat", response_model=AgentResponse)
async def agent_heartbeat(
    agent_id: str,
    payload: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    """Update agent last_seen timestamp and optionally refresh IP/version."""
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    agent.last_seen = datetime.now(timezone.utc)
    agent.status = "online"
    if payload.ip_address:
        agent.ip_address = payload.ip_address
    if payload.version:
        agent.version = payload.version

    await db.flush()
    await db.refresh(agent)
    return agent


@router.get("", response_model=List[AgentResponse])
async def list_agents(
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    db: AsyncSession = Depends(get_db),
):
    """List all registered agents."""
    query = select(Agent).offset(skip).limit(limit).order_by(Agent.last_seen.desc())
    if status:
        query = query.where(Agent.status == status)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Get details of a specific agent."""
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deregister_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Deregister (soft-delete) an agent by marking it offline."""
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    agent.status = "offline"
    await db.flush()
    logger.info("Agent deregistered: %s", agent_id)
