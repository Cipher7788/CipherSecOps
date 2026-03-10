"""SQLAlchemy ORM models and Pydantic schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from server.database import Base


# ---------------------------------------------------------------------------
# SQLAlchemy ORM Models
# ---------------------------------------------------------------------------


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), unique=True, index=True, nullable=False)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(64), nullable=False)  # windows / linux / macos
    ip_address = Column(String(45), nullable=True)
    status = Column(String(32), default="online", nullable=False)  # online/offline/isolated
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    version = Column(String(32), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    telemetry_events = relationship("TelemetryEvent", back_populates="agent", lazy="select")
    threats = relationship("Threat", back_populates="agent", lazy="select")


class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    severity = Column(String(16), default="info", nullable=False)
    data = Column(JSONB, nullable=False, default={})
    timestamp = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    processed = Column(Boolean, default=False, nullable=False)

    agent = relationship("Agent", back_populates="telemetry_events")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False)  # low/medium/high/critical
    status = Column(String(32), default="open", nullable=False)  # open/investigating/resolved
    mitre_technique = Column(String(16), nullable=True)
    risk_score = Column(Float, default=0.0, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    agent = relationship("Agent", back_populates="threats")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(16), nullable=False)
    status = Column(String(32), default="open", nullable=False)
    affected_agents = Column(JSONB, default=[], nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    trigger = Column(String(64), nullable=False)
    steps = Column(JSONB, default=[], nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AlertRule(Base):
    __tablename__ = "alert_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    condition = Column(Text, nullable=False)
    action = Column(String(64), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------


class AgentRegisterRequest(BaseModel):
    agent_id: str = Field(..., description="Unique agent identifier")
    hostname: str
    platform: str
    ip_address: Optional[str] = None
    version: Optional[str] = None


class AgentResponse(BaseModel):
    id: int
    agent_id: str
    hostname: str
    platform: str
    ip_address: Optional[str]
    status: str
    last_seen: datetime
    version: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class HeartbeatRequest(BaseModel):
    ip_address: Optional[str] = None
    version: Optional[str] = None


class TelemetryEventCreate(BaseModel):
    agent_id: str
    event_type: str
    severity: str = "info"
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class TelemetryEventResponse(BaseModel):
    id: int
    agent_id: str
    event_type: str
    severity: str
    data: Dict[str, Any]
    timestamp: datetime
    processed: bool

    class Config:
        from_attributes = True


class ThreatResponse(BaseModel):
    id: int
    agent_id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    mitre_technique: Optional[str]
    risk_score: float
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ThreatStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|investigating|resolved)$")


class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str
    status: str = "open"
    affected_agents: List[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    affected_agents: Optional[List[str]] = None


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    affected_agents: List[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger: str
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    is_active: bool = True


class PlaybookResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    trigger: str
    steps: List[Dict[str, Any]]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class PlaybookExecuteRequest(BaseModel):
    context: Dict[str, Any] = Field(default_factory=dict)


class AlertRuleCreate(BaseModel):
    name: str
    condition: str
    action: str
    is_active: bool = True


class AlertRuleResponse(BaseModel):
    id: int
    name: str
    condition: str
    action: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
