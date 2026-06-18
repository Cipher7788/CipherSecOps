"""FastAPI application entry point."""

import logging
import logging.config
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from server.config import settings
from server.database import close_db, init_db
from server.websocket import manager

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CipherSecOps server v%s", settings.APP_VERSION)
    await init_db()
    yield
    logger.info("Shutting down CipherSecOps server")
    await close_db()


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Cross-Platform Autonomous Security Monitoring & Response Platform. "
        "Mini EDR/XDR with real-time threat detection, automated response, and MITRE ATT&CK mapping."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

from server.api.agents import router as agents_router
from server.api.dashboard import router as dashboard_router
from server.api.incidents import router as incidents_router
from server.api.playbooks import router as playbooks_router
from server.api.telemetry import router as telemetry_router
from server.api.threats import router as threats_router

app.include_router(agents_router, prefix="/agents", tags=["Agents"])
app.include_router(telemetry_router, prefix="/telemetry", tags=["Telemetry"])
app.include_router(threats_router, prefix="/threats", tags=["Threats"])
app.include_router(incidents_router, prefix="/incidents", tags=["Incidents"])
app.include_router(playbooks_router, prefix="/playbooks", tags=["Playbooks"])
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])


# ---------------------------------------------------------------------------
# Core endpoints
# ---------------------------------------------------------------------------


@app.get("/health", tags=["Health"])
async def health_check():
    """Liveness probe."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """Real-time event stream for connected dashboards and agents."""
    await manager.connect(client_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            logger.debug("WS message from %s: %s", client_id, data)
            # Echo back acknowledgement
            await manager.send_to_client(client_id, {"ack": True, "received": data})
    except WebSocketDisconnect:
        try:
            await manager.disconnect(client_id)
        except Exception:
            logger.exception("Error during websocket disconnect for client %s", client_id)
        logger.info("WebSocket client %s disconnected", client_id)
