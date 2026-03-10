"""WebSocket connection manager."""

import json
import logging
from typing import Any, Dict

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self) -> None:
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, client_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(
            "WebSocket client connected: %s (total=%d)", client_id, len(self.active_connections)
        )

    def disconnect(self, client_id: str) -> None:
        self.active_connections.pop(client_id, None)
        logger.info(
            "WebSocket client disconnected: %s (total=%d)", client_id, len(self.active_connections)
        )

    async def send_to_client(self, client_id: str, message: Any) -> None:
        websocket = self.active_connections.get(client_id)
        if websocket is None:
            logger.warning("send_to_client: unknown client %s", client_id)
            return
        try:
            payload = message if isinstance(message, str) else json.dumps(message)
            await websocket.send_text(payload)
        except Exception as exc:
            logger.error("Error sending to client %s: %s", client_id, exc)
            self.disconnect(client_id)

    async def broadcast(self, message: Any) -> None:
        """Send a message to all connected clients."""
        if not self.active_connections:
            return
        payload = message if isinstance(message, str) else json.dumps(message)
        disconnected: list[str] = []
        for client_id, websocket in list(self.active_connections.items()):
            try:
                await websocket.send_text(payload)
            except Exception as exc:
                logger.error("Broadcast error for client %s: %s", client_id, exc)
                disconnected.append(client_id)
        for client_id in disconnected:
            self.disconnect(client_id)


manager = ConnectionManager()
