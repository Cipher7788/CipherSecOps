"""
Telemetry sender — batches security events and ships them to the CipherSecOps
backend over HTTPS with JWT auth and exponential-backoff retry logic.
"""

import dataclasses
import json
import logging
import queue
import threading
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import requests
    from requests import Session
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as exc:  # pragma: no cover
    raise ImportError("requests is required: pip install requests") from exc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JSON serialisation helper
# ---------------------------------------------------------------------------

class _AgentEncoder(json.JSONEncoder):
    """Serialise dataclasses, datetimes, and sets that the default encoder misses."""

    def default(self, obj: Any) -> Any:
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)


def _to_json(obj: Any) -> str:
    return json.dumps(obj, cls=_AgentEncoder)


# ---------------------------------------------------------------------------
# Payload envelope
# ---------------------------------------------------------------------------

def _make_envelope(agent_id: str, events: List[Any]) -> Dict[str, Any]:
    return {
        "agent_id": agent_id,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "events": events,
    }


# ---------------------------------------------------------------------------
# HTTP session with built-in retry (transport level)
# ---------------------------------------------------------------------------

def _build_session(verify_ssl: bool = True, ca_bundle: Optional[str] = None) -> Session:
    """Create a requests.Session pre-configured with connection-level retries."""
    session = Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    ssl_param: Any = ca_bundle if ca_bundle else verify_ssl
    session.verify = ssl_param
    return session


# ---------------------------------------------------------------------------
# TelemetrySender
# ---------------------------------------------------------------------------

class TelemetrySender:
    """
    Thread-safe telemetry sender.

    Usage
    -----
    sender = TelemetrySender(config)
    sender.add_event(event_obj)       # enqueue from any thread
    sender.flush()                    # force-send current queue
    sender.start_background_flush()   # auto-flush every flush_interval s
    sender.stop()                     # graceful shutdown
    """

    def __init__(
        self,
        server_url: str,
        agent_id: str,
        jwt_token: Optional[str] = None,
        batch_size: int = 50,
        flush_interval: int = 10,
        max_retries: int = 3,
        retry_backoff_base: float = 2.0,
        verify_ssl: bool = True,
        ca_bundle: Optional[str] = None,
    ) -> None:
        self._server_url = server_url.rstrip("/")
        self._agent_id = agent_id
        self._jwt_token = jwt_token
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_retries = max_retries
        self._retry_backoff_base = retry_backoff_base

        self._queue: queue.Queue = queue.Queue()
        self._session = _build_session(verify_ssl, ca_bundle)
        self._lock = threading.Lock()

        self._stop_event = threading.Event()
        self._flush_thread: Optional[threading.Thread] = None

        logger.info(
            "TelemetrySender initialised — server=%s agent=%s batch=%d",
            self._server_url,
            self._agent_id,
            self._batch_size,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self._jwt_token:
            headers["Authorization"] = f"Bearer {self._jwt_token}"
        return headers

    def set_token(self, token: str) -> None:
        """Update the JWT bearer token at runtime (e.g. after refresh)."""
        self._jwt_token = token

    def add_event(self, event: Any) -> None:
        """Enqueue a single event for batched transmission."""
        self._queue.put(event)
        logger.debug("Event enqueued — queue size≈%d", self._queue.qsize())
        if self._queue.qsize() >= self._batch_size:
            # Trigger an immediate flush in a daemon thread so the caller isn't blocked
            threading.Thread(target=self.flush, daemon=True).start()

    def flush(self) -> bool:
        """
        Drain the queue in batches and send to the server.

        Returns True if all batches were sent successfully, False otherwise.
        """
        with self._lock:
            batch: List[Any] = []
            success = True
            while not self._queue.empty():
                try:
                    batch.append(self._queue.get_nowait())
                except queue.Empty:
                    break
                if len(batch) >= self._batch_size:
                    if not self.send_batch(batch):
                        success = False
                    batch = []

            if batch:
                if not self.send_batch(batch):
                    success = False

            return success

    def send_batch(self, events: List[Any]) -> bool:
        """
        POST a batch of events to the server with exponential backoff retry.

        Returns True on success, False if all retries exhausted.
        """
        if not events:
            return True

        endpoint = f"{self._server_url}/api/v1/telemetry"
        payload = _to_json(_make_envelope(self._agent_id, events))

        for attempt in range(1, self._max_retries + 1):
            try:
                response = self._session.post(
                    endpoint,
                    data=payload,
                    headers=self.auth_headers,
                    timeout=15,
                )
                if response.status_code in (200, 201, 202, 204):
                    logger.info(
                        "Batch of %d events sent — HTTP %d (attempt %d)",
                        len(events),
                        response.status_code,
                        attempt,
                    )
                    return True

                logger.warning(
                    "Server returned HTTP %d for batch (attempt %d/%d)",
                    response.status_code,
                    attempt,
                    self._max_retries,
                )

            except requests.exceptions.SSLError as exc:
                logger.error("SSL error sending telemetry: %s", exc)
                return False  # Don't retry on SSL errors — configuration issue

            except requests.exceptions.ConnectionError as exc:
                logger.warning(
                    "Connection error (attempt %d/%d): %s", attempt, self._max_retries, exc
                )

            except requests.exceptions.Timeout:
                logger.warning("Timeout (attempt %d/%d)", attempt, self._max_retries)

            except requests.exceptions.RequestException as exc:
                logger.error("Unexpected request error: %s", exc)

            if attempt < self._max_retries:
                backoff = self._retry_backoff_base ** attempt
                logger.debug("Retrying in %.1f s…", backoff)
                time.sleep(backoff)

        logger.error(
            "Failed to send batch of %d events after %d attempts — events discarded",
            len(events),
            self._max_retries,
        )
        return False

    # ------------------------------------------------------------------
    # Background flush thread
    # ------------------------------------------------------------------

    def start_background_flush(self) -> None:
        """Start a daemon thread that flushes the queue every flush_interval seconds."""
        if self._flush_thread and self._flush_thread.is_alive():
            return
        self._stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._flush_loop, name="telemetry-flusher", daemon=True
        )
        self._flush_thread.start()
        logger.info("Background flush thread started — interval=%ds", self._flush_interval)

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the background flush thread to stop and wait for it to finish."""
        self._stop_event.set()
        if self._flush_thread:
            self._flush_thread.join(timeout=timeout)
        # Final flush of any remaining events
        self.flush()
        logger.info("TelemetrySender stopped")

    def _flush_loop(self) -> None:
        while not self._stop_event.wait(timeout=self._flush_interval):
            try:
                self.flush()
            except Exception as exc:
                logger.error("Unexpected error in flush loop: %s", exc)

    # ------------------------------------------------------------------
    # WebSocket stub (future implementation)
    # ------------------------------------------------------------------

    def connect_websocket(self) -> None:
        """
        Stub for future WebSocket streaming support.

        Implementation will use websocket-client or websockets library to
        establish a persistent bidirectional channel to the backend for
        real-time command & control and low-latency telemetry streaming.
        """
        logger.info("WebSocket support is not yet implemented — using HTTP batch mode")

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "TelemetrySender":
        self.start_background_flush()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()
