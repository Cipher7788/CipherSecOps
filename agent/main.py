"""
Agent entry point — orchestrates all monitors in dedicated threads and ships
telemetry to the CipherSecOps backend.
"""

import logging
import signal
import threading
import time
from dataclasses import asdict
from typing import Any, Callable, List

from agent.config import AgentConfig, default_config
from agent.integrity_checker import IntegrityChecker
from agent.log_collector import LogCollector
from agent.network_monitor import NetworkMonitor
from agent.system_monitor import SystemMonitor
from agent.telemetry_sender import TelemetrySender

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Monitor runner
# ---------------------------------------------------------------------------

class _MonitorThread(threading.Thread):
    """Generic wrapper that runs a collect() callable on a fixed interval."""

    def __init__(
        self,
        name: str,
        collect_fn: Callable[[], List[Any]],
        interval: int,
        sender: TelemetrySender,
        stop_event: threading.Event,
    ) -> None:
        super().__init__(name=name, daemon=True)
        self._collect_fn = collect_fn
        self._interval = interval
        self._sender = sender
        self._stop_event = stop_event

    def run(self) -> None:
        logger.info("Monitor thread started: %s (interval=%ds)", self.name, self._interval)
        while not self._stop_event.is_set():
            try:
                events = self._collect_fn()
                for event in events:
                    # Serialise dataclass → dict before enqueuing
                    try:
                        payload = asdict(event)
                    except TypeError:
                        payload = event  # already a plain dict or primitive
                    payload["monitor"] = self.name
                    self._sender.add_event(payload)
                logger.debug("%s: %d events collected", self.name, len(events))
            except Exception as exc:
                logger.error("Error in monitor %s: %s", self.name, exc, exc_info=True)

            self._stop_event.wait(timeout=self._interval)

        logger.info("Monitor thread stopped: %s", self.name)


# ---------------------------------------------------------------------------
# Agent orchestrator
# ---------------------------------------------------------------------------

class Agent:
    """Top-level agent that wires all monitors together."""

    def __init__(self, config: AgentConfig = default_config) -> None:
        self._config = config
        self._stop_event = threading.Event()
        self._threads: List[threading.Thread] = []

        self._sender = TelemetrySender(
            server_url=config.server_url,
            agent_id=config.agent_id,
            jwt_token=config.jwt_token,
            batch_size=config.batch_size,
            flush_interval=config.flush_interval,
            max_retries=config.max_retries,
            retry_backoff_base=config.retry_backoff_base,
            verify_ssl=config.verify_ssl,
            ca_bundle=config.ca_bundle,
        )

        self._system_monitor = SystemMonitor()
        self._network_monitor = NetworkMonitor()
        self._log_collector = LogCollector()
        self._integrity_checker = IntegrityChecker(db_path=config.baseline_db_path)

    def _register_signals(self) -> None:
        """Install SIGINT/SIGTERM handlers for graceful shutdown."""
        def _handler(signum: int, _frame: Any) -> None:
            logger.info("Signal %d received — initiating graceful shutdown…", signum)
            self.stop()

        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)

    def start(self) -> None:
        """Start all monitor threads and the telemetry sender."""
        logger.info(
            "CipherSecOps Agent starting — id=%s platform=%s server=%s",
            self._config.agent_id,
            self._config.platform,
            self._config.server_url,
        )

        self._register_signals()
        self._sender.start_background_flush()

        monitor_specs = [
            ("system-monitor", self._system_monitor.collect, self._config.interval_system),
            ("network-monitor", self._network_monitor.collect, self._config.interval_network),
            ("log-collector", self._log_collector.collect, self._config.interval_logs),
            ("integrity-checker", self._integrity_checker.check, self._config.interval_integrity),
        ]

        for name, fn, interval in monitor_specs:
            t = _MonitorThread(
                name=name,
                collect_fn=fn,
                interval=interval,
                sender=self._sender,
                stop_event=self._stop_event,
            )
            self._threads.append(t)
            t.start()

        logger.info("All monitor threads started — agent is running")

    def run_forever(self) -> None:
        """Block the main thread until a stop signal is received."""
        self.start()
        try:
            while not self._stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received — shutting down…")
            self.stop()

    def stop(self) -> None:
        """Signal all threads to stop, flush remaining telemetry, and exit."""
        if self._stop_event.is_set():
            return  # already stopping

        logger.info("Stopping CipherSecOps Agent…")
        self._stop_event.set()

        for t in self._threads:
            t.join(timeout=self._config.interval_network + 2)

        self._sender.stop()
        logger.info("CipherSecOps Agent stopped cleanly")

    # Context manager support
    def __enter__(self) -> "Agent":
        self.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point — reads config from environment and runs the agent."""
    config = AgentConfig()
    agent = Agent(config=config)
    agent.run_forever()


if __name__ == "__main__":
    main()
