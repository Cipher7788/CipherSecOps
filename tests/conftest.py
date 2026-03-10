"""Shared pytest fixtures for the CipherSecOps test suite."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock


@pytest.fixture
def mock_agent_config():
    """Mock AgentConfig with sane test defaults."""
    config = MagicMock()
    config.agent_id = "test-agent-001"
    config.server_url = "http://localhost:8443"
    config.jwt_token = "test-token"
    config.interval_system = 30
    config.interval_network = 15
    config.interval_logs = 60
    config.interval_integrity = 300
    config.batch_size = 50
    config.flush_interval = 10
    config.verify_ssl = False
    return config


@pytest.fixture
def mock_telemetry_event():
    """Generic telemetry event dict for testing rule matching."""
    return {
        "agent_id": "test-agent-001",
        "event_type": "process_create",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "pid": 1234,
            "process_name": "cmd.exe",
            "parent_process": "word.exe",
            "cmdline": "cmd.exe /c whoami",
        },
    }


@pytest.fixture
def mock_process_event():
    """Process event representing a suspicious python → powershell spawn."""
    return {
        "agent_id": "test-agent-001",
        "event_type": "process_create",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "pid": 5678,
            "process_name": "powershell.exe",
            "parent_process": "python.exe",
            "cmdline": "powershell.exe -Command Get-Process",
        },
    }


@pytest.fixture
def mock_network_event():
    """Network event for a suspected reverse shell connection."""
    return {
        "agent_id": "test-agent-001",
        "event_type": "network_connect",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "local_ip": "10.0.0.1",
            "local_port": 54321,
            "remote_ip": "203.0.113.5",
            "remote_port": 4444,
            "status": "ESTABLISHED",
            "process_name": "bash",
        },
    }


@pytest.fixture
def client():
    """Synchronous FastAPI TestClient with mocked database dependency."""
    from unittest.mock import patch
    from fastapi.testclient import TestClient
    from server.main import app
    from server.database import get_db

    async def mock_get_db():
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 0
        mock_result.scalar_one_or_none.return_value = None
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)
        yield mock_db

    app.dependency_overrides[get_db] = mock_get_db

    with patch("server.main.init_db", new_callable=AsyncMock), \
         patch("server.main.close_db", new_callable=AsyncMock):
        with TestClient(app) as test_client:
            yield test_client

    app.dependency_overrides.clear()
