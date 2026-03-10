"""Tests for server FastAPI endpoints (server/main.py and routers)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _make_test_client():
    """Build a TestClient with DB and lifespan mocked out."""
    from server.main import app
    from server.database import get_db

    async def _mock_db():
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 0
        mock_result.scalar_one_or_none.return_value = None
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)
        yield mock_db

    app.dependency_overrides[get_db] = _mock_db

    patcher_init = patch("server.database.init_db", new_callable=AsyncMock)
    patcher_close = patch("server.database.close_db", new_callable=AsyncMock)

    patcher_init.start()
    patcher_close.start()
    client = TestClient(app, raise_server_exceptions=True)
    # Enter the client context to trigger lifespan startup
    client.__enter__()
    return client, patcher_init, patcher_close


@pytest.fixture
def api_client():
    """Provide a TestClient and clean up after the test."""
    from server.main import app
    from server.database import get_db

    async def _mock_db():
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = 0
        mock_result.scalar_one_or_none.return_value = None
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=mock_result)
        yield mock_db

    app.dependency_overrides[get_db] = _mock_db

    with patch("server.main.init_db", new_callable=AsyncMock), \
         patch("server.main.close_db", new_callable=AsyncMock):
        with TestClient(app) as c:
            yield c

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def test_health_check(api_client):
    """GET /health must return 200 with status=healthy."""
    response = api_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "app" in data


def test_health_check_app_name(api_client):
    """GET /health must include the CipherSecOps app name."""
    response = api_client.get("/health")
    data = response.json()
    assert data["app"] == "CipherSecOps"


# ---------------------------------------------------------------------------
# Dashboard stats
# ---------------------------------------------------------------------------

def test_dashboard_stats_returns_data(api_client):
    """GET /dashboard/stats must return a response with the expected top-level keys."""
    response = api_client.get("/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert "agents" in data
    assert "threats" in data
    assert "risk_score" in data
    assert "events_last_24h" in data


def test_dashboard_stats_agents_shape(api_client):
    """The 'agents' section of /dashboard/stats must contain the required sub-keys."""
    response = api_client.get("/dashboard/stats")
    data = response.json()
    agents = data["agents"]
    for key in ("total", "active", "isolated", "offline"):
        assert key in agents, f"Missing key '{key}' in agents section"


def test_dashboard_stats_threats_shape(api_client):
    """The 'threats' section of /dashboard/stats must contain the required sub-keys."""
    response = api_client.get("/dashboard/stats")
    data = response.json()
    threats = data["threats"]
    for key in ("total", "open", "critical"):
        assert key in threats, f"Missing key '{key}' in threats section"


def test_dashboard_stats_numeric_types(api_client):
    """Numeric fields in /dashboard/stats must be of the correct Python types."""
    response = api_client.get("/dashboard/stats")
    data = response.json()
    assert isinstance(data["risk_score"], (int, float))
    assert isinstance(data["events_last_24h"], int)
    assert isinstance(data["agents"]["total"], int)
    assert isinstance(data["threats"]["total"], int)
