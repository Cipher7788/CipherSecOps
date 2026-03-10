"""Tests for agent/network_monitor.py."""

import pytest
from unittest.mock import MagicMock, patch

from agent.network_monitor import (
    NetworkMonitor,
    NetworkEvent,
    SUSPICIOUS_PORTS,
    _HIGH_PORT_THRESHOLD,
    _check_reverse_shell,
    _check_high_port_outbound,
    _evaluate_event,
)


def _make_conn(
    laddr_ip="10.0.0.1",
    laddr_port=54321,
    raddr_ip="8.8.8.8",
    raddr_port=443,
    status="ESTABLISHED",
    pid=None,
):
    """Build a mock psutil connection namedtuple-alike."""
    conn = MagicMock()
    conn.laddr = MagicMock(ip=laddr_ip, port=laddr_port)
    conn.raddr = MagicMock(ip=raddr_ip, port=raddr_port)
    conn.status = status
    conn.pid = pid
    return conn


def test_collect_connections_returns_list():
    """collect() must return a list of NetworkEvent objects."""
    monitor = NetworkMonitor()
    mock_conn = _make_conn()

    with patch("agent.network_monitor.psutil.net_connections", return_value=[mock_conn]), \
         patch("agent.network_monitor._resolve_process_name", return_value="chrome"):
        result = monitor.collect()

    assert isinstance(result, list)
    assert len(result) == 1
    event = result[0]
    assert isinstance(event, NetworkEvent)
    assert event.local_ip == "10.0.0.1"
    assert event.remote_ip == "8.8.8.8"
    assert event.remote_port == 443


def test_reverse_shell_port_flagged():
    """An ESTABLISHED connection to port 4444 from a public IP must be suspicious."""
    assert 4444 in SUSPICIOUS_PORTS, "Port 4444 must be in SUSPICIOUS_PORTS"

    event = NetworkEvent(
        local_ip="10.0.0.1",
        local_port=54321,
        remote_ip="198.18.0.1",   # Not RFC-1918 / not private
        remote_port=4444,
        status="ESTABLISHED",
        pid=None,
        process_name=None,
    )
    is_suspicious, reason = _check_reverse_shell(event)
    assert is_suspicious is True
    assert "4444" in reason


def test_normal_https_not_flagged():
    """A connection to port 443 (HTTPS) must not be flagged as suspicious."""
    assert 443 not in SUSPICIOUS_PORTS, "Port 443 should not be in SUSPICIOUS_PORTS"

    event = NetworkEvent(
        local_ip="10.0.0.1",
        local_port=54321,
        remote_ip="93.184.216.34",
        remote_port=443,
        status="ESTABLISHED",
        pid=None,
        process_name=None,
    )
    is_suspicious, _ = _check_reverse_shell(event)
    assert is_suspicious is False


def test_high_port_flagged():
    """_check_high_port_outbound must flag a port that is both suspicious and high (>=49152)."""
    high_suspicious_port = 49999

    with patch("agent.network_monitor.SUSPICIOUS_PORTS", {high_suspicious_port}):
        event = NetworkEvent(
            local_ip="10.0.0.1",
            local_port=12345,
            remote_ip="1.2.3.4",
            remote_port=high_suspicious_port,
            status="ESTABLISHED",
            pid=None,
            process_name=None,
        )
        is_suspicious, reason = _check_high_port_outbound(event)

    assert is_suspicious is True
    assert str(high_suspicious_port) in reason
