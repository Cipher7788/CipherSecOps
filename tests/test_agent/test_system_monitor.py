"""Tests for agent/system_monitor.py."""

import pytest
import psutil
from unittest.mock import MagicMock, patch

from agent.system_monitor import SystemMonitor, ProcessInfo, _check_suspicious


def _make_proc_info(**overrides) -> ProcessInfo:
    """Helper to build a ProcessInfo with sensible defaults."""
    defaults = dict(
        pid=1234,
        name="chrome",
        exe="/usr/bin/chrome",
        cmdline=["chrome", "--new-window"],
        cpu_percent=2.0,
        memory_percent=1.0,
        status="running",
        username="user",
        ppid=1,
        parent_name="systemd",
    )
    defaults.update(overrides)
    return ProcessInfo(**defaults)


def test_collect_processes_returns_list():
    """collect() must return a list of ProcessInfo objects."""
    monitor = SystemMonitor()

    mock_proc = MagicMock()
    mock_proc.info = {
        "pid": 1234,
        "name": "chrome",
        "exe": "/usr/bin/chrome",
        "cmdline": ["chrome", "--no-sandbox"],
        "cpu_percent": 5.0,
        "memory_percent": 2.0,
        "status": "running",
        "username": "user",
        "ppid": 1,
    }

    mock_parent = MagicMock()
    mock_parent.name.return_value = "systemd"

    with patch("agent.system_monitor.psutil.process_iter", return_value=[mock_proc]), \
         patch("agent.system_monitor.psutil.Process", return_value=mock_parent):
        result = monitor.collect()

    assert isinstance(result, list)
    assert len(result) == 1
    pi = result[0]
    assert isinstance(pi, ProcessInfo)
    assert pi.name == "chrome"
    assert pi.pid == 1234
    assert pi.parent_name == "systemd"


def test_suspicious_process_python_spawning_powershell():
    """python → powershell.exe spawn must be flagged as suspicious."""
    proc = _make_proc_info(
        name="powershell.exe",
        cmdline=["powershell.exe", "-Command", "Get-Process"],
        parent_name="python",
    )
    is_suspicious, reason = _check_suspicious(proc)
    assert is_suspicious is True
    assert reason != ""
    # Reason should reference both the parent and the child process names
    assert "python" in reason.lower() or "powershell" in reason.lower()


def test_normal_process_not_flagged():
    """A regular chrome process spawned from explorer must not be suspicious."""
    proc = _make_proc_info(
        name="chrome",
        cmdline=["chrome", "--new-window"],
        parent_name="explorer.exe",
    )
    is_suspicious, reason = _check_suspicious(proc)
    assert is_suspicious is False
    assert reason == ""


def test_collect_handles_psutil_error():
    """collect() must continue gracefully when psutil raises NoSuchProcess."""
    monitor = SystemMonitor()

    mock_proc = MagicMock()
    mock_proc.info = {
        "pid": 4242,
        "name": "safe_app",
        "exe": "/usr/bin/safe_app",
        "cmdline": ["safe_app"],
        "cpu_percent": 1.0,
        "memory_percent": 0.5,
        "status": "running",
        "username": "user",
        "ppid": 999,
    }

    # Parent lookup raises NoSuchProcess — process should still be collected
    with patch("agent.system_monitor.psutil.process_iter", return_value=[mock_proc]), \
         patch("agent.system_monitor.psutil.Process",
               side_effect=psutil.NoSuchProcess(999)):
        result = monitor.collect()

    assert isinstance(result, list)
    assert len(result) == 1
    assert result[0].pid == 4242
    # parent_name falls back to None when parent lookup fails
    assert result[0].parent_name is None
