"""
Log collector — tails security-relevant log files on Linux/macOS and reads
Windows Event Log entries, then parses them into structured LogEvent objects.
"""

import logging
import os
import platform
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Windows Event Log import (optional — only available on Windows)
# ---------------------------------------------------------------------------

try:
    import win32evtlog  # type: ignore
    import win32evtlogutil  # type: ignore
    import win32security  # type: ignore
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class LogEvent:
    source: str               # e.g. "auth.log", "syslog", "Security", "System"
    timestamp: Optional[datetime]
    raw_line: str
    event_type: str           # "auth_failure", "login_success", "sudo", "su", "unknown"
    username: Optional[str] = None
    remote_ip: Optional[str] = None
    is_suspicious: bool = False
    suspicion_reason: str = ""
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Log file paths per platform
# ---------------------------------------------------------------------------

_LINUX_LOG_FILES = [
    "/var/log/auth.log",
    "/var/log/secure",       # RHEL/CentOS equivalent
    "/var/log/syslog",
    "/var/log/messages",     # RHEL/CentOS
]

# ---------------------------------------------------------------------------
# Regex patterns for Linux log parsing
# ---------------------------------------------------------------------------

_RE_AUTH_FAILURE = re.compile(
    r"(?:Failed password|authentication failure|Invalid user|FAILED LOGIN)",
    re.IGNORECASE,
)
_RE_LOGIN_SUCCESS = re.compile(
    r"(?:Accepted password|Accepted publickey|session opened for user)",
    re.IGNORECASE,
)
_RE_SUDO = re.compile(r"\bsudo\b", re.IGNORECASE)
_RE_SU = re.compile(r"\bsu\b.*session opened", re.IGNORECASE)
_RE_USERNAME = re.compile(r"(?:user|for user|invalid user)\s+(\S+)", re.IGNORECASE)
_RE_IP = re.compile(r"from\s+([\d.]+)")

# Suspicious thresholds
_BRUTE_FORCE_PATTERN = re.compile(r"Failed password", re.IGNORECASE)


def _classify_line(line: str) -> tuple[str, Optional[str], Optional[str], bool, str]:
    """
    Returns (event_type, username, remote_ip, is_suspicious, suspicion_reason).
    """
    event_type = "unknown"
    is_suspicious = False
    suspicion_reason = ""

    if _RE_AUTH_FAILURE.search(line):
        event_type = "auth_failure"
        if _BRUTE_FORCE_PATTERN.search(line):
            is_suspicious = True
            suspicion_reason = "Failed SSH password attempt"
    elif _RE_LOGIN_SUCCESS.search(line):
        event_type = "login_success"
    elif _RE_SUDO.search(line):
        event_type = "sudo"
    elif _RE_SU.search(line):
        event_type = "su"

    username_match = _RE_USERNAME.search(line)
    username = username_match.group(1) if username_match else None

    ip_match = _RE_IP.search(line)
    remote_ip = ip_match.group(1) if ip_match else None

    return event_type, username, remote_ip, is_suspicious, suspicion_reason


# ---------------------------------------------------------------------------
# File tail helpers
# ---------------------------------------------------------------------------

def _read_last_n_lines(path: str, n: int = 200) -> List[str]:
    """Memory-efficient tail — reads the last *n* lines of a file."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "rb") as fh:
            # Seek from end
            fh.seek(0, 2)
            file_size = fh.tell()
            block_size = 4096
            lines: List[bytes] = []
            remaining = file_size

            while remaining > 0 and len(lines) <= n:
                read_size = min(block_size, remaining)
                remaining -= read_size
                fh.seek(remaining)
                chunk = fh.read(read_size)
                lines = chunk.split(b"\n") + lines

            decoded = [ln.decode("utf-8", errors="replace") for ln in lines]
            return decoded[-n:] if len(decoded) > n else decoded
    except (OSError, PermissionError) as exc:
        logger.warning("Cannot read log file %s: %s", path, exc)
        return []


def _iter_linux_logs(log_files: Optional[List[str]] = None) -> Iterator[LogEvent]:
    """Yield LogEvent objects from Linux/macOS log files."""
    files = log_files if log_files is not None else _LINUX_LOG_FILES
    for path in files:
        source = os.path.basename(path)
        for line in _read_last_n_lines(path):
            line = line.strip()
            if not line:
                continue
            event_type, username, remote_ip, is_susp, reason = _classify_line(line)
            if event_type == "unknown" and not is_susp:
                continue  # skip noise
            yield LogEvent(
                source=source,
                timestamp=datetime.now(),  # production: parse timestamp from line
                raw_line=line,
                event_type=event_type,
                username=username,
                remote_ip=remote_ip,
                is_suspicious=is_susp,
                suspicion_reason=reason,
            )


# ---------------------------------------------------------------------------
# Windows Event Log reader
# ---------------------------------------------------------------------------

def _iter_windows_events(max_records: int = 200) -> Iterator[LogEvent]:
    """Yield LogEvent objects from Windows Security/System event logs."""
    if not _WIN32_AVAILABLE:
        logger.debug("win32evtlog not available — skipping Windows event log collection")
        return

    channels = ["Security", "System", "Application"]
    for channel in channels:
        try:
            hand = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            count = 0
            while events and count < max_records:
                for ev in events:
                    count += 1
                    event_id = ev.EventID & 0xFFFF
                    # Map common Windows Security event IDs
                    event_type = "unknown"
                    is_susp = False
                    reason = ""
                    if event_id == 4625:
                        event_type = "auth_failure"
                        is_susp = True
                        reason = "Windows logon failure (event 4625)"
                    elif event_id == 4624:
                        event_type = "login_success"
                    elif event_id in {4672, 4673}:
                        event_type = "sudo"  # privileged operation
                    elif event_id == 4688:
                        event_type = "process_create"

                    try:
                        raw = win32evtlogutil.SafeFormatMessage(ev, channel)
                    except Exception:
                        raw = f"EventID={event_id}"

                    yield LogEvent(
                        source=channel,
                        timestamp=ev.TimeGenerated,
                        raw_line=raw or "",
                        event_type=event_type,
                        is_suspicious=is_susp,
                        suspicion_reason=reason,
                    )
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            win32evtlog.CloseEventLog(hand)
        except Exception as exc:
            logger.warning("Windows event log read error (%s): %s", channel, exc)


# ---------------------------------------------------------------------------
# Public collector
# ---------------------------------------------------------------------------

class LogCollector:
    """Cross-platform log collector — Linux auth logs and Windows Event Log."""

    def __init__(self, log_files: Optional[List[str]] = None) -> None:
        self._platform = platform.system().lower()
        self._log_files = log_files  # override for testing

    def collect(self) -> List[LogEvent]:
        """Return parsed LogEvent list from the current platform's log sources."""
        events: List[LogEvent] = []

        if self._platform == "windows":
            events.extend(_iter_windows_events())
        else:
            events.extend(_iter_linux_logs(self._log_files))

        suspicious_count = sum(1 for e in events if e.is_suspicious)
        logger.debug(
            "LogCollector: %d events collected, %d suspicious",
            len(events),
            suspicious_count,
        )
        if suspicious_count:
            logger.warning("LogCollector: %d suspicious log events detected", suspicious_count)

        return events
