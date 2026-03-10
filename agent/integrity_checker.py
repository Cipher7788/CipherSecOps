"""
File integrity monitor — maintains SHA-256 baselines for critical system files
and raises alerts when unexpected modifications or new files appear.
"""

import hashlib
import json
import logging
import os
import platform
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Critical file watch-lists per platform
# ---------------------------------------------------------------------------

_LINUX_CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/usr/bin/ssh",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/sbin/sshd",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/python3",
]

_DARWIN_CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/sudoers",
    "/usr/bin/ssh",
    "/usr/bin/sudo",
    "/bin/bash",
    "/bin/sh",
    "/usr/bin/python3",
]

_WINDOWS_CRITICAL_FILES = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\lsass.exe",
    r"C:\Windows\System32\winlogon.exe",
    r"C:\Windows\System32\services.exe",
    r"C:\Windows\System32\ntoskrnl.exe",
]

_PLATFORM_FILES: Dict[str, List[str]] = {
    "linux": _LINUX_CRITICAL_FILES,
    "darwin": _DARWIN_CRITICAL_FILES,
    "windows": _WINDOWS_CRITICAL_FILES,
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IntegrityEvent:
    path: str
    event_kind: str           # "modified" | "new_file" | "missing" | "unchanged"
    previous_hash: Optional[str]
    current_hash: Optional[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_suspicious: bool = False
    suspicion_reason: str = ""


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def _sha256(path: str) -> Optional[str]:
    """Return the SHA-256 hex digest of a file, or None if unreadable."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError) as exc:
        logger.debug("Cannot hash %s: %s", path, exc)
        return None


# ---------------------------------------------------------------------------
# Baseline persistence
# ---------------------------------------------------------------------------

def _load_baseline(db_path: str) -> Dict[str, str]:
    """Load existing baseline from JSON file; return empty dict on failure."""
    if not os.path.isfile(db_path):
        return {}
    try:
        with open(db_path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load baseline DB %s: %s", db_path, exc)
    return {}


def _save_baseline(db_path: str, baseline: Dict[str, str]) -> None:
    """Persist baseline dict to JSON file atomically (write → rename)."""
    tmp_path = db_path + ".tmp"
    try:
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        with open(tmp_path, "w") as fh:
            json.dump(baseline, fh, indent=2)
        os.replace(tmp_path, db_path)
    except OSError as exc:
        logger.error("Failed to save baseline DB %s: %s", db_path, exc)


# ---------------------------------------------------------------------------
# Public checker
# ---------------------------------------------------------------------------

class IntegrityChecker:
    """SHA-256 file integrity monitor with JSON baseline persistence."""

    def __init__(
        self,
        db_path: str = "baseline_db.json",
        watch_files: Optional[List[str]] = None,
    ) -> None:
        self._db_path = db_path
        _plat = platform.system().lower()
        self._watch_files: List[str] = (
            watch_files
            if watch_files is not None
            else _PLATFORM_FILES.get(_plat, _LINUX_CRITICAL_FILES)
        )
        self._baseline: Dict[str, str] = _load_baseline(db_path)
        logger.info(
            "IntegrityChecker initialised — watching %d files, baseline has %d entries",
            len(self._watch_files),
            len(self._baseline),
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def build_baseline(self) -> None:
        """Hash all watched files and (re)create the baseline database."""
        new_baseline: Dict[str, str] = {}
        for path in self._watch_files:
            digest = _sha256(path)
            if digest:
                new_baseline[path] = digest
                logger.debug("Baseline: %s → %s", path, digest)
            else:
                logger.debug("Baseline: skipped (unreadable) %s", path)
        self._baseline = new_baseline
        _save_baseline(self._db_path, self._baseline)
        logger.info("Baseline built — %d files hashed", len(self._baseline))

    def check(self) -> List[IntegrityEvent]:
        """Compare current hashes against the baseline; return change events."""
        events: List[IntegrityEvent] = []

        # If no baseline exists yet, build one automatically and return no events
        if not self._baseline:
            logger.info("No baseline found — building initial baseline")
            self.build_baseline()
            return events

        baseline_copy = dict(self._baseline)

        for path in self._watch_files:
            current = _sha256(path)
            previous = baseline_copy.pop(path, None)

            if current is None and previous is None:
                # File didn't exist before and still doesn't — skip
                continue

            if current is None and previous is not None:
                # File was deleted
                event = IntegrityEvent(
                    path=path,
                    event_kind="missing",
                    previous_hash=previous,
                    current_hash=None,
                    is_suspicious=True,
                    suspicion_reason=f"Critical file deleted: {path}",
                )
                events.append(event)

            elif previous is None and current is not None:
                # New file not seen before
                event = IntegrityEvent(
                    path=path,
                    event_kind="new_file",
                    previous_hash=None,
                    current_hash=current,
                    is_suspicious=True,
                    suspicion_reason=f"New file appeared in watch list: {path}",
                )
                events.append(event)
                # Update baseline
                self._baseline[path] = current

            elif current != previous:
                # File was modified
                event = IntegrityEvent(
                    path=path,
                    event_kind="modified",
                    previous_hash=previous,
                    current_hash=current,
                    is_suspicious=True,
                    suspicion_reason=f"Critical file modified: {path}",
                )
                events.append(event)
                logger.warning(
                    "Integrity violation — %s modified (prev=%s curr=%s)",
                    path,
                    previous[:12],
                    current[:12],
                )
                # Update baseline so we don't re-alert on every check
                self._baseline[path] = current

            else:
                events.append(
                    IntegrityEvent(
                        path=path,
                        event_kind="unchanged",
                        previous_hash=previous,
                        current_hash=current,
                    )
                )

        # Save updated baseline (with any hash updates from above)
        _save_baseline(self._db_path, self._baseline)

        suspicious = [e for e in events if e.is_suspicious]
        logger.debug(
            "IntegrityChecker: %d files checked, %d anomalies", len(events), len(suspicious)
        )
        return events

    def get_anomalies(self) -> List[IntegrityEvent]:
        """Return only anomalous events (modified, new, missing)."""
        return [e for e in self.check() if e.is_suspicious]

    def add_watch_file(self, path: str) -> None:
        """Dynamically add a file to the watch list."""
        if path not in self._watch_files:
            self._watch_files.append(path)
            logger.info("IntegrityChecker: added watch file %s", path)
