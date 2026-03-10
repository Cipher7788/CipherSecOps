"""
System process monitor — collects running process telemetry and flags
suspicious behaviour using heuristic rules.
"""

import logging
import platform
from dataclasses import dataclass
from typing import List, Optional

try:
    import psutil
except ImportError as exc:  # pragma: no cover
    raise ImportError("psutil is required: pip install psutil") from exc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: Optional[str]
    cmdline: List[str]
    cpu_percent: float
    memory_percent: float
    status: str
    username: Optional[str]
    ppid: Optional[int]
    parent_name: Optional[str]
    is_suspicious: bool = False
    suspicion_reason: str = ""


# ---------------------------------------------------------------------------
# Heuristic rules
# ---------------------------------------------------------------------------

# Parent-process names that should never directly spawn a shell interpreter
_NON_SHELL_PARENTS = {
    "sshd", "httpd", "nginx", "apache2", "mysqld", "postgres",
    "java", "node", "ruby", "php", "python3", "python",
    "dotnet", "mono", "uwsgi", "gunicorn",
}

# Shell-like binaries that are unexpected from _NON_SHELL_PARENTS
_SHELL_NAMES = {
    "bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "cmd.exe", "powershell.exe", "pwsh.exe",
}

# Patterns that appear in download-and-execute one-liners
_DOWNLOAD_EXEC_PATTERNS = [
    "curl", "wget", "Invoke-WebRequest", "Invoke-Expression", "IEX(",
    "DownloadString", "bash -i", "nc -e", "ncat -e", "python -c",
    "/dev/tcp/", "mkfifo",
]

# Combinations where one tool spawns another that is unusual
_SUSPICIOUS_SPAWN_PAIRS: List[tuple] = [
    ("python", "powershell.exe"),
    ("python3", "powershell.exe"),
    ("python", "cmd.exe"),
    ("python3", "cmd.exe"),
    ("python", "bash"),
    ("python3", "bash"),
    ("office", "cmd.exe"),
    ("winword.exe", "cmd.exe"),
    ("excel.exe", "cmd.exe"),
    ("word", "powershell.exe"),
    ("excel", "powershell.exe"),
    ("acrobat", "cmd.exe"),
]


def _cmdline_str(cmdline: List[str]) -> str:
    return " ".join(cmdline).lower()


def _check_suspicious(proc_info: ProcessInfo) -> tuple[bool, str]:
    """Apply heuristic rules; return (is_suspicious, reason)."""

    name_lower = proc_info.name.lower()
    cmd = _cmdline_str(proc_info.cmdline)
    parent = (proc_info.parent_name or "").lower()

    # Rule 1: unexpected shell spawned from non-shell parents
    if name_lower in _SHELL_NAMES and parent in _NON_SHELL_PARENTS:
        return True, (
            f"Shell '{proc_info.name}' spawned from unexpected parent '{proc_info.parent_name}'"
        )

    # Rule 2: suspicious spawn pairs
    for (par_pattern, child_pattern) in _SUSPICIOUS_SPAWN_PAIRS:
        if par_pattern in parent and child_pattern in name_lower:
            return True, (
                f"Suspicious spawn: '{proc_info.parent_name}' → '{proc_info.name}'"
            )

    # Rule 3: download-and-execute patterns in command line
    for pattern in _DOWNLOAD_EXEC_PATTERNS:
        if pattern.lower() in cmd:
            return True, f"Download/exec pattern detected in cmdline: '{pattern}'"

    # Rule 4: Linux — process reading /dev/tcp (reverse shell indicator)
    if "/dev/tcp/" in cmd:
        return True, "Reverse shell indicator: /dev/tcp/ in cmdline"

    # Rule 5: Windows — encoded PowerShell command (common malware technique)
    if name_lower in {"powershell.exe", "pwsh.exe"} and (
        "-encodedcommand" in cmd or "-enc " in cmd or "-e " in cmd
    ):
        return True, "Encoded PowerShell command argument detected"

    # Rule 6: Unusually high CPU by an obscure process (>90 % sustained)
    if proc_info.cpu_percent > 90.0 and name_lower not in {
        "python", "python3", "java", "node", "chrome", "firefox"
    }:
        return True, f"High CPU usage ({proc_info.cpu_percent:.1f}%) from '{proc_info.name}'"

    return False, ""


# ---------------------------------------------------------------------------
# Platform-specific hints
# ---------------------------------------------------------------------------

def _windows_wmi_hint(pid: int) -> Optional[str]:
    """Try to get extra info from WMI on Windows (best-effort)."""
    try:
        import wmi  # type: ignore
        c = wmi.WMI()
        for proc in c.Win32_Process(ProcessId=pid):
            return proc.CommandLine
    except Exception:
        pass
    return None


def _linux_proc_hint(pid: int) -> Optional[str]:
    """Read /proc/<pid>/status for supplementary info on Linux."""
    try:
        with open(f"/proc/{pid}/status", "r") as fh:
            return fh.read()
    except (OSError, PermissionError):
        return None


# ---------------------------------------------------------------------------
# Public collector
# ---------------------------------------------------------------------------

class SystemMonitor:
    """Collects process telemetry and applies suspicion heuristics."""

    def __init__(self) -> None:
        self._platform = platform.system().lower()

    def collect(self) -> List[ProcessInfo]:
        """Snapshot all running processes and return ProcessInfo list."""
        results: List[ProcessInfo] = []

        for proc in psutil.process_iter(
            attrs=[
                "pid", "name", "exe", "cmdline", "cpu_percent",
                "memory_percent", "status", "username", "ppid",
            ]
        ):
            try:
                info = proc.info
                parent_name: Optional[str] = None
                try:
                    parent = psutil.Process(info["ppid"])
                    parent_name = parent.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied, TypeError):
                    pass

                # Platform-specific supplementary hints enrich the ProcessInfo
                # with additional context (command line from WMI, /proc status).
                # The hints are best-effort; failures are silently ignored.
                extra_cmdline: Optional[str] = None
                if self._platform == "windows":
                    extra_cmdline = _windows_wmi_hint(info["pid"])
                elif self._platform == "linux":
                    extra_cmdline = _linux_proc_hint(info["pid"])

                base_cmdline: List[str] = info.get("cmdline") or []
                # Supplement psutil cmdline with platform hint if it provides
                # additional tokens (WMI on Windows, /proc/pid/cmdline on Linux).
                if extra_cmdline:
                    hint_tokens = extra_cmdline.split()
                    if len(hint_tokens) > len(base_cmdline):
                        base_cmdline = hint_tokens

                pi = ProcessInfo(
                    pid=info["pid"],
                    name=info["name"] or "",
                    exe=info.get("exe"),
                    cmdline=base_cmdline,
                    cpu_percent=info.get("cpu_percent") or 0.0,
                    memory_percent=info.get("memory_percent") or 0.0,
                    status=info.get("status") or "",
                    username=info.get("username"),
                    ppid=info.get("ppid"),
                    parent_name=parent_name,
                )
                pi.is_suspicious, pi.suspicion_reason = _check_suspicious(pi)

                if pi.is_suspicious:
                    logger.warning(
                        "Suspicious process detected — pid=%d name=%s reason=%s",
                        pi.pid,
                        pi.name,
                        pi.suspicion_reason,
                    )

                results.append(pi)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        logger.debug("SystemMonitor collected %d processes", len(results))
        return results
