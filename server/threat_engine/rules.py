"""Detection rules for the threat engine."""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------


@dataclass
class Rule:
    id: str
    name: str
    description: str
    condition_func: Callable[[Dict[str, Any]], bool]
    severity: str  # low / medium / high / critical
    mitre_technique: Optional[str] = None
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Condition helpers
# ---------------------------------------------------------------------------


def _get(event_data: Dict[str, Any], *keys: str, default=None):
    """Safely traverse nested dicts."""
    obj = event_data
    for k in keys:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(k, default)
    return obj


# ---------------------------------------------------------------------------
# Individual rule condition functions
# ---------------------------------------------------------------------------


def _suspicious_process_spawn(event: Dict[str, Any]) -> bool:
    """Detect suspicious child processes spawned by common parent processes."""
    if event.get("event_type") != "process_create":
        return False
    parent = str(_get(event, "data", "parent_process", default="")).lower()
    child = str(_get(event, "data", "process_name", default="")).lower()
    suspicious_parents = {"word.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "winword.exe"}
    suspicious_children = {
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    }
    return parent in suspicious_parents and child in suspicious_children


def _reverse_shell(event: Dict[str, Any]) -> bool:
    """Detect reverse shell indicators in command lines or network connections."""
    if event.get("event_type") not in {"process_create", "network_connect"}:
        return False
    cmdline = str(_get(event, "data", "cmdline", default="")).lower()
    reverse_shell_patterns = [
        r"bash\s+-i\s+>&\s*/dev/tcp",
        r"nc\s+(-e|--exec|.*-c)\s+/bin/(bash|sh)",
        r"python.*socket.*connect.*exec",
        r"/bin/sh\s+-i",
        r"rm\s+/tmp/f.*mkfifo",
        r"ncat.*--exec",
    ]
    for pattern in reverse_shell_patterns:
        if re.search(pattern, cmdline):
            return True
    return False


def _dns_tunneling(event: Dict[str, Any]) -> bool:
    """Detect DNS tunneling via abnormally long DNS queries."""
    if event.get("event_type") != "dns_query":
        return False
    query = str(_get(event, "data", "query", default=""))
    # Unusually long hostnames or high entropy labels are indicators
    if len(query) > 100:
        return True
    labels = query.split(".")
    if any(len(label) > 40 for label in labels):
        return True
    return False


def _brute_force_login(event: Dict[str, Any]) -> bool:
    """Detect brute-force login via failed auth count threshold."""
    if event.get("event_type") != "auth_failure":
        return False
    failure_count = int(_get(event, "data", "failure_count", default=0))
    return failure_count >= 5


def _file_integrity_violation(event: Dict[str, Any]) -> bool:
    """Detect modification of protected system files."""
    if event.get("event_type") != "file_write":
        return False
    path = str(_get(event, "data", "file_path", default="")).lower()
    protected_prefixes = (
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "c:\\windows\\system32\\", "/boot/", "/usr/bin/",
    )
    return any(path.startswith(p) for p in protected_prefixes)


def _crypto_miner(event: Dict[str, Any]) -> bool:
    """Detect crypto-mining activity via known pool hostnames or port patterns."""
    if event.get("event_type") not in {"network_connect", "dns_query"}:
        return False
    dest = str(_get(event, "data", "destination", default="")).lower()
    query = str(_get(event, "data", "query", default="")).lower()
    miner_keywords = {
        "pool.minexmr", "xmrpool", "nanopool", "supportxmr",
        "moneroocean", ":3333", ":4444", ":14433",
    }
    combined = dest + query
    return any(kw in combined for kw in miner_keywords)


def _privilege_escalation(event: Dict[str, Any]) -> bool:
    """Detect privilege escalation patterns."""
    if event.get("event_type") != "process_create":
        return False
    cmdline = str(_get(event, "data", "cmdline", default="")).lower()
    priv_patterns = [
        r"sudo\s+-s",
        r"sudo\s+su",
        r"chmod\s+[46]7[57]\d*\s+/",
        r"chown\s+root",
        r"setuid",
        r"runas\s+/user:administrator",
        r"whoami\s*/priv",
    ]
    for pattern in priv_patterns:
        if re.search(pattern, cmdline):
            return True
    return False


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: List[Rule] = [
    Rule(
        id="RULE-001",
        name="Suspicious Process Spawn",
        description="Office application spawning a shell or scripting interpreter",
        condition_func=_suspicious_process_spawn,
        severity="high",
        mitre_technique="T1059",
        tags=["process", "office", "execution"],
    ),
    Rule(
        id="RULE-002",
        name="Reverse Shell Detected",
        description="Command line or network activity matching reverse shell patterns",
        condition_func=_reverse_shell,
        severity="critical",
        mitre_technique="T1059",
        tags=["shell", "lateral-movement", "c2"],
    ),
    Rule(
        id="RULE-003",
        name="DNS Tunneling",
        description="Unusually long DNS queries indicative of data exfiltration via DNS",
        condition_func=_dns_tunneling,
        severity="high",
        mitre_technique="T1071",
        tags=["dns", "exfiltration", "c2"],
    ),
    Rule(
        id="RULE-004",
        name="Brute Force Login Attempt",
        description="Multiple consecutive authentication failures from a single source",
        condition_func=_brute_force_login,
        severity="medium",
        mitre_technique="T1110",
        tags=["auth", "brute-force"],
    ),
    Rule(
        id="RULE-005",
        name="File Integrity Violation",
        description="Modification of a protected system file",
        condition_func=_file_integrity_violation,
        severity="high",
        mitre_technique="T1078",
        tags=["file", "persistence", "integrity"],
    ),
    Rule(
        id="RULE-006",
        name="Crypto Miner Activity",
        description="Network connections to known crypto-mining pool addresses",
        condition_func=_crypto_miner,
        severity="medium",
        mitre_technique="T1496",
        tags=["miner", "resource-hijacking"],
    ),
    Rule(
        id="RULE-007",
        name="Privilege Escalation Attempt",
        description="Command indicating attempt to gain elevated privileges",
        condition_func=_privilege_escalation,
        severity="critical",
        mitre_technique="T1055",
        tags=["privesc", "root", "elevation"],
    ),
]


# ---------------------------------------------------------------------------
# Matching interface
# ---------------------------------------------------------------------------


def match_rules(event: Dict[str, Any]) -> List[Rule]:
    """Evaluate all rules against a telemetry event and return matching rules."""
    matched: List[Rule] = []
    for rule in RULES:
        try:
            if rule.condition_func(event):
                matched.append(rule)
                logger.debug("Rule matched: %s on event_type=%s", rule.id, event.get("event_type"))
        except Exception as exc:
            logger.error("Error evaluating rule %s: %s", rule.id, exc)
    return matched
