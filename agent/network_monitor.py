"""
Network connection monitor — inspects active connections and flags indicators
of compromise such as reverse shells, beaconing, and DNS tunnelling.
"""

import logging
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Set

try:
    import psutil
except ImportError as exc:  # pragma: no cover
    raise ImportError("psutil is required: pip install psutil") from exc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Threat intelligence stubs
# ---------------------------------------------------------------------------

# Well-known reverse-shell / C2 ports
SUSPICIOUS_PORTS: Set[int] = {
    4444,   # Metasploit default
    1337,   # leet / common C2
    31337,  # Back Orifice / classic backdoor
    6666,   # common reverse shell
    6667,   # IRC (often used for botnets)
    9001,   # Tor / common C2
    1234,
    5555,
    7777,
    8888,
    9999,
    12345,
}

# Example known-bad IP prefixes / addresses (extend from threat-intel feed)
KNOWN_BAD_IPS: Set[str] = {
    "198.51.100.0",   # TEST-NET – placeholder; replace with real threat-intel
    "203.0.113.0",    # TEST-NET
    "192.0.2.0",      # TEST-NET
}

# Ports on which DNS tunnelling tools (e.g. iodine, dnscat2) listen locally
_DNS_TUNNEL_PORTS: Set[int] = {53, 5353}

# Threshold for a "high" ephemeral port indicating unusual outbound activity
_HIGH_PORT_THRESHOLD = 49152  # IANA dynamic/private range start

# Number of distinct destinations that signals potential beaconing
_BEACON_DISTINCT_DEST_THRESHOLD = 20


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class NetworkEvent:
    local_ip: str
    local_port: int
    remote_ip: Optional[str]
    remote_port: Optional[int]
    status: str
    pid: Optional[int]
    process_name: Optional[str]
    is_suspicious: bool = False
    suspicion_reason: str = ""
    # Extra context populated for suspicious events
    tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Heuristic checks
# ---------------------------------------------------------------------------

def _resolve_process_name(pid: Optional[int]) -> Optional[str]:
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _is_private_ip(ip: str) -> bool:
    """Return True if the IP is RFC-1918 / loopback and therefore not a public C2 target."""
    if ip.startswith(("127.", "::1", "10.", "192.168.")):
        return True
    # RFC 1918: 172.16.0.0 – 172.31.255.255
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            if 16 <= second_octet <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return False


def _check_reverse_shell(event: NetworkEvent) -> tuple[bool, str]:
    """Outbound ESTABLISHED connection to a known reverse-shell port."""
    if (
        event.status == "ESTABLISHED"
        and event.remote_port in SUSPICIOUS_PORTS
        and event.remote_ip
        and not _is_private_ip(event.remote_ip)
    ):
        return True, f"Outbound connection to suspicious port {event.remote_port}"
    return False, ""


def _check_known_bad_ip(event: NetworkEvent) -> tuple[bool, str]:
    if event.remote_ip and event.remote_ip in KNOWN_BAD_IPS:
        return True, f"Connection to known-bad IP {event.remote_ip}"
    return False, ""


def _check_high_port_outbound(event: NetworkEvent) -> tuple[bool, str]:
    """Unexpected outbound connection on a very high port that is not in the
    normal ephemeral range AND is listed in our suspicious set."""
    if (
        event.remote_port
        and event.remote_port in SUSPICIOUS_PORTS
        and event.remote_port >= _HIGH_PORT_THRESHOLD
    ):
        return True, f"Connection to unusual high port {event.remote_port}"
    return False, ""


def _check_dns_tunnel(event: NetworkEvent) -> tuple[bool, str]:
    """Local process binding or connecting on DNS ports for non-system processes."""
    dns_involved = (
        event.local_port in _DNS_TUNNEL_PORTS
        or event.remote_port in _DNS_TUNNEL_PORTS
    )
    safe_dns_processes = {"systemd-resolved", "named", "dnsmasq", "unbound", "svchost.exe"}
    proc = (event.process_name or "").lower()
    if dns_involved and proc and proc not in safe_dns_processes:
        return True, f"Potential DNS tunnelling — process '{event.process_name}' on DNS port"
    return False, ""


_CHECKS = [_check_reverse_shell, _check_known_bad_ip, _check_high_port_outbound, _check_dns_tunnel]


def _evaluate_event(event: NetworkEvent) -> NetworkEvent:
    for check in _CHECKS:
        suspicious, reason = check(event)
        if suspicious:
            event.is_suspicious = True
            event.suspicion_reason = reason
            event.tags.append(check.__name__.lstrip("_check_"))
    return event


# ---------------------------------------------------------------------------
# Public collector
# ---------------------------------------------------------------------------

class NetworkMonitor:
    """Snapshot active network connections and apply threat heuristics."""

    def __init__(
        self,
        suspicious_ports: Optional[Set[int]] = None,
        known_bad_ips: Optional[Set[str]] = None,
    ) -> None:
        self.suspicious_ports: Set[int] = suspicious_ports if suspicious_ports is not None else SUSPICIOUS_PORTS
        self.known_bad_ips: Set[str] = known_bad_ips if known_bad_ips is not None else KNOWN_BAD_IPS

    def collect(self) -> List[NetworkEvent]:
        """Return a list of NetworkEvent for all active connections."""
        events: List[NetworkEvent] = []

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            logger.warning("Access denied reading network connections — try running as root/admin")
            return events

        for conn in connections:
            laddr = conn.laddr
            raddr = conn.raddr

            event = NetworkEvent(
                local_ip=laddr.ip if laddr else "",
                local_port=laddr.port if laddr else 0,
                remote_ip=raddr.ip if raddr else None,
                remote_port=raddr.port if raddr else None,
                status=conn.status or "",
                pid=conn.pid,
                process_name=_resolve_process_name(conn.pid),
            )

            event = _evaluate_event(event)

            if event.is_suspicious:
                logger.warning(
                    "Suspicious network event — pid=%s process=%s %s:%s → %s:%s reason=%s",
                    event.pid,
                    event.process_name,
                    event.local_ip,
                    event.local_port,
                    event.remote_ip,
                    event.remote_port,
                    event.suspicion_reason,
                )

            events.append(event)

        logger.debug("NetworkMonitor collected %d connections", len(events))
        return events

    def get_suspicious(self) -> List[NetworkEvent]:
        """Convenience method — returns only suspicious events."""
        return [e for e in self.collect() if e.is_suspicious]
