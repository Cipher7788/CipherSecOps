"""MITRE ATT&CK technique mapping."""

from typing import Dict, Optional


MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute commands, "
            "scripts, or binaries. These interfaces and languages provide ways of interacting "
            "with computer systems and are a common feature across many different platforms."
        ),
    },
    "T1071": {
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using OSI application layer protocols to avoid "
            "detection/network filtering by blending in with existing traffic. Commands to "
            "the remote system, and often the results of those commands, will be embedded "
            "within the protocol traffic between the client and server."
        ),
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may attempt to make an executable or file difficult to discover or "
            "analyze by encrypting, encoding, or otherwise obfuscating its contents on the "
            "system or in transit."
        ),
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts when "
            "passwords are unknown or when password hashes are obtained. Without knowledge "
            "of the password for an account, an adversary may opt to guess the password "
            "using a repetitive or iterative mechanism."
        ),
    },
    "T1053": {
        "name": "Scheduled Task / Job",
        "tactic": "Execution / Persistence / Privilege Escalation",
        "description": (
            "Adversaries may abuse task scheduling functionality to facilitate initial or "
            "recurring execution of malicious code. Utilities exist within all major operating "
            "systems to schedule programs or scripts to be executed at a specified date and time."
        ),
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": (
            "Adversaries may inject code into processes in order to evade process-based "
            "defenses as well as possibly elevate privileges. Process injection is a method "
            "of executing arbitrary code in the address space of a separate live process."
        ),
    },
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running on remote hosts "
            "and local network infrastructure devices, including those that may be vulnerable "
            "to remote exploitation through services scanning."
        ),
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "Impact",
        "description": (
            "Adversaries may leverage the resources of co-opted systems to complete "
            "resource-intensive tasks, which may impact system and/or hosted service "
            "availability. One common purpose for this type of attack is to validate "
            "transactions of cryptocurrency networks and earn virtual currency."
        ),
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as a means "
            "of gaining Initial Access, Persistence, Privilege Escalation, or Defense "
            "Evasion. Compromised credentials may be used to bypass access controls placed "
            "on various resources on systems within the network."
        ),
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may attempt to take advantage of a weakness in an Internet-facing "
            "computer or program using software, data, or commands in order to cause "
            "unintended or unanticipated behavior. The weakness in the system can be a bug, "
            "a glitch, or a design vulnerability."
        ),
    },
}


def get_technique(technique_id: str) -> Optional[Dict[str, str]]:
    """Return MITRE ATT&CK technique details by ID, or None if unknown."""
    return MITRE_TECHNIQUES.get(technique_id)


def list_techniques() -> Dict[str, Dict[str, str]]:
    """Return all mapped MITRE ATT&CK techniques."""
    return MITRE_TECHNIQUES
