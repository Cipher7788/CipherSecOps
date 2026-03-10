"""Tests for server/threat_engine/rules.py and mitre_mapping.py."""

import pytest
from datetime import datetime, timezone

from server.threat_engine.rules import match_rules, RULES
from server.threat_engine.mitre_mapping import MITRE_TECHNIQUES, get_technique
from server.threat_engine.risk_scorer import RiskScorer


def _make_rule_stub(severity: str):
    """Create a minimal object with a .severity attribute for RiskScorer tests."""
    return type("RuleStub", (), {"severity": severity})()


# ---------------------------------------------------------------------------
# Rule matching tests
# ---------------------------------------------------------------------------

def test_rules_match_suspicious_process():
    """RULE-001 must fire for an Office app spawning cmd.exe."""
    event = {
        "event_type": "process_create",
        "data": {
            "parent_process": "word.exe",
            "process_name": "cmd.exe",
            "cmdline": "cmd.exe /c whoami",
        },
    }
    matched = match_rules(event)
    assert len(matched) >= 1
    matched_ids = [r.id for r in matched]
    assert "RULE-001" in matched_ids


def test_rules_match_excel_spawning_powershell():
    """RULE-001 must also fire for excel.exe → powershell.exe."""
    event = {
        "event_type": "process_create",
        "data": {
            "parent_process": "excel.exe",
            "process_name": "powershell.exe",
            "cmdline": "powershell.exe -EncodedCommand dGVzdA==",
        },
    }
    matched = match_rules(event)
    matched_ids = [r.id for r in matched]
    assert "RULE-001" in matched_ids


def test_rules_no_match_normal_event():
    """No rules must match a plain chrome process spawned by explorer."""
    event = {
        "event_type": "process_create",
        "data": {
            "parent_process": "explorer.exe",
            "process_name": "chrome.exe",
            "cmdline": "chrome.exe --new-window https://example.com",
        },
    }
    matched = match_rules(event)
    assert len(matched) == 0


def test_brute_force_rule_fires():
    """RULE-004 must fire when failure_count reaches the threshold (5)."""
    event = {
        "event_type": "auth_failure",
        "data": {"failure_count": 7, "source_ip": "1.2.3.4"},
    }
    matched = match_rules(event)
    matched_ids = [r.id for r in matched]
    assert "RULE-004" in matched_ids


def test_file_integrity_rule_fires():
    """RULE-005 must fire on write to /etc/passwd."""
    event = {
        "event_type": "file_write",
        "data": {"file_path": "/etc/passwd", "size_bytes": 1024},
    }
    matched = match_rules(event)
    matched_ids = [r.id for r in matched]
    assert "RULE-005" in matched_ids


# ---------------------------------------------------------------------------
# MITRE mapping tests
# ---------------------------------------------------------------------------

def test_mitre_mapping_has_t1059():
    """T1059 must be present in the MITRE mapping with required fields."""
    assert "T1059" in MITRE_TECHNIQUES
    t1059 = MITRE_TECHNIQUES["T1059"]
    assert "name" in t1059
    assert "tactic" in t1059
    assert "description" in t1059
    assert "Command" in t1059["name"]


def test_get_technique_returns_correct_entry():
    """get_technique() must return the same dict as direct MITRE_TECHNIQUES access."""
    result = get_technique("T1110")
    assert result is not None
    assert result["tactic"] == "Credential Access"


def test_get_technique_unknown_returns_none():
    """get_technique() must return None for an unknown technique ID."""
    assert get_technique("T9999") is None


def test_mitre_mapping_covers_all_rule_techniques():
    """Every MITRE technique referenced by a rule must exist in the mapping."""
    for rule in RULES:
        if rule.mitre_technique:
            assert rule.mitre_technique in MITRE_TECHNIQUES, (
                f"Rule {rule.id} references unmapped technique {rule.mitre_technique}"
            )


# ---------------------------------------------------------------------------
# RiskScorer integration with rules
# ---------------------------------------------------------------------------

def test_risk_scorer_critical_score():
    """Multiple critical rules within the last 60 s must produce a score >= 85."""
    scorer = RiskScorer()
    rules = [
        _make_rule_stub("critical"),
        _make_rule_stub("critical"),
        _make_rule_stub("high"),
    ]
    event = {
        "agent_id": "agent-test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    score = scorer.score(event, rules)
    assert score >= 85, f"Expected critical score (>=85), got {score}"


def test_risk_scorer_low_score():
    """A single low-severity rule on a stale event must produce a score < 30."""
    scorer = RiskScorer()
    rules = [_make_rule_stub("low")]
    # Old timestamp — no recency bonus
    event = {
        "agent_id": "agent-test",
        "timestamp": "2020-01-01T00:00:00+00:00",
    }
    score = scorer.score(event, rules)
    assert score < 30, f"Expected low score (<30), got {score}"
