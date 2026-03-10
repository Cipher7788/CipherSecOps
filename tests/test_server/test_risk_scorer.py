"""Tests for server/threat_engine/risk_scorer.py."""

import pytest
from datetime import datetime, timezone

from server.threat_engine.risk_scorer import RiskScorer


def _rule(severity: str):
    """Create a minimal stub with a .severity attribute."""
    return type("RuleStub", (), {"severity": severity})()


# ---------------------------------------------------------------------------
# Score range invariant
# ---------------------------------------------------------------------------

def test_score_range_always_0_to_100():
    """score() must always return a value in [0, 100] for any input combination."""
    scorer = RiskScorer()
    for severity in ("low", "medium", "high", "critical"):
        for n_rules in (1, 3, 5, 10):
            rules = [_rule(severity) for _ in range(n_rules)]
            result = scorer.score({}, rules)
            assert 0 <= result <= 100, (
                f"Score out of range for severity={severity}, n_rules={n_rules}: {result}"
            )


def test_score_is_zero_with_no_rules():
    """score() must return 0 when no rules matched."""
    scorer = RiskScorer()
    assert scorer.score({"agent_id": "x"}, []) == 0


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

def test_critical_severity_increases_score():
    """Severity ordering must be: critical > high > medium > low."""
    scorer = RiskScorer()
    event = {"timestamp": "2020-01-01T00:00:00+00:00"}  # no recency bonus

    critical = scorer.score(event, [_rule("critical")])
    high = scorer.score(event, [_rule("high")])
    medium = scorer.score(event, [_rule("medium")])
    low = scorer.score(event, [_rule("low")])

    assert critical > high, f"critical ({critical}) must exceed high ({high})"
    assert high > medium, f"high ({high}) must exceed medium ({medium})"
    assert medium > low, f"medium ({medium}) must exceed low ({low})"


# ---------------------------------------------------------------------------
# Multi-rule bonus
# ---------------------------------------------------------------------------

def test_multiple_rules_increases_score():
    """More matched rules must produce a higher score (multi-rule bonus)."""
    scorer = RiskScorer()
    event = {}

    one_rule = scorer.score(event, [_rule("high")])
    three_rules = scorer.score(event, [_rule("high")] * 3)

    assert three_rules > one_rule, (
        f"Three rules ({three_rules}) should outscore one rule ({one_rule})"
    )


def test_multi_rule_bonus_caps_at_20():
    """The multi-rule bonus must not grow beyond 20 points regardless of rule count."""
    scorer = RiskScorer()
    event = {}

    # Compare 5 rules vs 10 rules — bonus should cap
    five_rules = scorer.score(event, [_rule("low")] * 5)
    ten_rules = scorer.score(event, [_rule("low")] * 10)

    # With cap, the scores should be equal (bonus maxes at 20 for 5+ extra rules)
    assert ten_rules == five_rules


# ---------------------------------------------------------------------------
# Recency bonus
# ---------------------------------------------------------------------------

def test_recency_bonus_for_recent_event():
    """A recent event timestamp must yield a higher score than a stale one."""
    scorer = RiskScorer()
    rules = [_rule("medium")]

    recent_score = scorer.score(
        {"timestamp": datetime.now(timezone.utc).isoformat()}, rules
    )
    stale_score = scorer.score(
        {"timestamp": "2020-01-01T00:00:00+00:00"}, rules
    )

    assert recent_score > stale_score


# ---------------------------------------------------------------------------
# Risk level label thresholds
# ---------------------------------------------------------------------------

def test_get_risk_level_thresholds():
    """get_risk_level() must return the correct label at each boundary score."""
    assert RiskScorer.get_risk_level(85) == "Critical"
    assert RiskScorer.get_risk_level(100) == "Critical"
    assert RiskScorer.get_risk_level(84) == "High"
    assert RiskScorer.get_risk_level(60) == "High"
    assert RiskScorer.get_risk_level(59) == "Medium"
    assert RiskScorer.get_risk_level(30) == "Medium"
    assert RiskScorer.get_risk_level(29) == "Low"
    assert RiskScorer.get_risk_level(0) == "Low"


# ---------------------------------------------------------------------------
# Agent reputation
# ---------------------------------------------------------------------------

def test_agent_reputation_affects_score():
    """A low-reputation agent must produce a higher-risk score."""
    rules = [_rule("medium")]
    event_trusted = {"agent_id": "trusted-agent", "timestamp": "2020-01-01T00:00:00+00:00"}
    event_untrusted = {"agent_id": "risky-agent", "timestamp": "2020-01-01T00:00:00+00:00"}

    scorer = RiskScorer()
    scorer.update_agent_reputation("trusted-agent", 1.0)   # fully trusted
    scorer.update_agent_reputation("risky-agent", 0.0)     # fully untrusted

    trusted_score = scorer.score(event_trusted, rules)
    untrusted_score = scorer.score(event_untrusted, rules)

    assert untrusted_score > trusted_score
