import pytest

from server.playbooks.engine import PlaybookEngine


def test_numeric_condition():
    engine = PlaybookEngine()
    assert engine._evaluate_condition("risk_score >= 60", {"risk_score": 75}) is True
    assert engine._evaluate_condition("risk_score < 10", {"risk_score": 9}) is True
    assert engine._evaluate_condition("risk_score < 10", {"risk_score": "not-a-number"}) is False


def test_quoted_string_condition():
    engine = PlaybookEngine()
    assert engine._evaluate_condition('severity == "high risk"', {"severity": "high risk"}) is True
    assert engine._evaluate_condition("severity != low", {"severity": "low"}) is False


def test_missing_key_returns_false():
    engine = PlaybookEngine()
    assert engine._evaluate_condition("missing_key == 1", {}) is False


def test_param_resolution_exact_and_embedded():
    engine = PlaybookEngine()
    ctx = {"id": 123, "name": "alice", "details": {"a": 1}}
    params = {"ticket": "{{ id }}", "message": "user-{{name}}-{{id}}", "payload": "{{ details }}", "static": 42}
    resolved = engine._resolve_params(params, ctx)
    assert resolved["ticket"] == 123
    assert resolved["message"] == "user-alice-123"
    assert resolved["payload"] == {"a": 1}
    assert resolved["static"] == 42
