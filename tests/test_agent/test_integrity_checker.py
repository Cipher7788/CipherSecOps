"""Tests for agent/integrity_checker.py."""

import json
import os

import pytest

from agent.integrity_checker import IntegrityChecker, _sha256


def test_compute_hash_returns_sha256(tmp_path):
    """_sha256() must return a 64-char lowercase hex string for a readable file."""
    test_file = tmp_path / "sample.txt"
    test_file.write_text("Hello, CipherSecOps!")

    digest = _sha256(str(test_file))

    assert digest is not None
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_sha256_returns_none_for_missing_file(tmp_path):
    """_sha256() must return None when the file does not exist."""
    missing = str(tmp_path / "does_not_exist.txt")
    result = _sha256(missing)
    assert result is None


def test_baseline_creation(tmp_path):
    """build_baseline() must hash watched files and persist a JSON baseline DB."""
    watched = tmp_path / "watched.txt"
    watched.write_text("original content")
    db_path = str(tmp_path / "baseline.json")

    checker = IntegrityChecker(
        db_path=db_path,
        watch_files=[str(watched)],
    )
    checker.build_baseline()

    assert os.path.isfile(db_path), "Baseline JSON file must be created"

    with open(db_path) as fh:
        baseline = json.load(fh)

    assert str(watched) in baseline
    expected_hash = _sha256(str(watched))
    assert baseline[str(watched)] == expected_hash


def test_detect_file_modification(tmp_path):
    """check() must detect and report a 'modified' event after file content changes."""
    watched = tmp_path / "important.conf"
    watched.write_text("original content — version 1")
    db_path = str(tmp_path / "baseline.json")

    checker = IntegrityChecker(
        db_path=db_path,
        watch_files=[str(watched)],
    )
    checker.build_baseline()

    # Simulate an attacker modifying the file
    watched.write_text("MODIFIED BY ATTACKER — version 2")

    events = checker.check()

    modified_events = [e for e in events if e.event_kind == "modified"]
    assert len(modified_events) == 1

    evt = modified_events[0]
    assert evt.path == str(watched)
    assert evt.is_suspicious is True
    assert "modified" in evt.suspicion_reason.lower()
    assert evt.previous_hash != evt.current_hash


def test_detect_missing_file(tmp_path):
    """check() must report a 'missing' event when a baselined file is deleted."""
    watched = tmp_path / "critical.cfg"
    watched.write_text("critical configuration")
    db_path = str(tmp_path / "baseline.json")

    checker = IntegrityChecker(
        db_path=db_path,
        watch_files=[str(watched)],
    )
    checker.build_baseline()

    watched.unlink()

    events = checker.check()
    missing_events = [e for e in events if e.event_kind == "missing"]
    assert len(missing_events) == 1
    assert missing_events[0].is_suspicious is True


def test_unchanged_file_not_suspicious(tmp_path):
    """check() must not flag an unmodified file as suspicious."""
    watched = tmp_path / "stable.conf"
    watched.write_text("stable content")
    db_path = str(tmp_path / "baseline.json")

    checker = IntegrityChecker(
        db_path=db_path,
        watch_files=[str(watched)],
    )
    checker.build_baseline()

    events = checker.check()
    unchanged = [e for e in events if e.event_kind == "unchanged"]
    assert len(unchanged) == 1
    assert unchanged[0].is_suspicious is False
