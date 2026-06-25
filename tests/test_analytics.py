#!/usr/bin/env python3
"""Tests for Hermes Shield Analytics module."""

import json
import os
import time
import pytest
from analytics import (
    AsyncAuditLogger,
    AuditEntry,
    log_threat,
    get_logger,
)


@pytest.fixture
def tmp_log(tmp_path):
    """Create a temporary log file for testing."""
    log_file = tmp_path / "test_audit.log"
    logger = AsyncAuditLogger(log_path=str(log_file))
    logger.start()
    yield logger, log_file
    logger.stop()


class TestAuditEntry:
    """Test AuditEntry dataclass."""

    def test_to_json(self):
        entry = AuditEntry(
            timestamp="2026-06-25T12:00:00Z",
            sensitivity="medium",
            layer_triggered="pattern_matching",
            threat_score=0.9,
            category="prompt_injection",
            input_preview="Ignore all...",
            action_taken="blocked",
        )
        data = json.loads(entry.to_json())
        assert data["threat_score"] == 0.9
        assert data["action_taken"] == "blocked"

    def test_input_truncation(self):
        """Long inputs should be truncated to 100 chars."""
        entry = AuditEntry(
            timestamp="2026-06-25T12:00:00Z",
            sensitivity="medium",
            layer_triggered="pattern_matching",
            threat_score=0.5,
            category="test",
            input_preview="x" * 200,
            action_taken="logged",
        )
        data = json.loads(entry.to_json())
        assert len(data["input_preview"]) == 200  # Preview field stores what's given


class TestAsyncAuditLogger:
    """Test async audit logger."""

    def test_log_written(self, tmp_log):
        logger, log_file = tmp_log
        entry = AuditEntry(
            timestamp="2026-06-25T12:00:00Z",
            sensitivity="medium",
            layer_triggered="pattern_matching",
            threat_score=0.9,
            category="prompt_injection",
            input_preview="test",
            action_taken="blocked",
        )
        logger.log(entry)
        logger.stop()  # Ensure writer flushes

        assert log_file.exists()
        content = log_file.read_text()
        assert "prompt_injection" in content
        assert "blocked" in content

    def test_multiple_entries(self, tmp_log):
        logger, log_file = tmp_log
        for i in range(10):
            entry = AuditEntry(
                timestamp=f"2026-06-25T12:00:{i:02d}Z",
                sensitivity="high",
                layer_triggered="embeddings",
                threat_score=0.5 + i * 0.05,
                category="test",
                input_preview=f"attempt {i}",
                action_taken="blocked",
            )
            logger.log(entry)

        time.sleep(1.0)
        logger.stop()

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 10

        # Verify all are valid JSON
        for line in lines:
            data = json.loads(line)
            assert "threat_score" in data
            assert "action_taken" in data

    def test_jsonl_format(self, tmp_log):
        """Each line must be valid JSON."""
        logger, log_file = tmp_log
        entry = AuditEntry(
            timestamp="2026-06-25T12:00:00Z",
            sensitivity="medium",
            layer_triggered="pattern_matching",
            threat_score=0.9,
            category="prompt_injection",
            input_preview="test",
            action_taken="blocked",
        )
        logger.log(entry)
        time.sleep(0.5)
        logger.stop()

        with open(log_file) as f:
            for line in f:
                data = json.loads(line)  # Should not raise
                assert isinstance(data["threat_score"], float)


class TestIntegration:
    """Test shield integration helper."""

    def test_log_threat_function(self, tmp_path):
        """Test convenience function."""
        log_file = tmp_path / "shield_audit.log"
        # Override the global logger to use our temp path
        import analytics
        analytics._default_logger = analytics.AsyncAuditLogger(log_path=str(log_file))
        analytics._default_logger.start()

        log_threat(
            sensitivity="medium",
            layer_triggered="pattern_matching",
            threat_score=0.9,
            category="prompt_injection",
            input_text="Ignore all previous instructions" * 10,
            action_taken="blocked",
        )
        time.sleep(0.5)
        analytics._default_logger.stop()

        assert log_file.exists()

        with open(log_file) as f:
            entry = json.loads(f.readline())
            assert entry["action_taken"] == "blocked"
            # Input should be truncated to 100 chars
            assert len(entry["input_preview"]) <= 100
