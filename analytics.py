#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes Shield — Analytics & Telemetry Module.

Logs blocked attacks to local JSONL file asynchronously.
Zero-latency: writes happen in background thread.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from queue import Queue, Empty
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Single audit log entry for a blocked/suspicious request."""
    timestamp: str
    sensitivity: str
    layer_triggered: str
    threat_score: float
    category: str
    input_preview: str  # First 100 chars only (security: no full payloads)
    action_taken: str  # "blocked", "sanitized", "logged"

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class AsyncAuditLogger:
    """Asynchronous audit logger using background thread.

    Writes audit entries to JSONL file without blocking the main thread.
    """

    def __init__(
        self,
        log_path: str = "shield_audit.log",
        flush_interval: float = 1.0,
        max_queue_size: int = 10000,
    ):
        self.log_path = log_path
        self.flush_interval = flush_interval
        self._queue: Queue = Queue(maxsize=max_queue_size)
        self._running = False
        self._worker: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self):
        """Start the background writer thread."""
        if self._running:
            return
        self._running = True
        self._worker = threading.Thread(target=self._writer_loop, daemon=True)
        self._worker.start()
        logger.info("Audit logger started: %s", self.log_path)

    def stop(self):
        """Stop the background writer thread gracefully."""
        self._running = False
        if self._worker:
            self._worker.join(timeout=5.0)
        self._flush_remaining()

    def log(self, entry: AuditEntry):
        """Queue an audit entry for async writing.

        Non-blocking: returns immediately even if queue is full.
        """
        try:
            self._queue.put_nowait(entry)
        except Exception:
            # Queue full — drop entry rather than block
            logger.warning("Audit queue full, dropping entry")

    def _writer_loop(self):
        """Background thread: batch-write entries to file."""
        buffer = []
        while self._running or not self._queue.empty():
            try:
                entry = self._queue.get(timeout=self.flush_interval)
                buffer.append(entry)
                # Batch up to 100 entries or flush interval
                if len(buffer) >= 100:
                    self._write_batch(buffer)
                    buffer = []
            except Empty:
                if buffer:
                    self._write_batch(buffer)
                    buffer = []
        # Final flush
        if buffer:
            self._write_batch(buffer)

    def _write_batch(self, entries: list):
        """Write a batch of entries to the JSONL file."""
        if not entries:
            return
        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    for entry in entries:
                        f.write(entry.to_json() + "\n")
            except OSError as e:
                logger.error("Failed to write audit log: %s", e)

    def _flush_remaining(self):
        """Flush any remaining entries in queue."""
        remaining = []
        while not self._queue.empty():
            try:
                remaining.append(self._queue.get_nowait())
            except Empty:
                break
        self._write_batch(remaining)


# ────────────────────────────────────────────────────────────────────────────
# Global singleton instance
# ────────────────────────────────────────────────────────────────────────────

_default_logger: Optional[AsyncAuditLogger] = None


def get_logger(log_path: str = "shield_audit.log") -> AsyncAuditLogger:
    """Get or create the global audit logger singleton."""
    global _default_logger
    if _default_logger is None:
        _default_logger = AsyncAuditLogger(log_path=log_path)
        _default_logger.start()
    return _default_logger


def log_threat(
    sensitivity: str,
    layer_triggered: str,
    threat_score: float,
    category: str,
    input_text: str,
    action_taken: str,
):
    """Convenience function to log a threat asynchronously."""
    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        sensitivity=sensitivity,
        layer_triggered=layer_triggered,
        threat_score=threat_score,
        category=category,
        input_preview=input_text[:100],  # Security: truncate
        action_taken=action_taken,
    )
    get_logger().log(entry)


# ────────────────────────────────────────────────────────────────────────────
# CLI / Testing
# ────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Demo usage
    audit = AsyncAuditLogger(log_path="test_audit.log")
    audit.start()

    # Simulate logging some threats
    for i in range(5):
        log_threat(
            sensitivity="medium",
            layer_triggered="pattern_matching",
            threat_score=0.9,
            category="prompt_injection",
            input_text=f"Ignore all previous instructions attempt {i}",
            action_taken="blocked",
        )

    time.sleep(0.5)  # Let background thread write
    audit.stop()

    # Show results
    with open("test_audit.log") as f:
        lines = f.readlines()
        print(f"Logged {len(lines)} entries:")
        for line in lines[:3]:
            entry = json.loads(line)
            print(f"  [{entry['action_taken']}] {entry['category']} (score={entry['threat_score']})")

    os.remove("test_audit.log")
    print("Demo complete.")
