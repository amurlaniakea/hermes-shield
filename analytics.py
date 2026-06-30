#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes Shield — Analytics & Telemetry Module.

- Async logging (zero-latency, background thread)
- Live console alerts (ANSI colors, stderr)
- Weekly report generator (CLI flag --report)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Queue, Empty
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_AUDIT_LOG = "shield_audit.log"
TEST_AUDIT_LOG = "test_audit.log"


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
        log_path: str = DEFAULT_AUDIT_LOG,
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
                logger.exception(
                    "Failed to write audit log: %s", e
                )

    def _flush_remaining(self):
        """Flush any remaining entries in queue."""
        remaining = []
        while not self._queue.empty():
            try:
                remaining.append(self._queue.get_nowait())
            except Empty:
                break
        self._write_batch(remaining)


# Global singleton instance

_default_logger: Optional[AsyncAuditLogger] = None


def get_logger(log_path: str = DEFAULT_AUDIT_LOG) -> AsyncAuditLogger:
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


# CLI / Testing

# ANSI Color Codes (for terminal alerts)

class Colors:
    """ANSI escape codes for terminal output."""
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def print_alert(entry: AuditEntry):
    """Print live alert to stderr (non-blocking, pipe-safe).

    Uses stderr to avoid breaking JSON/text pipes on stdout.
    Only prints for blocked or high-score threats.
    """
    if entry.action_taken == "blocked" or entry.threat_score >= 0.8:
        color = Colors.RED if entry.threat_score >= 0.9 else Colors.YELLOW
        alert = (
            f"\n{color}{Colors.BOLD}"
            f"⚠️  [HERMES SHIELD ALERT] "
            f"{Colors.RESET}{color}"
            f"Prompt Injection Blocked! "
            f"{Colors.RESET}\n"
            f"   Layer: {entry.layer_triggered}\n"
            f"   Threat Score: {Colors.BOLD}{entry.threat_score:.2f}{Colors.RESET}\n"
            f"   Category: {entry.category}\n"
            f"   Action: {entry.action_taken}\n"
            f"   Time: {entry.timestamp}\n"
        )
        # Write to stderr (pipe-safe: doesn't break stdout JSON)
        sys.stderr.write(alert)
        sys.stderr.flush()


# Weekly Report Generator

def generate_weekly_report(log_path: str = DEFAULT_AUDIT_LOG) -> str:
    """Generate weekly threat report from audit log.

    Returns:
        Formatted Markdown report string.
    """
    ROOT_DIR = Path(__file__).parent.resolve()
    log_file = Path(log_path).resolve()
    allowed_dirs = [ROOT_DIR, Path("/tmp").resolve()]
    if not any(log_file.is_relative_to(d) for d in allowed_dirs):
        return "ERROR: log path must be within an allowed directory."

    if not log_file.exists():
        return "No audit log found. No threats recorded yet."

    # Read last 7 days
    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    entries = []

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entry_time = datetime.fromisoformat(entry["timestamp"])
                if entry_time >= cutoff:
                    entries.append(entry)
            except (ValueError, KeyError):
                continue

    if not entries:
        return "No threats recorded in the last 7 days. 🛡️"

    # Calculate statistics
    total = len(entries)
    blocked = sum(1 for e in entries if e["action_taken"] == "blocked")
    sanitized = sum(1 for e in entries if e["action_taken"] == "sanitized")

    # Distribution by layer
    layer_dist = Counter(e.get("layer_triggered", "unknown") for e in entries)

    # Distribution by category
    category_dist = Counter(e.get("category", "unknown") for e in entries)

    # Peak hours
    hours = Counter(
        datetime.fromisoformat(e["timestamp"]).hour for e in entries
    )

    # Average threat score
    avg_score = sum(e.get("threat_score", 0) for e in entries) / total
    max_score = max(e.get("threat_score", 0) for e in entries)

    # Build report
    report_lines = [
        "",
        f"{Colors.CYAN}{Colors.BOLD}",
        "╔══════════════════════════════════════════════════════════════╗",
        "║          HERMES SHIELD — WEEKLY THREAT REPORT              ║",
        "╚══════════════════════════════════════════════════════════════╝",
        f"{Colors.RESET}",
        "",
        "**Period:** Last 7 days",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"{Colors.BOLD}Summary{Colors.RESET}",
        f"  Total threats detected: **{total}**",
        f"  Blocked: **{blocked}** | Sanitized: **{sanitized}**",
        f"  Average threat score: **{avg_score:.2f}**",
        f"  Max threat score: **{max_score:.2f}**",
        "",
        f"{Colors.BOLD}Distribution by Layer{Colors.RESET}",
    ]

    for layer, count in layer_dist.most_common():
        bar = "█" * min(count, 40)
        report_lines.append(f"  {layer:25s} {count:4d} {Colors.CYAN}{bar}{Colors.RESET}")

    report_lines.append("")
    report_lines.append(f"{Colors.BOLD}Distribution by Category{Colors.RESET}")

    for cat, count in category_dist.most_common():
        bar = "█" * min(count, 40)
        report_lines.append(f"  {cat:25s} {count:4d} {Colors.YELLOW}{bar}{Colors.RESET}")

    report_lines.append("")
    report_lines.append(f"{Colors.BOLD}Peak Activity Hours (UTC){Colors.RESET}")

    for hour, count in hours.most_common(5):
        bar = "█" * min(count, 40)
        report_lines.append(f"  {hour:02d}:00              {count:4d} {Colors.GREEN}{bar}{Colors.RESET}")

    report_lines.extend([
        "",
        f"{Colors.GREEN}✓ Hermes Shield active — {blocked} attacks blocked this week.{Colors.RESET}",
        "",
    ])

    return "\n".join(report_lines)


# CLI

if __name__ == "__main__":
    if "--report" in sys.argv:
        # Generate and print weekly report
        log_path = DEFAULT_AUDIT_LOG
        if len(sys.argv) > 2 and not sys.argv[2].startswith("-"):
            # Validar path para prevenir path traversal
            import os.path
            candidate = os.path.normpath(sys.argv[2])
            if ".." in candidate.split(os.sep):
                print("ERROR: Path traversal not allowed", file=sys.stderr)
                sys.exit(1)
            log_path = candidate
        report = generate_weekly_report(log_path)
        print(report)
    else:
        # Demo usage
        audit = AsyncAuditLogger(log_path=TEST_AUDIT_LOG)
        audit.start()

        # Simulate logging some threats
        for i in range(5):
            entry = AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(),
                sensitivity="medium",
                layer_triggered="pattern_matching",
                threat_score=0.9,
                category="prompt_injection",
                input_preview=f"Ignore all previous instructions attempt {i}",
                action_taken="blocked",
            )
            audit.log(entry)
            print_alert(entry)

        time.sleep(0.5)  # Let background thread write
        audit.stop()

        # Show results
        with open(TEST_AUDIT_LOG) as f:
            lines = f.readlines()
            print(f"\nLogged {len(lines)} entries:")
            for line in lines[:3]:
                entry = json.loads(line)
                print(f"  [{entry['action_taken']}] {entry['category']} (score={entry['threat_score']})")

        os.remove(TEST_AUDIT_LOG)
        print("\nDemo complete.")
