"""Integration layer: auto-log threats from HermesShield."""

from __future__ import annotations
from analytics import log_threat, get_logger

def register_threat(result, sensitivity: str, input_text: str):
    """Log a threat if it was blocked or sanitized.

    Args:
        result: ShieldResult from HermesShield.check()
        sensitivity: Active sensitivity profile
        input_text: Original input text
    """
    if result.is_malicious:
        log_threat(
            sensitivity=sensitivity,
            layer_triggered=result.layer_triggered,
            threat_score=result.threat_score,
            category="prompt_injection",
            input_text=input_text,
            action_taken="blocked",
        )
    elif result.is_suspicious:
        log_threat(
            sensitivity=sensitivity,
            layer_triggered=result.layer_triggered,
            threat_score=result.threat_score,
            category="suspicious_input",
            input_text=input_text,
            action_taken="sanitized",
        )
