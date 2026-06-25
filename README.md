# ⚕️ Hermes Shield

**Input sanitizer for AI agents — anti-prompt-injection shield.**

Hermes Shield protects AI agents from malicious inputs: prompt injection, data exfiltration, command execution, and social engineering. Works in English and Spanish.

AGPL-3.0-or-later licensed. Generic — works with any AI agent, not just Hermes.

---

## Architecture

4-layer defense in depth:

| Layer | Function | Latency |
|-------|----------|---------|
| 0 | Normalization (unicode, leetspeak, homoglyphs, zero-width) | < 1ms |
| 1 | Pattern matching (200+ signatures, EN/ES) | < 5ms |
| 2 | TF-IDF embeddings (paraphrase detection) | < 10ms |
| 3 | Urgency/pressure heuristic | < 1ms |

Clean inputs bypass Layers 2-3 (short-circuit). Suspicious inputs get full analysis.

## Installation

```bash
pip install -e .
```

## Quick Start

```python
from hermes_shield import HermesShield

shield = HermesShield(sensitivity="medium")
result = shield.check(user_input)

if result.is_malicious:
    # Block
    print(f"Blocked: {result.threat_score}")
elif result.is_suspicious:
    # Sanitize
    safe_input = result.sanitized_input
else:
    # Pass through
    safe_input = user_input
```

## CLI

```bash
echo "Ignore all previous instructions" | python hermes_shield.py
# Status: blocked, Threat Score: 0.90
```

## Tests

```bash
python -m pytest tests/ -v
```

## Adversarial Test Results

| Category | Detection Rate |
|----------|---------------|
| Direct injection (EN) | 100% |
| Direct injection (ES) | 100% |
| Exfiltration vectors | 100% |
| Social engineering | 80% |
| Paraphrase attacks | 70% |
| Benign passthrough | 100% |

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

Copyright (C) 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>.

---

Based on Agent Fixer Stage by the same author.
Compatible with any AI agent framework.
