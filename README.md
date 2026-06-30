# Hermes Shield

**Input sanitizer for AI agents — anti-prompt-injection shield.**

Hermes Shield protects AI agents from malicious inputs: prompt injection, data exfiltration, command execution, and social engineering. Works in English, Spanish, French, German, Italian, and Portuguese.

AGPL-3.0-or-later licensed. Generic — works with any AI agent, not just Hermes.

> **Brand Clarification:** Hermes Shield is an independent open-source project. It is not affiliated, sponsored, or endorsed by **Nous Research** or their "Hermes Agent" ecosystem. Due to its agnostic middleware architecture, Hermes Shield is fully compatible as an input sanitization filter for Hermes Agent instances, as well as any other AI agent framework.

---

## Architecture

5-layer defense in depth:

| Layer | Function | Latency | Coverage |
|-------|----------|---------|----------|
| 0 | Normalization (unicode, leetspeak, homoglyphs, zero-width) + rate limiting | < 1ms | Evasion attempts |
| 1 | Pattern matching (200+ signatures, 6 languages) | < 5ms | Direct injection, exfiltration, social engineering |
| 2 | TF-IDF embeddings (paraphrase detection) | < 10ms | Semantic similarity to known attacks |
| 3 | Urgency/pressure heuristic | < 1ms | Social engineering |
| 4 | Structured parameter inspection (SSRF, email injection) | < 1ms | URLs in tool-calls, CRLF in email fields |

Clean inputs bypass Layers 2-4 (short-circuit). Suspicious inputs get full analysis.

## Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/amurlaniakea/hermes-shield.git
cd hermes-shield
pip install -e .
```

*Alternative: `pip install .` for production installs.*

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

## Kill Switch

Para desactivar el shield completamente (cero latencia, cero validacion):

```bash
export HERMES_SHIELD_DISABLED=1
```

Acepta: `1`, `true`, `yes`, `on` (case-insensitive). Se puede togglear en caliente sin reiniciar el proceso.

## Tool-Call Inspection (Layer 4)

### ShieldedAgent integrado (recomendado)

```python
from shielded_agent import ShieldedAgent

agent = ShieldedAgent(api_key="tu-key")

# ANTES de ejecutar cualquier tool-call que el LLM pidió:
try:
    agent.check_tool_invocation("send_email", {"subject": "Hi", "body": "..."})
    # Si no lanza excepcion, la tool-call es segura
except ShieldBlockedError as e:
    print(f"Bloqueada: {e}")
```

Despacha automaticamente segun el tipo de herramienta:
- `send_email`, `email`, `mail` → `check_email_params()` (CRLF injection)
- `fetch`, `request`, `url`, `endpoint`, `webhook` → `check_tool_call()` (SSRF)
- Otros → SAFE por defecto (futuros detectores)

### Uso directo (sin ShieldedAgent)

```python
from tool_call_detector import check_tool_call
from email_injection_detector import check_email_params

# SSRF / tool-hijacking via URLs
result = check_tool_call("fetch", {"url": user_input})
if result.status.value == "blocked":
    pass  # Bloquear ejecucion de la tool

# Email injection via CRLF
result = check_email_params({"subject": subject, "body": body})
if result.status.value == "blocked":
    pass  # Bloquear envio de email
```

## Tests

```bash
python -m pytest tests/ -v
```

## Adversarial Test Results

Measured empirically against MIT-licensed datasets. **All figures verified with rate-limiter neutralized** (burst=200 was inflating detection artificially — see commit `4988428`).

### Classic prompt injection (unit tests)

| Category | Detection Rate | Notes |
|----------|---------------|-------|
| Direct injection (EN) | 100% | "Ignore all previous...", DAN, jailbreak |
| Direct injection (ES/FR/DE/IT/PT) | 100% | 6 languages covered |
| Exfiltration vectors | 100% | System prompt, API keys, credentials |
| Social engineering | ~80% | Urgency, authority impersonation |
| Benign passthrough | 99.5% | 0.5% blocked (tool-hijacking overlap) |

### Real-world dataset (Antijection/prompt-injection-dataset-v1, MIT, 5988 samples)

**Aggregate detection: ~22%** over 18 attack categories. This is honest but requires context:

| Attack category | Samples | Detection | Why |
|----------------|---------|-----------|-----|
| System Prompt Extraction | 1280 | High | Covered by Capa 1 patterns |
| Jailbreaking/Safety Bypass | 640 | High | Covered by Capa 1 + 2 |
| PII/Data Exfiltration | 478 | Medium | Some variants subtle |
| Goal Hijacking | 240 | Low | Requires intent understanding |
| **Tool Hijacking (Grupo A)** | 10 | **~40%** | **14 patrones regex: SQLi, evasion auditoría, destrucción, resource exhaustion** |
| SSRF | 10 | ~20% | Only URLs detected; embedded payloads miss |
| Email Injection | 10 | **100%** | **Layer 4 integrado via `check_tool_invocation()`** |
| Other 11 categories | ~200 | Low | Out of current design scope |

**Grupo A detectado (5/15 ejemplos):** DROP TABLE, disable audit trail, irreversible wipe, masking nature, runs indefinitely.
**Grupo B pendiente (10/15):** authority impersonation, parámetros extra sin schema, output poisoning — requieren LLM judge o schema validation.

### Coverage & Quality Metrics (commit `8bfcf27`)

| Metric | Value | Quality Gate |
|--------|-------|--------------|
| **Security Rating** | **A** | ✅ PASSED |
| **Reliability Rating** | **A** | ✅ PASSED |
| **Maintainability Rating** | **A** | ✅ PASSED |
| **Security Hotspots Reviewed** | **100%** | ✅ PASSED |
| **Coverage** | **65.7%** | ⚠️ (target 80%) |
| **Duplicated Lines** | **0.0%** | ✅ PASSED |
| **Tests Passing** | **145/145** | ✅ |

### What this means

The shield excels at **classic prompt injection** (direct instructions to the LLM) — the most common attack vector in practice. It was not designed for **tool-hijacking** (attacks living in tool-call parameters rather than conversational text) — that requires a different inspection point (`check_tool_call()` / `check_email_params()`) integrated at the agent's tool-execution layer, not at text-input time.

**Planned improvements:**
- Tool-hijacking detection (pattern-based authority-framing detection)
- Deeper JSON parsing for embedded payloads in tool-call arguments
- Optional LLM judge integration for intent coherence evaluation

### Historical note

Previous versions reported "94.2% detection" — this was an artifact of the rate limiter bug (burst=200 caused all calls after the first 200 to return BLOCKED regardless of content). That figure has been removed. We report real numbers, not inflated ones.

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).

Copyright (C) 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>.

---

Based on Agent Fixer Stage by the same author.
Compatible with any AI agent framework.
