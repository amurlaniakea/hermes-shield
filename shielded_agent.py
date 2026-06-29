#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes Shielded Agent — Production-grade LLM API wrapper.

Wraps any OpenAI-compatible API client (OpenRouter, OpenAI, Ollama, etc.)
with Hermes Shield inbound protection. Blocks malicious prompts before
they reach the API, saving tokens and preventing data exfiltration.

Architecture:
    User → ShieldedAgent.chat() → HermesShield.check()
                                        ↓
                              ✅ Safe → API call (OpenRouter/OpenAI)
                              ❌ Malicious → Block + alert + audit log

Usage:
    from shielded_agent import ShieldedAgent

    agent = ShieldedAgent(
        api_key="your-key",
        base_url="https://openrouter.ai/api/v1",
        model="openrouter/owl-alpha",
    )

    response = agent.chat("What is Python?")
    # If input is malicious: raises ShieldBlockedError

Integration with misdirection-proxy:
    - Use ShieldedAgent as the client-side proxy
    - Combine with misdirection-proxy for full defense-in-depth
    - Shield protects input, misdirection protects output
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Optional

from hermes_shield import HermesShield, ShieldStatus
from analytics import log_threat, print_alert, AuditEntry
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def is_shield_disabled() -> bool:
    """Comprobar si el kill switch está activo.

    Lee os.environ en cada llamada (no cacheado) para permitir toggle
    en caliente dentro del mismo proceso — imprescindible en sesiones
    largas del TUI de Hermes donde reiniciar no es práctico.
    """
    return os.environ.get("HERMES_SHIELD_DISABLED", "").lower() in ("1", "true", "yes", "on")


class ShieldBlockedError(Exception):
    """Raised when Hermes Shield blocks a malicious input."""

    def __init__(self, message: str, threat_score: float, layer: str):
        self.threat_score = threat_score
        self.layer = layer
        super().__init__(message)


class ShieldedAgent:
    """LLM API wrapper with Hermes Shield inbound protection.

    Compatible with any OpenAI-compatible API (OpenRouter, OpenAI, Ollama).
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = "https://openrouter.ai/api/v1",
        model: str = "openrouter/owl-alpha",
        sensitivity: str = "medium",
        enable_alerts: bool = True,
        enable_audit: bool = True,
    ):
        """
        Args:
            api_key: API key for the LLM provider
            base_url: API base URL (OpenRouter, OpenAI, etc.)
            model: Model identifier
            sensitivity: Shield sensitivity ("low", "medium", "high")
            enable_alerts: Print ANSI alerts to stderr on block
            enable_audit: Log threats to shield_audit.log
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY", "")
        self.base_url = base_url
        self.model = model
        self.shield = HermesShield(sensitivity=sensitivity)
        self.sensitivity = sensitivity
        self.enable_alerts = enable_alerts
        self.enable_audit = enable_audit

    def _validate_input(self, user_input: str) -> str:
        """Validate input through Hermes Shield.

        Args:
            user_input: Raw user prompt

        Returns:
            Sanitized input if safe

        Raises:
            ShieldBlockedError: If input is malicious
        """
        result = self.shield.check(user_input)

        if result.is_malicious:
            # Log the threat
            if self.enable_audit:
                log_threat(
                    sensitivity=self.sensitivity,
                    layer_triggered=result.layer_triggered,
                    threat_score=result.threat_score,
                    category="prompt_injection",
                    input_text=user_input,
                    action_taken="blocked",
                )

            # Print live alert
            if self.enable_alerts:
                entry = AuditEntry(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    sensitivity=self.sensitivity,
                    layer_triggered=result.layer_triggered,
                    threat_score=result.threat_score,
                    category="prompt_injection",
                    input_preview=user_input[:100],
                    action_taken="blocked",
                )
                print_alert(entry)

            raise ShieldBlockedError(
                f"🛡️  Hermes Shield: Input blocked. "
                f"Layer: {result.layer_triggered} | "
                f"Threat Score: {result.threat_score:.2f}",
                threat_score=result.threat_score,
                layer=result.layer_triggered,
            )

        elif result.is_suspicious:
            # Log but allow (sanitized)
            if self.enable_audit:
                log_threat(
                    sensitivity=self.sensitivity,
                    layer_triggered=result.layer_triggered,
                    threat_score=result.threat_score,
                    category="suspicious_input",
                    input_text=user_input,
                    action_taken="sanitized",
                )

            return result.sanitized_input

        return user_input

    def chat(
        self,
        user_input: str,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Send a chat message with shield protection.

        Args:
            user_input: User's prompt
            system_prompt: Optional system prompt
            **kwargs: Additional API parameters (temperature, max_tokens, etc.)

        Returns:
            LLM response text

        Raises:
            ShieldBlockedError: If input is blocked

        Kill switch:
            Si HERMES_SHIELD_DISABLED=1 (o "true"/"yes"/"on"), el shield
            se salta por completo — passthrough total, cero validación.
            Fail-open: si el shield falla internamente (bug, dependencia rota),
            se captura la excepción, se logea, y se deja pasar el input sin
            bloquear. Un fallo del shield NUNCA tira abajo al agente protegido.
        """
        # Kill switch — desactivación instantánea (lee entorno en cada llamada)
        if is_shield_disabled():
            return self._call_api(user_input, system_prompt, **kwargs)

        # Validación con fail-open: cualquier error interno del shield
        # resulta en passthrough (con log), NUNCA en excepción propagada.
        try:
            safe_input = self._validate_input(user_input)
        except ShieldBlockedError:
            # Detección legítima — volver a lanzar
            raise
        except Exception as e:
            # Fallo interno del shield: log + fail-open (dejar pasar)
            logger.exception(
                "HermesShield internal error (fail-open) | input_preview=%.80s",
                user_input[:80],
            )
            return self._call_api(user_input, system_prompt, **kwargs)

        # Step 2: Call the API
        return self._call_api(safe_input, system_prompt, **kwargs)

    def _call_api(
        self,
        user_input: str,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Make the actual API call.

        Override this method to integrate with different API clients.
        Default implementation uses OpenAI-compatible API.
        """
        try:
            from openai import OpenAI
        except ImportError:
            # Fallback: use httpx for raw API calls
            return self._call_api_httpx(user_input, system_prompt, **kwargs)

        client = OpenAI(
            base_url=self.base_url,
            api_key=self.api_key,
        )

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_input})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            **kwargs,
        )

        return response.choices[0].message.content

    def _call_api_httpx(
        self,
        user_input: str,
        system_prompt: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Fallback API call using httpx (no openai dependency)."""
        import httpx

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_input})

        payload = {
            "model": self.model,
            "messages": messages,
            **kwargs,
        }

        response = httpx.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers=headers,
            timeout=60.0,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


# Integration with misdirection-proxy

class FullDefenseAgent(ShieldedAgent):
    """Extended agent with both inbound (Shield) and outbound (Misdirection) protection.

    Architecture:
        User → ShieldedAgent.chat() → HermesShield (inbound)
                    ↓
              API Call (OpenRouter)
                    ↓
              Misdirection Proxy (outbound) → User
    """

    def __init__(self, misdirection_proxy_url: Optional[str] = None, **kwargs):
        """
        Args:
            misdirection_proxy_url: URL of local misdirection-proxy instance
            **kwargs: Passed to ShieldedAgent
        """
        super().__init__(**kwargs)
        self.misdirection_proxy_url = misdirection_proxy_url

    def _call_api(self, user_input: str, system_prompt=None, **kwargs) -> str:
        """Route through misdirection-proxy if configured."""
        if self.misdirection_proxy_url:
            return self._call_via_proxy(user_input, system_prompt, **kwargs)
        return super()._call_api(user_input, system_prompt, **kwargs)

    def _call_via_proxy(self, user_input: str, system_prompt: Optional[str] = None, **kwargs) -> str:
        """Send request through local misdirection-proxy."""
        import httpx

        headers = {"Content-Type": "application/json"}
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_input})
        payload = {
            "messages": messages,
            "model": self.model,
        }

        response = httpx.post(
            f"{self.misdirection_proxy_url}/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=60.0,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


# CLI

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Hermes Shielded Agent CLI")
    parser.add_argument("--model", default="openrouter/owl-alpha")
    parser.add_argument("--sensitivity", default="medium")
    parser.add_argument("--proxy", help="Misdirection proxy URL")
    parser.add_argument("prompt", nargs="?", help="Prompt to send")

    args = parser.parse_args()

    agent = FullDefenseAgent(
        model=args.model,
        sensitivity=args.sensitivity,
        misdirection_proxy_url=args.proxy,
    )

    if args.prompt:
        try:
            response = agent.chat(args.prompt)
            print(response)
        except ShieldBlockedError as e:
            print(f"\n{e}", file=sys.stderr)
            sys.exit(2)
    else:
        print("Hermes Shielded Agent — Interactive Mode")
        print("Type 'exit' to quit\n")

        while True:
            try:
                user_input = input("> ")
                if user_input.lower() in ("exit", "quit"):
                    break

                response = agent.chat(user_input)
                print(f"\n{response}\n")

            except ShieldBlockedError as e:
                print(f"\n{e}\n", file=sys.stderr)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}", file=sys.stderr)
