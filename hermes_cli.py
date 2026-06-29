#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes CLI — Blindaje permanente para interacción con Hermes vía OpenRouter.

Interfaz de chat interactiva con protección Hermes Shield integrada.
Cada input pasa por el escudo antes de llegar a OpenRouter.
    - Inputs maliciosos → bloqueados (alerta ANSI + log, 0 tokens gastados)
    - Inputs seguros → enviados a OpenRouter

Uso:
    python hermes_cli.py                    # Modo interactivo
    python hermes_cli.py "¿Qué es Python?"  # Modo single-shot
    echo "Hola" | python hermes_cli.py     # Modo pipe

Alias (añadir a ~/.bashrc):
    alias hermes="python /home/sil/hermes-shield/hermes_cli.py"
"""

from __future__ import annotations

import os
import sys
from shielded_agent import FullDefenseAgent, ShieldBlockedError

# Configuration

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openrouter/owl-alpha")
SHIELD_SENSIBILITY = os.getenv("SHIELD_SENSIBILITY", "high")
MISDIRECTION_PROXY_URL = os.getenv("MISDIRECTION_PROXY_URL", "")


# Banner

def print_banner():
    """Print startup banner with shield status."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║  🛡️  HERMES CLI — Blindaje Activo                         ║
║  Shield: ON | Profile: {:10s} | Target: OpenRouter     ║
╚══════════════════════════════════════════════════════════════╝
    """.format(SHIELD_SENSIBILITY)
    print(banner)


# Main Loop

def main():
    """Secure REPL loop with Hermes Shield protection."""
def _run_single_shot(agent: FullDefenseAgent, user_input: str):
    """Execute single-shot mode (one input, print result, exit)."""
    try:
        response = agent.chat(user_input)
        print(response)
    except ShieldBlockedError as e:
        print(f"\n{e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def _run_interactive(agent: FullDefenseAgent):
    """Run interactive REPL loop."""
    print("Escribe 'exit' o 'quit' para salir.\n")

    while True:
        try:
            user_input = input("🛡️  Sil> ").strip()

            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "q"):
                print("¡Hasta luego!")
                break

            # Send through shield → API
            response = agent.chat(user_input)
            print(f"\n🤖 Hermes> {response}\n")

        except ShieldBlockedError as e:
            print(f"\n{e}\n", file=sys.stderr)
            print("   Intenta un prompt diferente.\n", file=sys.stderr)

        except KeyboardInterrupt:
            print("\n\n¡Hasta luego!")
            break

        except EOFError:
            break

        except Exception as e:
            print(f"\n❌ Error: {e}\n", file=sys.stderr)


def main():
    """Secure REPL loop with Hermes Shield protection."""

    if not OPENROUTER_API_KEY:
        print(
            "⚠️  ERROR: OPENROUTER_API_KEY no configurada.\n"
            "   export OPENROUTER_API_KEY='tu-token-aqui'",
            file=sys.stderr,
        )
        sys.exit(1)

    agent = FullDefenseAgent(
        api_key=OPENROUTER_API_KEY,
        base_url=OPENROUTER_BASE_URL,
        model=OPENROUTER_MODEL,
        sensitivity=SHIELD_SENSIBILITY,
        misdirection_proxy_url=MISDIRECTION_PROXY_URL or None,
        enable_alerts=True,
        enable_audit=True,
    )

    print_banner()

    if len(sys.argv) > 1:
        user_input = " ".join(sys.argv[1:])
        _run_single_shot(agent, user_input)
        return

    if not sys.stdin.isatty():
        user_input = sys.stdin.read().strip()
        if user_input:
            _run_single_shot(agent, user_input)
        return

    _run_interactive(agent)


if __name__ == "__main__":
    main()
