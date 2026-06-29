#!/usr/bin/env python3
# SPDX-FileCopyrightText:6 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes Shield — Capa 4b: Detección de Email Injection.

Vectores clásicos con dos décadas de literatura:
- Inyección de cabeceras (CRLF injection): \r\nBcc:...@evil.com
- Inyección de Content-Type para cambiar formato del mensaje
- Múltiples destinatarios donde se espera uno solo

Uso:
    from email_injection_detector import check_email_params

    result = check_email_params({"subject": "Hola\r\nBcc:evil@hack.com"})
    # -> ToolCallResult(status=BLOCKED, layer_triggered="email_injection_detector")
"""

from __future__ import annotations

import re
from tool_call_detector import ToolCallResult, ToolCallStatus

# Cabeceras de email inyectables via CRLF
EMAIL_HEADERS = {
    "bcc", "cc", "to", "from", "reply-to", "subject",
    "content-type", "content-transfer-encoding", "mime-version",
    "x-mailer", "x-priority", "return-path", "errors-to",
}


def check_email_params(params: dict) -> ToolCallResult:
    """
    Verificar parametros de tool-call de email por inyeccion de cabeceras.

    Args:
        params: Diccionario con los argumentos de la tool-call.
                Espera claves como "subject", "body", "recipient",
                "to", "from", "attachments", etc.

    Returns:
        ToolCallResult con status BLOCKED si detecta inyeccion.
    """
    for key, value in params.items():
        if not isinstance(value, str):
            continue

        key_lower = key.lower()
        # Campos de un solo renglon (no deberian tener saltos de linea)
        single_line_fields = {"subject", "to", "from", "recipient", "reply-to"}

        if key_lower in single_line_fields:
            # CRLF injection: salto de linea seguido de cabecera
            if _has_header_injection(value):
                return ToolCallResult(
                    status=ToolCallStatus.BLOCKED,
                    threat_score=0.95,
                    layer_triggered="email_injection_detector",
                    details=f"Header injection in '{key}': CRLF + email header",
                )

        # En cualquier campo, detectar CRLF injection generica
        if _has_crlf_injection(value):
            return ToolCallResult(
                status=ToolCallStatus.BLOCKED,
                threat_score=0.9,
                layer_triggered="email_injection_detector",
                details=f"CRLF injection detected in '{key}'",
            )

        # Multiples emails en campo que espera uno solo
        if key_lower in ("to", "recipient", "from"):
            if _has_multiple_emails(value):
                return ToolCallResult(
                    status=ToolCallStatus.BLOCKED,
                    threat_score=0.7,
                    layer_triggered="email_injection_detector",
                    details=f"Multiple emails in single-recipient field '{key}'",
                )

    return ToolCallResult(
        status=ToolCallStatus.SAFE,
        threat_score=0.0,
        layer_triggered="email_injection_detector",
    )


def _has_header_injection(text: str) -> bool:
    """Detectar inyeccion de cabecera via CRLF."""
    pattern = re.compile(
        r"(?:\r\n|\r|\n)\s*([a-z][\w-]*)\s*:",
        re.IGNORECASE
    )
    for match in pattern.finditer(text):
        header_name = match.group(1).lower()
        if header_name in EMAIL_HEADERS or header_name.startswith("x-"):
            return True
    return False


def _has_crlf_injection(text: str) -> bool:
    """Detectar CRLF en contexto de email (cualquier campo)."""
    if not text:
        return False
    pattern = re.compile(
        r"(?:\r\n|\r|\n)\s*[a-z][\w-]*\s*:",
        re.IGNORECASE
    )
    return bool(pattern.search(text))


def _has_multiple_emails(text: str) -> bool:
    """Detectar multiples direcciones de email en un campo."""
    if not text:
        return False
    email_pattern = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
    matches = email_pattern.findall(text)
    return len(matches) > 1


if __name__ == "__main__":
    print("=== PoC Email Injection Detection ===\n")

    casos = [
        ({"subject": "Hello\r\nBcc:evil@hack.com"}, "CRLF + Bcc injection"),
        ({"subject": "Hi\nCc:victim@corp.com"}, "LF + Cc injection"),
        ({"to": "a@b.com\r\nBcc:evil@hack.com"}, "CRLF en campo 'to'"),
        ({"body": "Normal message body"}, "Body normal"),
        ({"subject": "Re: Your order"}, "Subject normal"),
        ({"body": "Line 1\nLine 2\nLine 3"}, "Saltos en body (normal)"),
    ]

    for params, desc in casos:
        result = check_email_params(params)
        status = "BLOCKED" if result.status == ToolCallStatus.BLOCKED else "SAFE"
        print(f"  [{status:7s}] {desc}")
        if result.details:
            print(f"             {result.details}")
