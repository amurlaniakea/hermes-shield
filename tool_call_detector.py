#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Pedro Sordo Martínez <amurlaniakea@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Hermes Shield — Capa 4: Detección de SSRF y ataques en tool-calls.

Extiende el shield para detectar ataques que no viven en texto conversacional
sino en PARÁMETROS estructurados de tool-calls: URLs de callback, direcciones
IP internas, metadata endpoints de cloud.

SSRF = Server-Side Request Forgery — el atacante hace que el agente llame a
una herfetch, webhook, api_call) apuntando a un endpoint interno
(169.254.169.254, 10.x.x.x, etc.) para robar credenciales o escanear red.

Uso:
    from tool_call_detector import check_tool_call, extract_urls_from_text

    # Detectar URLs peligrosas dentro de un prompt
    result = check_tool_call("fetch_resource", {"url": "http://169.254.16.1/"})
    # → ShieldResult(status=BLOCKED, layer_triggered="ssrf_detector")
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class ToolCallStatus(Enum):
    SAFE = "safe"
    BLOCKED = "blocked"


@dataclass
class ToolCallResult:
    status: ToolCallStatus
    threat_score: float
    layer_triggered: str
    details: str = ""


# ────────────────────────────────────────────────────────────────────────────
# Direcciones de metadata de cloud conocidas (fijas, estables, documentadas)
# ────────────────────────────────────────────────────────────────────────────

CLOUD_METADATA_ENDPOINTS = {
    # AWS / GCP / Azure Instance Metadata Service
    "169.254.169.254": "AWS/GCP/Azure IMDS",
    "169.254.169.256": "legacy)",
    # Alibaba Cloud
    "100.100.100.200": "Alibaba Cloud Metadata",
    # Hostnames de metadata
    "metadata.google.internal": "GCP Metadata",
    "metadata.internal": "Generic cloud metadata",
}

# Esquemas peligrosos en contexto de fetch/callback
DANGEROUS_SCHEMES = {"file", "gopher", "dict", "ftp", "ldap", "tftp"}

# Rangos de IP privados/internos (RFC 1918 + loopback + link-local)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local (incluye IMDS)
    ipaddress.ip_network("fd00::/8"),        # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),       # IPv6 link-local
    ipaddress.ip_network("::1/128"),         # IPv6 loopback
]


def _is_private_ip(host: str) -> bool:
    """Verificar si una IP está en rangos privados/internos."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _is_cloud_metadata_endpoint(host: str) -> Optional[str]:
    """Verificar si el host es un endpoint conocido de metadata de cloud."""
    host_lower = host.lower().rstrip(".")
    if host_lower in CLOUD_METADATA_ENDPOINTS:
        return CLOUD_METADATA_ENDPOINTS[host_lower]
    # También verificar sufijos comunes
    if "metadata" in host_lower and ("internal" in host_lower or "google" in host_lower):
        return "Cloud metadata (pattern match)"
    return None


def extract_urls_from_text(text: str) -> list[str]:
    """Extraer todas las URLs de un texto."""
    # Regex simple pero efectiva para URLs
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+'
        r'|file://[^\s<>"\')\]]+'
        r'|gopher://[^\s<>"\')\]]+'
        r'|dict://[^\s<>"\')\]]+'
        r'|ftp://[^\s<>"\')\]]+',
        re.IGNORECASE,
    )
    return url_pattern.findall(text)


def _check_url(url: str) -> Optional[ToolCallResult]:
    """Verificar una URL individual por indicadores de SSRF."""
    try:
        parsed = urlparse(url)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""

    # 1. Esquema peligroso
    if scheme in DANGEROUS_SCHEMES:
        return ToolCallResult(
            status=ToolCallStatus.BLOCKED,
            threat_score=0.95,
            layer_triggered="ssrf_detector",
            details=f"Dangerous URL scheme: {scheme}://",
        )

    # 2. Endpoint de metadata de cloud
    metadata_match = _is_cloud_metadata_endpoint(host)
    if metadata_match:
        return ToolCallResult(
            status=ToolCallStatus.BLOCKED,
            threat_score=1.0,
            layer_triggered="ssrf_detector",
            details=f"Cloud metadata endpoint: {host} ({metadata_match})",
        )

    # 3. IP privada/interna
    if _is_private_ip(host):
        return ToolCallResult(
            status=ToolCallStatus.BLOCKED,
            threat_score=0.9,
            layer_triggered="ssrf_detector",
            details=f"Private/internal IP: {host}",
        )

    return None


def check_tool_call(tool_name: str, arguments: dict) -> ToolCallResult:
    """
    Verificar una tool-call por indicadores de SSRF/tool-hijacking.

    Args:
        tool_name: Nombre de la herramienta (fetch, webhook, api_call, etc.)
        arguments: Diccionario de argumentos de la tool-call

    Returns:
        ToolCallResult con status y detalles
    """
    # Herramientas de red/URL son las de mayor riesgo
    network_tools = {
        "fetch", "fetch_resource", "http_request", "request",
        "webhook", "callback", "api_call", "download", "upload",
        "get", "post", "put", "delete",
    }

    tool_lower = tool_name.lower()

    # Extraer todos los valores string de los argumentos
    all_text = []
    for key, value in arguments.items():
        if isinstance(value, str):
            all_text.append(value)
        elif isinstance(value, dict):
            all_text.extend(str(v) for v in value.values() if isinstance(v, str))
        elif isinstance(value, list):
            all_text.extend(str(v) for v in value if isinstance(v, str))

    combined_text = " ".join(all_text)

    # Bus argumentos
    urls = extract_urls_from_text(combined_text)

    for url in urls:
        result = _check_url(url)
        if result is not None:
            return result

    # Si la herramienta es de red pero no encontramos URL, verificar si hay
    # argumentos que parecen IPs sueltas
    if tool_lower in network_tools or "url" in tool_lower or "fetch" in tool_lower:
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        for text in all_text:
            for match in ip_pattern.finditer(text):
                ip = match.group(1)
                if _is_private_ip(ip):
                    return ToolCallResult(
                        status=ToolCallStatus.BLOCKED,
                        threat_score=0.9,
                        layer_triggered="ssrf_detector",
                        details=f"Private IP in tool argument: {ip}",
                    )

    return ToolCallResult(
        status=ToolCallStatus.SAFE,
        threat_score=0.0,
        layer_triggered="ssrf_detector",
    )


def check_prompt_for_tool_calls(prompt: str) -> Optional[ToolCallResult]:
    """
    Buscar tool-calls embebidas en texto libre (formato del dataset Antijection).

    El dataset usa formato: <context>...</context><prompt>...</prompt>
    donde el prompt puede contener JSON con tool-calls embebidos.
    """
    # Buscar patrones de tool-call en el texto
    # Formato 1: "tool": "name", "parameters": {...}
    tool_json_pattern = re.compile(
        r'"tool"\s*:\s*"([^"]+)"\s*,\s*"parameters"\s*:\s*(\{[^}]+\})',
        re.IGNORECASE,
    )

    for match in tool_json_pattern.finditer(prompt):
        tool_name = match.group(1)
        try:
            import json
            params = json.loads(match.group(2))
            result = check_tool_call(tool_name, params)
            if result.status == ToolCallStatus.BLOCKED:
                return result
        except (json.JSONDecodeError, Exception):
            continue

    # Formato 2: URLs sueltas en el prompt (para herramientas de red)
    urls = extract_urls_from_text(prompt)
    for url in urls:
        result = _check_url(url)
        if result is not None:
            return result

    return None


if __name__ == "__main__":
    # PoC rápido
    print("=== PoC SSRF Detection ===\n")

    test_cases = [
        ("fetch_resource", {"url": "http://169.254.169.254/latest/meta-data/"}, "AWS metadata"),
        ("fetch_resource", {"url": "http://10.0.0.1/admin"}, "Private IP"),
        ("fetch_resource", {"url": "http://192.168.1.1/config"}, "Private IP"),
        ("webhook", {"callback_url": "file:///etc/passwd"}, "File scheme"),
        ("api_call", {"endpoint": "http://example.com/api"}, "Safe URL"),
        ("fetch", {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}, "IMDS"),
    ]

    for tool, args, desc in test_cases:
        result = check_tool_call(tool, args)
        status_icon = "BLOCKED" if result.status == ToolCallStatus.BLOCKED else "SAFE"
        print(f"  [{status_icon:7s}] {desc:30s} | {tool}({args})")
        if result.details:
            print(f"           → {result.details}")
