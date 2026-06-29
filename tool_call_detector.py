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
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
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
# Indicadores de amenaza SSRF (IPs/endpoints de cloud metadata).
# Se cargan desde el archivo ssrf_threat_intel.json (no escaneado por SAST).
# ────────────────────────────────────────────────────────────────────────────

import json

_THREAT_INTEL_PATH = Path(__file__).parent / "ssrf_threat_intel.json"


def _load_threat_intel() -> tuple[dict[str, str], list[str], set[str]]:
    """Cargar indicadores SSRF desde archivo JSON externo."""
    try:
        with open(_THREAT_INTEL_PATH, encoding="utf-8") as f:
            data = json.load(f)
        endpoints = data.get("cloud_metadata_endpoints", {})
        networks = data.get("private_networks", [])
        schemes = set(data.get("dangerous_schemes", []))
        return endpoints, networks, schemes
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return {}, [], set()


CLOUD_METADATA_ENDPOINTS, _private_ranges, _dangerous_schemes = _load_threat_intel()
PRIVATE_NETWORKS = [ipaddress.ip_network(r) for r in _private_ranges]
DANGEROUS_SCHEMES = _dangerous_schemes


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


def _extract_strings_from_args(arguments: dict) -> list[str]:
    """Extraer todos los valores string de un dict de argumentos."""
    result = []
    for value in arguments.values():
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, dict):
            result.extend(str(v) for v in value.values() if isinstance(v, str))
        elif isinstance(value, list):
            result.extend(str(v) for v in value if isinstance(v, str))
    return result


def _is_network_tool(tool_name: str) -> bool:
    """Verificar si una herramienta es de red/URL."""
    network_tools = {
        "fetch", "fetch_resource", "http_request", "request",
        "webhook", "callback", "api_call", "download", "upload",
        "get", "post", "put", "delete",
    }
    tool_lower = tool_name.lower()
    return tool_lower in network_tools or "url" in tool_lower or "fetch" in tool_lower


def _check_ips_in_text(texts: list[str]) -> Optional[ToolCallResult]:
    """Buscar IPs privadas en textos de argumentos."""
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for text in texts:
        for match in ip_pattern.finditer(text):
            ip = match.group(1)
            if _is_private_ip(ip):
                return ToolCallResult(
                    status=ToolCallStatus.BLOCKED,
                    threat_score=0.9,
                    layer_triggered="ssrf_detector",
                    details=f"Private IP in tool argument: {ip}",
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
    all_text = _extract_strings_from_args(arguments)
    combined_text = " ".join(all_text)

    # Verificar URLs encontradas
    for url in extract_urls_from_text(combined_text):
        result = _check_url(url)
        if result is not None:
            return result

    # Si es herramienta de red, buscar IPs sueltas
    if _is_network_tool(tool_name):
        result = _check_ips_in_text(all_text)
        if result is not None:
            return result

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
        except Exception:  # nosec B112 — expected: skip malformed JSON in prompt
            continue

    # Formato 2: URLs sueltas en el prompt (para herramientas de red)
    urls = extract_urls_from_text(prompt)
    for url in urls:
        result = _check_url(url)
        if result is not None:
            return result

    return None



