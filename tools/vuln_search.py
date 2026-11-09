"""Herramientas del Agente Investigador: fuentes EXTERNAS de vulnerabilidades.

- query_osv:  base OSV.dev (Google), datos estructurados y gratuitos, sin API key.
- web_search: Tavily, para contexto (explotación activa, advisories, parches).

Regla de diseño: las tools del investigador TRAEN datos, no los interpretan.
El cálculo de riesgo es responsabilidad del Analista (tools/risk_analysis.py).
"""

import json
from typing import Literal

import httpx
from langchain_core.tools import tool

OSV_URL = "https://api.osv.dev/v1/query"
MAX_VULNS_PER_PACKAGE = 15  # recorte para no inflar el contexto del LLM

# Ecosistemas OSV para los lenguajes del proyecto:
#   Java -> Maven | JavaScript/Node -> npm | Python -> PyPI | PHP -> Packagist
Ecosystem = Literal["Maven", "npm", "PyPI", "Packagist"]


def _fixed_versions(vuln: dict, package: str) -> list[str]:
    """Extrae las versiones que corrigen la vuln para ESTE paquete."""
    fixed = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return sorted(set(fixed))


def _cvss_vector(vuln: dict) -> str | None:
    """Prefiere CVSS v3 (el Analista sabe calcularlo); si no, devuelve v4."""
    by_type = {s["type"]: s["score"] for s in vuln.get("severity", [])}
    return by_type.get("CVSS_V3") or by_type.get("CVSS_V4")


def _simplify(vuln: dict, package: str) -> dict:
    """Reduce el JSON de OSV (muy verboso) a lo que el análisis necesita."""
    db = vuln.get("database_specific", {})
    return {
        "id": vuln["id"],
        "cve": [a for a in vuln.get("aliases", []) if a.startswith("CVE-")],
        "summary": vuln.get("summary", "")[:200],
        "cvss_vector": _cvss_vector(vuln),
        "severity_label": db.get("severity"),  # CRITICAL/HIGH/MODERATE/LOW
        "cwe": db.get("cwe_ids", []),
        "fixed_in": _fixed_versions(vuln, package),
        "published": vuln.get("published", "")[:10],
    }


@tool
def query_osv(package: str, version: str, ecosystem: Ecosystem) -> str:
    """Busca vulnerabilidades conocidas de un paquete y versión en OSV.dev.

    Args:
        package: nombre exacto del paquete. Maven usa 'groupId:artifactId'
            (ej. 'org.apache.logging.log4j:log4j-core'); Packagist usa
            'vendor/paquete' (ej. 'guzzlehttp/guzzle').
        version: versión instalada, ej. '4.17.15'.
        ecosystem: 'Maven' (Java), 'npm' (JavaScript/Node), 'PyPI' (Python)
            o 'Packagist' (PHP).

    Returns:
        JSON con la lista de vulnerabilidades (id, CVE, vector CVSS,
        severidad, CWE y versiones que lo corrigen).
    """
    payload = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    try:
        resp = httpx.post(OSV_URL, json=payload, timeout=20)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        # Devolver el error como texto: el agente puede razonar y reintentar,
        # en vez de que una excepción rompa todo el grafo.
        return json.dumps({"error": f"OSV no respondió: {exc}"})

    vulns = resp.json().get("vulns", [])
    result = {
        "package": package,
        "version": version,
        "ecosystem": ecosystem,
        "total_found": len(vulns),
        "vulnerabilities": [_simplify(v, package) for v in vulns[:MAX_VULNS_PER_PACKAGE]],
    }
    if len(vulns) > MAX_VULNS_PER_PACKAGE:
        result["note"] = f"Se muestran {MAX_VULNS_PER_PACKAGE} de {len(vulns)}."
    return json.dumps(result, ensure_ascii=False)


def get_web_search_tool():
    """Crea la tool de Tavily. Es una función (y no una variable global) para
    que importar este módulo no falle si todavía no cargaste TAVILY_API_KEY."""
    from langchain_tavily import TavilySearch

    return TavilySearch(
        name="web_search",
        description=(
            "Busca en la web contexto sobre una vulnerabilidad concreta: si se "
            "explota activamente, advisories oficiales o guías de mitigación. "
            "Usala con queries específicas, ej. 'CVE-2021-44228 exploited in the wild'."
        ),
        max_results=3,
    )
