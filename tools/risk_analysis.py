"""Herramientas del Agente Analista: CÓMPUTO determinístico sobre los datos.

Los LLM son malos haciendo aritmética exacta. Por eso el cálculo de CVSS y el
ranking de riesgo se hacen en Python puro: el Analista decide QUÉ calcular y
cómo explicarlo, pero los números salen de código verificable.
"""

import json
import math

from langchain_core.tools import tool
from packaging.version import InvalidVersion, Version

# ---------------------------------------------------------------------------
# CVSS v3.1 — fórmula oficial (https://www.first.org/cvss/v3.1/specification-document)
# ---------------------------------------------------------------------------
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

# Si solo hay CVSS v4 (o nada), usamos la etiqueta de GitHub como aproximación.
_LABEL_TO_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 2.5}


def _roundup(value: float) -> float:
    """Redondeo hacia arriba a 1 decimal, tal como lo define CVSS v3.1."""
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000
    return (math.floor(as_int / 10_000) + 1) / 10.0


def cvss31_base_score(vector: str) -> float:
    """Calcula el base score de un vector 'CVSS:3.x/AV:N/AC:L/...'."""
    metrics = dict(part.split(":") for part in vector.split("/")[1:])
    scope_changed = metrics["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr_table[metrics["PR"]] * _UI[metrics["UI"]]

    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def score_vulnerability(cvss_vector: str | None, severity_label: str | None) -> tuple[float, str]:
    """Devuelve (score, método). El método deja claro si es exacto o aproximado."""
    if cvss_vector and cvss_vector.startswith("CVSS:3"):
        try:
            return cvss31_base_score(cvss_vector), "cvss3.1"
        except (KeyError, ValueError):
            pass
    if severity_label and severity_label.upper() in _LABEL_TO_SCORE:
        return _LABEL_TO_SCORE[severity_label.upper()], "label-approx"
    return 5.0, "unknown-default"


# ---------------------------------------------------------------------------
# Tools expuestas al Analista
# ---------------------------------------------------------------------------
@tool
def calculate_cvss_score(cvss_vector: str) -> str:
    """Calcula el CVSS v3.1 base score (0-10) y la severidad de un vector,
    ej. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'."""
    if not cvss_vector.startswith("CVSS:3"):
        return json.dumps({"error": "Solo se soportan vectores CVSS v3.x"})
    try:
        score = cvss31_base_score(cvss_vector)
    except (KeyError, ValueError) as exc:
        return json.dumps({"error": f"Vector inválido: {exc}"})
    return json.dumps({"vector": cvss_vector, "score": score, "severity": severity_from_score(score)})


def _parse_version(v: str) -> Version | None:
    try:
        return Version(v)
    except InvalidVersion:
        return None


def recommended_upgrade(installed: str, vulns: list[dict]) -> str | None:
    """Versión MÍNIMA que corrige todas las vulns con fix conocido.

    Para cada vuln tomamos el fix más chico que sea > versión instalada
    (respeta ramas: django 3.2.x se arregla en 3.2.y, no hace falta saltar a 5.x).
    El upgrade recomendado es el MÁXIMO de esos mínimos.
    """
    current = _parse_version(installed)
    if current is None:
        return None
    needed = []
    for vuln in vulns:
        fixes = [fv for f in vuln["fixed_in"] if (fv := _parse_version(f)) and fv > current]
        if fixes:
            needed.append(min(fixes))
    return str(max(needed)) if needed else None


def prioritize(osv_results: list[dict]) -> dict:
    """Función PURA (sin LLM): recibe la salida de query_osv y rankea paquetes.

    Orden de prioridad (lexicográfico): 1) CVSS máximo, 2) cantidad de vulns
    CRITICAL, 3) cantidad de HIGH, 4) total de vulns. Así una sola vuln crítica
    pesa más que muchas medias, y la cantidad solo desempata.
    """
    ranking = []
    for pkg in osv_results:
        vulns = []
        for v in pkg["vulnerabilities"]:
            score, method = score_vulnerability(v.get("cvss_vector"), v.get("severity_label"))
            vulns.append({
                "id": v["id"], "cve": v.get("cve", []), "summary": v.get("summary", ""),
                "score": score, "severity": severity_from_score(score),
                "method": method, "fixed_in": v.get("fixed_in", []),
            })
        if not vulns:
            continue
        by_sev = {s: sum(1 for x in vulns if x["severity"] == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        ranking.append({
            "package": pkg["package"],
            "installed_version": pkg["version"],
            "ecosystem": pkg["ecosystem"],
            "max_cvss": max(x["score"] for x in vulns),
            "vuln_count_analyzed": len(vulns),
            "vuln_count_total": pkg.get("total_found", len(vulns)),
            "by_severity": by_sev,
            "approximated_scores": sum(1 for x in vulns if x["method"] != "cvss3.1"),
            "recommended_version": recommended_upgrade(pkg["version"], vulns),
            "top_vulns": sorted(vulns, key=lambda x: -x["score"])[:3],
        })

    ranking.sort(
        key=lambda p: (p["max_cvss"], p["by_severity"]["CRITICAL"], p["by_severity"]["HIGH"], p["vuln_count_total"]),
        reverse=True,
    )
    for i, p in enumerate(ranking, start=1):
        p["priority"] = i
    return {"packages_analyzed": len(ranking), "data_warnings": data_warnings(ranking), "ranking": ranking}


def data_warnings(ranking: list[dict]) -> list[str]:
    """Advertencias ya redactadas por código: el LLM las copia, no las deduce.
    (Un LLM leyendo un JSON largo omite o confunde estos detalles.)"""
    warnings = []
    for p in ranking:
        name = p["package"].split(":")[-1]
        if p["vuln_count_total"] > p["vuln_count_analyzed"]:
            warnings.append(f"{name}: análisis parcial, {p['vuln_count_analyzed']} de {p['vuln_count_total']} vulnerabilidades analizadas.")
        if p["approximated_scores"]:
            warnings.append(f"{name}: {p['approximated_scores']} scores aproximados (sin vector CVSS v3; estimados por etiqueta de severidad).")
    return warnings
