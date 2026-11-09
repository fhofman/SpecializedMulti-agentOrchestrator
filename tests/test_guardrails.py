"""Tests determinísticos (sin LLM ni red) de las reglas anti-bucle del supervisor.

    uv run python -m pytest tests -q
"""

from agents.supervisor import SupervisorDecision, apply_guardrails, automatic_checks
from state import MAX_RUNS_PER_AGENT, MAX_STEPS, initial_state

PKG_LOG4J = {
    "package": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "Maven",
    "total_found": 8,
    "vulnerabilities": [
        {"id": "GHSA-jfh8", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "severity_label": "CRITICAL", "fixed_in": ["2.15.0"]},
        {"id": "GHSA-v4", "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:L/SA:N", "severity_label": "MODERATE", "fixed_in": ["2.25.4"]},
    ],
}


def decision(next_agent, instruction="hacé algo"):
    return SupervisorDecision(research_issues=[], analysis_issues=[], next_agent=next_agent,
                              instruction=instruction, reasoning="test")


def test_g1_no_analyst_without_data():
    nxt, _, notes = apply_guardrails(decision("analyst"), initial_state("q"))
    assert nxt == "researcher" and "G1" in notes[0]


def test_g2_no_finish_without_analysis():
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J], "revisions": {"researcher": 1, "analyst": 0}}
    nxt, _, _ = apply_guardrails(decision("FINISH"), st)
    assert nxt == "analyst"


def test_g3_max_runs_per_agent():
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J], "analysis_report": "x",
                               "revisions": {"researcher": 1, "analyst": MAX_RUNS_PER_AGENT}}
    nxt, _, notes = apply_guardrails(decision("analyst"), st)
    assert nxt == "FINISH" and any("G3" in n for n in notes)


def test_g4_max_steps():
    st = initial_state("q") | {"step_count": MAX_STEPS - 1}
    nxt, _, notes = apply_guardrails(decision("researcher"), st)
    assert nxt == "FINISH" and any("G4" in n for n in notes)


def test_g0_empty_instruction_gets_default():
    _, instruction, notes = apply_guardrails(decision("researcher", instruction=""), initial_state("q"))
    assert instruction and any("G0" in n for n in notes)


def test_automatic_checks_detect_missing_warning():
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J],
                               "analysis_report": "## Ranking\n| 1 | log4j-core |\n## Datos faltantes\n- ninguno"}
    failures = automatic_checks(st)
    assert any("aproximados" in f for f in failures)


def test_g5_refines_when_checks_fail_then_g3_stops_it():
    base = initial_state("q") | {"vulnerability_data": [PKG_LOG4J],
                                 "analysis_report": "## Ranking\n| 1 | log4j-core |\n## Datos faltantes\n- ninguno"}
    # Con presupuesto: G5 manda a refinar.
    nxt, instr, _ = apply_guardrails(decision("FINISH"), base | {"revisions": {"researcher": 1, "analyst": 1}})
    assert nxt == "analyst" and "aproximados" in instr
    # Sin presupuesto: termina igual (no hay bucle infinito).
    nxt, _, _ = apply_guardrails(decision("FINISH"), base | {"revisions": {"researcher": 1, "analyst": MAX_RUNS_PER_AGENT}})
    assert nxt == "FINISH"


def test_automatic_checks_pass_with_precise_warnings():
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J],
                               "analysis_report": "| 1 | log4j-core | 2.25.4 |\n## Datos faltantes\n- log4j-core: 1 score aproximado (solo CVSS v4)"}
    assert automatic_checks(st) == []


def test_g5_report_issue_goes_to_analyst_not_researcher():
    """Conflicto: el LLM quiere devolverle al investigador un fallo del REPORTE."""
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J], "research_findings": "ok",
                               "analysis_report": "## Ranking\n| 1 | log4j-core |\n## Datos faltantes\n- ninguno",
                               "revisions": {"researcher": 1, "analyst": 1}}
    nxt, _, notes = apply_guardrails(decision("researcher"), st)
    assert nxt == "analyst" and any("G5" in n for n in notes)


GOOD_REPORT = ("| 1 | log4j-core | 10.0 | 2.25.4 |\n## Plan de acción\n1. Actualizar log4j-core.\n"
               "## Datos faltantes / advertencias\n- log4j-core: 1 scores aproximados (sin vector CVSS v3)")


def test_g6_no_refinement_without_concrete_issue():
    """El LLM pide refinar por un criterio objetivo (A3) que el código ya validó -> FINISH."""
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J], "research_findings": "ok",
                               "analysis_report": GOOD_REPORT, "revisions": {"researcher": 1, "analyst": 1}}
    d = SupervisorDecision(research_issues=[], analysis_issues=["A2: lodash sin versión"],
                           next_agent="analyst", instruction="corregí", reasoning="x")
    nxt, _, notes = apply_guardrails(d, st)
    assert nxt == "FINISH" and any("G6" in n for n in notes)


def test_judged_issue_is_respected():
    """Un fallo de juicio concreto (A4) sí habilita el refinamiento."""
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J], "research_findings": "ok",
                               "analysis_report": GOOD_REPORT, "revisions": {"researcher": 1, "analyst": 1}}
    d = SupervisorDecision(research_issues=[], analysis_issues=["A4: el plan no dice a qué versión"],
                           next_agent="analyst", instruction="agregá versiones al plan", reasoning="x")
    assert apply_guardrails(d, st)[0] == "analyst"


def test_a2_detects_missing_version():
    st = initial_state("q") | {"vulnerability_data": [PKG_LOG4J],
                               "analysis_report": "| 1 | log4j-core | 10.0 |\n## Datos faltantes\n- log4j-core: 1 scores aproximados"}
    assert any(f.startswith("A2") and "2.25.4" in f for f in automatic_checks(st))


def test_g7_no_analyst_when_no_vulnerabilities():
    empty = {"package": "requests", "version": "2.99.0", "ecosystem": "PyPI", "total_found": 0, "vulnerabilities": []}
    st = initial_state("q") | {"vulnerability_data": [empty], "research_findings": "0 vulns",
                               "revisions": {"researcher": 1, "analyst": 0}}
    nxt, _, notes = apply_guardrails(decision("analyst"), st)
    assert nxt == "FINISH" and any("G7" in n for n in notes)


def test_g7_out_of_scope_finishes_without_looping():
    st = initial_state("q") | {"research_findings": "FUERA DE ALCANCE: firmware de router",
                               "revisions": {"researcher": 1, "analyst": 0}}
    nxt, _, _ = apply_guardrails(decision("analyst"), st)
    assert nxt == "FINISH"


def test_package_name_validation():
    from tools.vuln_search import validate_package_name
    assert validate_package_name("psf/requests", "PyPI")            # repo de GitHub en PyPI
    assert validate_package_name("expressjs/express", "npm")
    assert validate_package_name("log4j-core", "Maven")
    assert validate_package_name("guzzle", "Packagist")
    assert validate_package_name("requests", "PyPI") is None
    assert validate_package_name("@angular/core", "npm") is None
    assert validate_package_name("org.apache.logging.log4j:log4j-core", "Maven") is None


def test_g7_out_of_scope_does_not_retry_researcher():
    """Aunque el LLM insista en volver al investigador (hallazgo F2-fix en Phoenix)."""
    st = initial_state("q") | {"research_findings": "FUERA DE ALCANCE: firmware",
                               "revisions": {"researcher": 1, "analyst": 0}}
    d = SupervisorDecision(research_issues=["R1: falta consultar el firmware"], analysis_issues=[],
                           next_agent="researcher", instruction="consultá el firmware", reasoning="x")
    assert apply_guardrails(d, st)[0] == "FINISH"
