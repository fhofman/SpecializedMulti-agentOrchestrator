"""Supervisor: router inteligente + validador (rúbrica) + controlador de flujo.

Tres capas de decisión, de más "blanda" a más "dura":
1. HECHOS VERIFICABLES: Python calcula datos objetivos del estado (qué paquetes
   se consultaron, cuáles se recortaron, cuántos scores son aproximados) y se los
   da al LLM. Así la rúbrica se evalúa contra hechos, no contra impresiones.
2. LLM CON RÚBRICA: decide el próximo paso con salida ESTRUCTURADA (Pydantic +
   Literal): no puede responder algo fuera de researcher/analyst/FINISH.
3. GUARDRAILS EN CÓDIGO: reglas que el LLM no puede saltarse (límite de pasos,
   límite de refinamientos, no terminar sin análisis). Evitan el supervisor infinito.
"""

from langchain_core.messages import AIMessage
from pydantic import BaseModel, Field

from agents.llm import get_llm
from state import MAX_RUNS_PER_AGENT, MAX_STEPS, AgentState, NextStep, make_contribution
from tools.risk_analysis import prioritize, score_vulnerability


class SupervisorDecision(BaseModel):
    """Salida estructurada del supervisor. El orden de los campos importa:
    el LLM primero evalúa la rúbrica y DESPUÉS decide (razonar antes de actuar)."""

    research_issues: list[str] = Field(description="Fallos concretos de R1/R2 (ej. 'R1: falta consultar express'). Vacío si OK o si aún no hay investigación.")
    analysis_issues: list[str] = Field(description="Fallos concretos de A4 (ej. 'A4: el plan no está ordenado'). Vacío si OK o si aún no hay análisis.")
    next_agent: NextStep = Field(description="'researcher', 'analyst' o 'FINISH'")
    instruction: str = Field(description="Instrucción concreta y acotada para el agente elegido. Si es un refinamiento, decí exactamente qué corregir. Vacío si FINISH.")
    reasoning: str = Field(description="Una oración explicando la decisión")


SYSTEM_PROMPT = f"""Sos el Supervisor de un equipo de análisis de vulnerabilidades en dependencias
(Java/Maven, JavaScript-Node/npm, Python/PyPI, PHP/Packagist). Coordinás a:
- researcher: consulta OSV.dev y la web. Es el ÚNICO que obtiene datos nuevos.
- analyst: calcula CVSS, rankea paquetes y arma el plan de remediación. NO busca datos.

Dado el estado actual, decidí quién interviene ahora o si es momento de FINISH.

Flujo esperado: researcher -> analyst -> FINISH. Pedí un refinamiento SOLO si un
criterio de la rúbrica falla de forma concreta y corregible.

La rúbrica tiene dos tipos de criterios:

CRITERIOS OBJETIVOS (los verifica el CÓDIGO; NO los evalúes vos ni los repitas):
- A1 (todos los paquetes en el ranking), A2 (orden por riesgo y versión recomendada
  en cada fila) y A3 (advertencias precisas de análisis parcial y scores aproximados).
  Su resultado está en CHEQUEOS AUTOMÁTICOS.
  Si dice "sin fallos", esos criterios están CUMPLIDOS.

CRITERIOS DE JUICIO (los evaluás vos):
R1. Todos los paquetes que pidió el usuario fueron consultados (compará la consulta con HECHOS).
R2. Ninguna consulta falló sin explicación.
A4. El plan de acción es concreto, ordenado y accionable.
Reportá un fallo SOLO si podés señalar el error concreto. No pidas cambios de estilo.

RESOLUCIÓN DE CONFLICTOS:
- Si el analista reporta datos faltantes que solo se obtienen buscando -> researcher.
- Si el texto de un agente contradice los HECHOS, los HECHOS ganan: pedí corrección al autor.
- Cada agente tiene máximo {MAX_RUNS_PER_AGENT} ejecuciones; no pidas refinamientos por detalles de estilo.
- Si los fallos restantes no son corregibles con los datos disponibles -> FINISH.
"""


def compute_facts(state: AgentState) -> str:
    """Hechos objetivos calculados en Python (no por un LLM) para la rúbrica."""
    data = state.get("vulnerability_data", [])
    if not data:
        return "- Todavía no hay datos de OSV."
    lines = []
    for pkg in data:
        vulns = pkg["vulnerabilities"]
        approx = sum(1 for v in vulns if score_vulnerability(v.get("cvss_vector"), v.get("severity_label"))[1] != "cvss3.1")
        partial = " (ANÁLISIS PARCIAL)" if pkg["total_found"] > len(vulns) else ""
        lines.append(
            f"- {pkg['package']}@{pkg['version']} ({pkg['ecosystem']}): "
            f"{len(vulns)} analizadas de {pkg['total_found']}{partial}; scores aproximados: {approx}"
        )
    return "\n".join(lines)


def _short(name: str) -> str:
    """'org.apache.logging.log4j:log4j-core' -> 'log4j-core'; 'guzzlehttp/guzzle' -> 'guzzle'."""
    return name.split(":")[-1].split("/")[-1].lower()


def automatic_checks(state: AgentState) -> list[str]:
    """Validación DETERMINÍSTICA de la rúbrica A3 (lo objetivo no se le deja al LLM).
    Devuelve la lista de fallos concretos; vacía si todo OK o si no hay reporte."""
    report = state.get("analysis_report", "")
    if not report:
        return []
    lower = report.lower()
    # Buscamos solo en la sección de advertencias (si existe).
    idx = max(lower.find("datos faltantes"), lower.find("advertencia"))
    warnings = lower[idx:] if idx >= 0 else lower
    failures = []
    for pkg in state.get("vulnerability_data", []):
        name, vulns = _short(pkg["package"]), pkg["vulnerabilities"]
        if pkg["total_found"] > len(vulns) and name not in warnings:
            failures.append(f"A3: no advierte que {name} se analizó parcialmente ({len(vulns)} de {pkg['total_found']})")
        approx = sum(1 for v in vulns if score_vulnerability(v.get("cvss_vector"), v.get("severity_label"))[1] != "cvss3.1")
        if approx and not (name in warnings and "aprox" in warnings):
            failures.append(f"A3: no advierte que {name} tiene {approx} scores aproximados (sin CVSS v3)")
        if vulns and name not in lower:
            failures.append(f"A1: {name} no aparece en el ranking")

    # A2: orden y versión recomendada, comparados contra el cálculo determinístico.
    table_rows = [line for line in lower.splitlines() if line.strip().startswith("|")]
    positions = []
    for pkg in prioritize(state.get("vulnerability_data", []))["ranking"]:
        name = _short(pkg["package"])
        row_idx = next((i for i, row in enumerate(table_rows) if name in row), None)
        if row_idx is None:
            continue  # ya lo reporta A1
        positions.append((name, row_idx))
        version = pkg["recommended_version"]
        if version and version.lower() not in table_rows[row_idx]:
            failures.append(f"A2: la fila de {name} no indica la versión recomendada {version}")
    expected = [n for n, _ in positions]
    actual = [n for n, _ in sorted(positions, key=lambda x: x[1])]
    if expected != actual:
        failures.append(f"A2: el orden del ranking debería ser {' > '.join(expected)}")
    return failures


def _build_context(state: AgentState) -> str:
    """El supervisor ve resultados y métricas de control, NO los mensajes internos
    de los agentes ni los JSON crudos (evita contaminación de contexto)."""
    runs = state.get("revisions", {})
    return f"""CONSULTA DEL USUARIO:
{state['user_query']}

CONTROL: paso {state.get('step_count', 0) + 1} de {MAX_STEPS}. Ejecuciones: researcher={runs.get('researcher', 0)}/{MAX_RUNS_PER_AGENT}, analyst={runs.get('analyst', 0)}/{MAX_RUNS_PER_AGENT}.

HECHOS VERIFICABLES (calculados por código):
{compute_facts(state)}

CHEQUEOS AUTOMÁTICOS DEL REPORTE (si hay fallos, el reporte NO cumple la rúbrica):
{chr(10).join('- ' + f for f in automatic_checks(state)) or '- sin fallos (o todavía no hay reporte)'}

HALLAZGOS DEL INVESTIGADOR:
{state.get('research_findings') or '(todavía no investigó)'}

REPORTE DEL ANALISTA:
{state.get('analysis_report') or '(todavía no analizó)'}
"""


CODE_OWNED = ("A1", "A2", "A3")  # criterios objetivos: los decide automatic_checks, no el LLM


def judged_issues(decision: SupervisorDecision, state: AgentState) -> tuple[list[str], list[str]]:
    """Filtra los fallos que reporta el LLM: descarta los de etapas que todavía no
    corrieron y los de criterios objetivos (que son responsabilidad del código)."""
    research = decision.research_issues if state.get("research_findings") else []
    analysis = decision.analysis_issues if state.get("analysis_report") else []
    analysis = [i for i in analysis if not i.strip().upper().startswith(CODE_OWNED)]
    return research, analysis


def apply_guardrails(decision: SupervisorDecision, state: AgentState) -> tuple[str, str, list[str]]:
    """Reglas duras que corrigen al LLM. Devuelve (next, instrucción, notas)."""
    nxt, instruction, notes = decision.next_agent, decision.instruction, []
    research_issues, analysis_issues = judged_issues(decision, state)
    runs = state.get("revisions", {})
    step = state.get("step_count", 0) + 1

    def can_run(agent: str) -> bool:
        return runs.get(agent, 0) < MAX_RUNS_PER_AGENT

    # G5: los chequeos automáticos fallan sobre el REPORTE -> el responsable es el
    # analista (no el investigador), con una instrucción precisa. Resuelve el
    # conflicto "¿a quién le devuelvo el trabajo?" de forma determinística.
    failures = automatic_checks(state)
    # Excepción: si el LLM manda al researcher por un problema REAL de investigación, se respeta.
    legit_research_request = nxt == "researcher" and bool(research_issues)
    if failures and not legit_research_request:
        if can_run("analyst"):
            if nxt != "analyst":
                notes.append(f"G5: chequeos automáticos fallidos, {nxt} -> analyst")
            nxt = "analyst"
            instruction = "Corregí tu reporte: " + "; ".join(failures) + ". Mantené el resto igual."

    # G6: refinamiento sin fallo concreto -> no se re-trabaja (anti bucle "por las dudas").
    if not failures:
        if nxt == "analyst" and state.get("analysis_report") and not analysis_issues:
            nxt = "FINISH"
            notes.append("G6: se pidió refinar al analista sin fallo concreto -> FINISH")
        elif nxt == "researcher" and state.get("research_findings") and not research_issues:
            nxt = "analyst" if not state.get("analysis_report") else "FINISH"
            notes.append(f"G6: se pidió refinar al investigador sin fallo concreto -> {nxt}")

    # G7: los datos existen pero no hay NINGUNA vulnerabilidad (o el pedido está fuera
    # de alcance): no hay nada que rankear, el analista solo gastaría tokens.
    # (Hallazgo de Phoenix: en Q3/F2 el analista corrió 3 veces sobre datos vacíos.)
    data = state.get("vulnerability_data", [])
    no_vulns = bool(data) and all(not p["vulnerabilities"] for p in data)
    out_of_scope = "FUERA DE ALCANCE" in state.get("research_findings", "").upper()
    if (nxt == "analyst" and no_vulns) or (out_of_scope and nxt != "FINISH"):
        notes.append(f"G7: {'fuera de alcance' if out_of_scope else 'sin vulnerabilidades que analizar'}, {nxt} -> FINISH")
        nxt = "FINISH"

    # G1: no se puede analizar sin datos.
    if nxt == "analyst" and not state.get("vulnerability_data") and can_run("researcher"):
        nxt, instruction = "researcher", "Consultá OSV para todos los paquetes de la consulta."
        notes.append("G1: se pidió analista sin datos -> researcher")

    # G2: no se puede terminar sin análisis (si todavía hay presupuesto).
    if nxt == "FINISH" and not state.get("analysis_report") and not (no_vulns or out_of_scope):
        if state.get("vulnerability_data") and can_run("analyst"):
            nxt, instruction = "analyst", "Priorizá los paquetes por riesgo y armá el plan de remediación."
            notes.append("G2: FINISH sin análisis -> analyst")

    # G3: límite de ejecuciones por agente (anti bucle de refinamiento).
    if nxt in ("researcher", "analyst") and not can_run(nxt):
        notes.append(f"G3: {nxt} alcanzó {MAX_RUNS_PER_AGENT} ejecuciones -> FINISH")
        nxt = "FINISH"

    # G4: límite global de pasos (anti supervisor infinito).
    if step >= MAX_STEPS and nxt != "FINISH":
        notes.append(f"G4: se alcanzó MAX_STEPS={MAX_STEPS} -> FINISH")
        nxt = "FINISH"

    # G0: nunca delegar con instrucción vacía.
    if nxt != "FINISH" and not instruction.strip():
        instruction = {
            "researcher": "Consultá OSV para cada paquete de la consulta y buscá contexto web de las vulns más graves.",
            "analyst": "Priorizá los paquetes por riesgo y armá el plan de remediación.",
        }[nxt]
        notes.append("G0: instrucción vacía -> instrucción por defecto")

    return nxt, instruction, notes


_router = get_llm().with_structured_output(SupervisorDecision)


def supervisor_node(state: AgentState) -> dict:
    step = state.get("step_count", 0) + 1
    decision: SupervisorDecision = _router.invoke(
        [("system", SYSTEM_PROMPT), ("user", _build_context(state))]
    )
    nxt, instruction, notes = apply_guardrails(decision, state)

    research_issues, analysis_issues = judged_issues(decision, state)
    issues = research_issues + analysis_issues + automatic_checks(state)
    issues = list(dict.fromkeys(issues))  # sin duplicados, conserva el orden
    feedback = decision.reasoning
    if issues:
        feedback += " | Fallos de rúbrica: " + "; ".join(issues)
    if notes:
        feedback += " | Guardrails: " + "; ".join(notes)

    log = f"[paso {step}] -> {nxt}. {feedback}" + (f"\nInstrucción: {instruction}" if nxt != "FINISH" else "")
    return {
        "next_agent": nxt,
        "current_instruction": instruction if nxt != "FINISH" else "",
        "supervisor_feedback": feedback,
        # Fallos que quedan sin resolver si se termina (los usa la síntesis).
        "pending_issues": issues if nxt == "FINISH" else [],
        "step_count": step,
        "messages": [AIMessage(content=log, name="supervisor")],
        "contributions": [make_contribution("supervisor", step, 1, "decidir próximo paso", log)],
    }
