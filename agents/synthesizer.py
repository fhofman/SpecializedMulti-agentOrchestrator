"""Fase de síntesis final: redacta la respuesta para el usuario.

Solo corre cuando el supervisor decidió FINISH. Recibe la última versión
VALIDADA de cada especialista y las advertencias pendientes del supervisor.
"""

from langchain_core.messages import AIMessage

from agents.llm import get_llm
from state import AgentState, make_contribution

SYSTEM_PROMPT = """Redactás la respuesta final para un equipo de desarrollo, en español.
Combiná el reporte del Analista (fuente de los números y el orden) con el contexto
del Investigador (explotación activa, advisories). No agregues datos nuevos ni cambies
números, versiones o el orden del ranking. Las advertencias del analista se copian
TEXTUALMENTE (sin reformular cantidades).

Estructura:
# Reporte de vulnerabilidades
**Resumen ejecutivo**: 2-3 oraciones (qué es lo más urgente y por qué).
## Prioridades  (tabla del analista)
## Plan de acción
## Contexto relevante  (explotación activa / advisories, con URL si las hay)
## Advertencias  (limitaciones de datos y, si existen, observaciones del supervisor no resueltas)
"""

_llm = get_llm()


def synthesizer_node(state: AgentState) -> dict:
    if not state.get("analysis_report"):
        # Sin análisis NUNCA se afirma que el proyecto es seguro (hallazgo F2/Q3).
        answer = (
            "# No se pudo completar el análisis de vulnerabilidades\n\n"
            "**Esto no significa que las dependencias sean seguras**: no hubo datos suficientes "
            "para evaluarlas (fuera de alcance, nombres no encontrados o herramientas no disponibles).\n\n"
            "Este sistema analiza dependencias de Maven (Java), npm (JavaScript/Node), "
            "PyPI (Python) y Packagist (PHP).\n\n"
            f"## Lo que informó el investigador\n{state.get('research_findings') or '(nada)'}\n\n"
            f"## Decisión del supervisor\n{state.get('supervisor_feedback', '')}"
        )
    else:
        context = f"""CONSULTA: {state['user_query']}

REPORTE DEL ANALISTA:
{state['analysis_report']}

HALLAZGOS DEL INVESTIGADOR:
{state.get('research_findings', '')}

OBSERVACIONES DEL SUPERVISOR NO RESUELTAS:
{chr(10).join(state.get('pending_issues', [])) or 'ninguna'}"""
        answer = _llm.invoke([("system", SYSTEM_PROMPT), ("user", context)]).content

    return {
        "final_answer": answer,
        "task_completed": True,
        "messages": [AIMessage(content=answer, name="synthesizer")],
        "contributions": [make_contribution("synthesizer", state.get("step_count", 0), 1, "síntesis final", answer)],
    }
