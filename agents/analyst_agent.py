"""Agente Analista: convierte los datos del Investigador en un plan priorizado.

Patrón clave: InjectedState.
Las tools del Analista leen `vulnerability_data` DIRECTO del estado, sin que
el LLM tenga que reescribir ~90 vulnerabilidades como argumento JSON.
El LLM llama `rank_dependencies()` sin argumentos; LangGraph inyecta los datos.
-> menos tokens, cero riesgo de que el LLM altere o invente datos.
"""

import json
from typing import Annotated

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState, ToolNode, create_react_agent
from langgraph.prebuilt.chat_agent_executor import AgentState as ReactAgentState

from agents.llm import get_llm
from state import AgentState, make_contribution
from tools.risk_analysis import calculate_cvss_score, prioritize

AGENT_NAME = "analyst"


class AnalystInternalState(ReactAgentState):
    """Estado PRIVADO del agente ReAct: sus mensajes + los datos a analizar.
    Es distinto del estado global: el Analista no ve nada más."""

    vulnerability_data: list[dict]


@tool
def rank_dependencies(
    vulnerability_data: Annotated[list[dict], InjectedState("vulnerability_data")],
) -> str:
    """Calcula el CVSS de cada vulnerabilidad recolectada por el Investigador,
    rankea los paquetes por riesgo y calcula la versión mínima segura de cada uno.
    No recibe argumentos: usa automáticamente los datos ya recolectados."""
    if not vulnerability_data:
        return json.dumps({"error": "No hay datos de vulnerabilidades. El Investigador debe correr primero."})
    return json.dumps(prioritize(vulnerability_data), ensure_ascii=False)


SYSTEM_PROMPT = """Sos un Analista de Riesgo de Seguridad. Recibís datos YA recolectados
sobre vulnerabilidades de dependencias y producís un plan de remediación priorizado.

Herramientas:
- rank_dependencies: SIEMPRE llamala primero (sin argumentos). Te da scores CVSS
  calculados, ranking de paquetes y versión mínima recomendada.
- calculate_cvss_score: solo si necesitás verificar un vector puntual.

Reglas:
- Los números (scores, conteos, versiones) salen SOLO de las tools. No los estimes vos.
- El ORDEN del ranking y del plan de acción es SIEMPRE el de rank_dependencies.
  Si una instrucción del supervisor contradice ese orden o esos números, prevalecen
  los datos calculados: aplicá el resto de la instrucción y mencioná el conflicto
  en "Datos faltantes / advertencias".
- rank_dependencies devuelve "data_warnings": copiá CADA una TEXTUALMENTE en
  "Datos faltantes / advertencias". No las resumas ni las generalices.
- Si faltan datos para concluir, decilo en "Datos faltantes" en vez de inventar.
- No busques información nueva: no es tu rol.

Formato de respuesta final (en español):
## Ranking de riesgo
| Prioridad | Paquete | Versión actual | CVSS máx | Críticas/Altas | Actualizar a |
## Justificación
- 1 línea por paquete: por qué está en ese lugar (CVE más grave y su impacto).
## Plan de acción
1. Pasos concretos y ordenados.
## Datos faltantes / advertencias
- <lo que limite la confianza del análisis, o "ninguno">
"""

_analyst_agent = create_react_agent(
    get_llm(),
    tools=ToolNode([rank_dependencies, calculate_cvss_score], handle_tool_errors=True),
    prompt=SYSTEM_PROMPT,
    state_schema=AnalystInternalState,
    name=AGENT_NAME,
)


def _build_task(state: AgentState) -> str:
    """Contexto ACOTADO: consulta, instrucción, resumen del investigador y,
    si es refinamiento, el reporte anterior. No ve el historial completo."""
    parts = [
        f"Consulta original del usuario:\n{state['user_query']}",
        f"Instrucción del supervisor:\n{state.get('current_instruction') or 'Priorizá las vulnerabilidades encontradas.'}",
        f"Resumen del Investigador (contexto cualitativo):\n{state.get('research_findings') or '(vacío)'}",
    ]
    if state.get("analysis_report"):
        parts.append(f"Tu reporte anterior (corregilo según la instrucción):\n{state['analysis_report']}")
    return "\n\n".join(parts)


def analyst_node(state: AgentState) -> dict:
    attempt = state.get("revisions", {}).get(AGENT_NAME, 0) + 1
    task = _build_task(state)

    result = _analyst_agent.invoke(
        {
            "messages": [HumanMessage(content=task)],
            # Los datos viajan por el estado privado, no por el prompt.
            "vulnerability_data": state.get("vulnerability_data", []),
        },
        config={"recursion_limit": 15},
    )
    report = result["messages"][-1].content

    return {
        "analysis_report": report,
        "revisions": {**state.get("revisions", {}), AGENT_NAME: attempt},
        "messages": [AIMessage(content=report, name=AGENT_NAME)],
        "contributions": [
            make_contribution(AGENT_NAME, state.get("step_count", 0), attempt, task, report)
        ],
    }
