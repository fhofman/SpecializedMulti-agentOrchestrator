"""Agente Investigador: busca vulnerabilidades en fuentes externas.

Tiene dos piezas:
1. `build_research_agent()`: un agente ReAct (razona -> llama tool -> observa
   -> repite) creado con `create_react_agent`, con herramientas ACOTADAS.
2. `research_node(state)`: el nodo del grafo principal. Es un "adaptador":
   arma un input mínimo para el agente, lo ejecuta en su propio contexto y
   escribe en el estado global solo lo que importa.
"""

import json
import os

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.prebuilt import ToolNode, create_react_agent

from agents.llm import get_llm
from state import AgentState, make_contribution
from tools.vuln_search import get_web_search_tool, query_osv

AGENT_NAME = "researcher"

SYSTEM_PROMPT = """Sos un Investigador de Seguridad especializado en vulnerabilidades
de dependencias de software (Java/Maven, JavaScript y Node/npm, Python/PyPI, PHP/Packagist).

Tu trabajo es RECOLECTAR datos, no priorizar ni recomendar.

Herramientas:
- query_osv: fuente principal. Llamala UNA vez por cada paquete+versión.
  Usá el nombre EXACTO del registro oficial, nunca 'owner/repo' de GitHub:
  PyPI = 'requests', npm = 'express' (o '@scope/pkg'), Maven = 'groupId:artifactId',
  Packagist = 'vendor/paquete'. Si la tool devuelve "Nombre inválido", corregilo y reintentá.
- web_search: solo para contexto de las vulns más graves (CRITICAL/HIGH):
  explotación activa, advisories. Máximo 2 búsquedas.

Reglas:
- Nunca inventes CVEs, scores ni versiones: solo lo que devuelven las tools.
- Si un paquete no tiene vulns o la tool falla, decilo explícitamente.
- Si el pedido NO son dependencias de Maven/npm/PyPI/Packagist (ej. firmware, sistemas
  operativos, hardware), no consultes nada: respondé "FUERA DE ALCANCE: <motivo>".
- Si una tool falla, reportalo en "Limitaciones"; no inventes datos para compensar.

Formato de tu respuesta final (en español, conciso):
## Hallazgos por paquete
- <paquete>@<versión> (<ecosistema>): N vulns. Más relevantes: <ID/CVE> - <resumen corto> [severidad]
## Contexto web
- <hallazgo relevante con URL> (o "sin búsquedas web")
## Limitaciones
- <datos faltantes, errores o recortes>
"""


def build_research_agent():
    tools = [query_osv]
    if os.getenv("TAVILY_API_KEY"):
        tools.append(get_web_search_tool())
    # handle_tool_errors=True: una excepción en una tool vuelve al LLM como mensaje
    # de error en vez de tumbar el grafo (hallazgo del escenario F1 en Phoenix).
    return create_react_agent(
        get_llm(), tools=ToolNode(tools, handle_tool_errors=True), prompt=SYSTEM_PROMPT, name=AGENT_NAME
    )


# Se construye una sola vez al importar el módulo (no en cada llamada).
_research_agent = build_research_agent()


def _build_task(state: AgentState) -> str:
    """Arma el input ACOTADO: consulta + instrucción + (si es refinamiento)
    la versión anterior y el feedback. NO recibe el historial completo."""
    parts = [
        f"Consulta original del usuario:\n{state['user_query']}",
        f"Instrucción del supervisor:\n{state.get('current_instruction') or 'Investigá las vulnerabilidades de los paquetes mencionados.'}",
    ]
    if state.get("research_findings"):
        parts.append(f"Tu versión anterior (mejorala, no empieces de cero):\n{state['research_findings']}")
    return "\n\n".join(parts)


def _extract_osv_data(messages: list) -> list[dict]:
    """Toma los resultados de query_osv DIRECTO de los ToolMessages.

    No le pedimos al LLM que copie 50 vectores CVSS (podría alucinar o cortar):
    los datos estructurados salen de la tool, el LLM solo escribe el resumen.
    """
    data = []
    for msg in messages:
        if isinstance(msg, ToolMessage) and msg.name == "query_osv":
            try:
                result = json.loads(msg.content)
            except json.JSONDecodeError:
                continue
            if "error" not in result:
                data.append(result)
    return data


def research_node(state: AgentState) -> dict:
    attempt = state.get("revisions", {}).get(AGENT_NAME, 0) + 1
    task = _build_task(state)

    # El agente corre con SU PROPIA lista de mensajes (contexto aislado).
    # recursion_limit es un freno extra: evita que el ReAct loop se cuelgue.
    result = _research_agent.invoke(
        {"messages": [HumanMessage(content=task)]},
        config={"recursion_limit": 20},
    )
    internal_messages = result["messages"]
    summary = internal_messages[-1].content
    osv_data = _extract_osv_data(internal_messages)

    # Si en un refinamiento no volvió a consultar OSV, conservamos los datos previos.
    if not osv_data:
        osv_data = state.get("vulnerability_data", [])

    return {
        "research_findings": summary,
        "vulnerability_data": osv_data,
        "revisions": {**state.get("revisions", {}), AGENT_NAME: attempt},
        # Al historial global va SOLO la conclusión, firmada con name=.
        "messages": [AIMessage(content=summary, name=AGENT_NAME)],
        "contributions": [
            make_contribution(AGENT_NAME, state.get("step_count", 0), attempt, task, summary)
        ],
    }
