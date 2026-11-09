"""Estado compartido del orquestador multi-agente.

El estado es la "pizarra" que todos los nodos del grafo leen y escriben.
LangGraph se lo pasa a cada nodo, y cada nodo devuelve SOLO las claves que
quiere modificar. Cómo se combina ese update con el valor anterior lo define
el *reducer* de cada campo:

- Sin reducer (campo normal)  -> el valor nuevo REEMPLAZA al anterior.
- Con reducer (Annotated[...]) -> se aplica la función, p.ej. operator.add
  CONCATENA listas en lugar de pisarlas.
"""

import operator
from datetime import datetime, timezone
from typing import Annotated, Literal, TypedDict

from langgraph.graph import MessagesState

# Nombres de los nodos especialistas. Usar Literal hace que el supervisor
# (y el type checker) solo puedan elegir entre opciones válidas.
AgentName = Literal["researcher", "analyst"]
NextStep = Literal["researcher", "analyst", "FINISH"]

# Condición de parada dura contra el "supervisor infinito".
MAX_STEPS = 8          # máximo de turnos totales del supervisor
MAX_RUNS_PER_AGENT = 3  # 1 versión original + 2 refinamientos por especialista


class Contribution(TypedDict):
    """Un aporte registrado de un agente: quién, qué, cuándo y en qué intento."""

    agent: str           # "researcher" | "analyst" | "supervisor"
    step: int            # número de turno del supervisor en que ocurrió
    attempt: int         # 1 = primera versión, 2+ = refinamiento
    instruction: str     # qué se le pidió (trazabilidad de la delegación)
    content: str         # qué devolvió
    timestamp: str


class AgentState(MessagesState):
    """Estado del grafo. Hereda `messages` (con reducer add_messages)."""

    # --- Entrada -----------------------------------------------------------
    user_query: str

    # --- Control de flujo (lo escribe el Supervisor) ------------------------
    next_agent: NextStep
    current_instruction: str      # instrucción ACOTADA para el especialista
    supervisor_feedback: str      # por qué decidió lo que decidió
    pending_issues: list[str]     # fallos de rúbrica sin resolver al terminar
    step_count: int
    revisions: dict[str, int]     # veces que corrió cada uno: {"researcher": 2, "analyst": 1}
    task_completed: bool

    # --- Resultados de especialistas (última versión válida) ----------------
    # Se REEMPLAZAN: si el supervisor pide refinar, la versión nueva sustituye
    # a la anterior y los demás agentes siempre leen la más reciente.
    research_findings: str             # resumen del Investigador (texto)
    vulnerability_data: list[dict]     # datos crudos de OSV (estructurados, sin LLM)
    analysis_report: str               # reporte priorizado del Analista

    # --- Historial auditable ------------------------------------------------
    # Se ACUMULA (operator.add): nunca se pierde quién aportó qué.
    contributions: Annotated[list[Contribution], operator.add]

    # --- Salida -------------------------------------------------------------
    final_answer: str


def make_contribution(
    agent: str, step: int, attempt: int, instruction: str, content: str
) -> Contribution:
    """Helper para que todos los nodos registren aportes con el mismo formato."""
    return Contribution(
        agent=agent,
        step=step,
        attempt=attempt,
        instruction=instruction,
        content=content,
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


def initial_state(user_query: str) -> dict:
    """Estado inicial con todos los campos en valores neutros."""
    return {
        "messages": [("user", user_query)],
        "user_query": user_query,
        "next_agent": "researcher",
        "current_instruction": "",
        "supervisor_feedback": "",
        "pending_issues": [],
        "step_count": 0,
        "revisions": {"researcher": 0, "analyst": 0},
        "task_completed": False,
        "research_findings": "",
        "vulnerability_data": [],
        "analysis_report": "",
        "contributions": [],
        "final_answer": "",
    }
