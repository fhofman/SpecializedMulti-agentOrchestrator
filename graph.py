"""Grafo principal: topología jerárquica (Supervisor -> especialistas -> Supervisor).

    START -> supervisor --(condicional)--> researcher  --> supervisor
                                      \\--> analyst     --> supervisor
                                      \\--> synthesizer --> END
"""

from pathlib import Path
from typing import Literal

from langgraph.graph import END, START, StateGraph

from agents.analyst_agent import analyst_node
from agents.research_agent import research_node
from agents.supervisor import supervisor_node
from agents.synthesizer import synthesizer_node
from state import AgentState


def route_from_supervisor(state: AgentState) -> Literal["researcher", "analyst", "synthesizer"]:
    """Arista condicional. El Literal del retorno le dice a LangGraph (y al
    diagrama) cuáles son los únicos destinos posibles desde el supervisor."""
    if state["next_agent"] == "FINISH":
        return "synthesizer"
    return state["next_agent"]


def build_graph():
    builder = StateGraph(AgentState)

    builder.add_node("supervisor", supervisor_node)
    builder.add_node("researcher", research_node)
    builder.add_node("analyst", analyst_node)
    builder.add_node("synthesizer", synthesizer_node)

    builder.add_edge(START, "supervisor")
    builder.add_conditional_edges("supervisor", route_from_supervisor)
    # Los especialistas SIEMPRE reportan al supervisor: nunca hablan entre sí.
    builder.add_edge("researcher", "supervisor")
    builder.add_edge("analyst", "supervisor")
    builder.add_edge("synthesizer", END)

    return builder.compile()


graph = build_graph()


def save_diagram(out_dir: str = "docs") -> None:
    """Genera docs/graph.mmd (texto Mermaid) y docs/graph.png."""
    Path(out_dir).mkdir(exist_ok=True)
    g = graph.get_graph()
    Path(out_dir, "graph.mmd").write_text(g.draw_mermaid())
    try:
        Path(out_dir, "graph.png").write_bytes(g.draw_mermaid_png())  # usa la API de mermaid.ink
    except Exception as exc:  # sin internet: queda el .mmd
        print(f"No se pudo generar el PNG ({exc}); usá docs/graph.mmd")


if __name__ == "__main__":
    save_diagram()
    print(graph.get_graph().draw_mermaid())
