"""Punto de entrada: ejecuta el orquestador mostrando la delegación paso a paso.

Uso:
    uv run python main.py
    uv run python main.py "Tengo express 4.17.1 (npm) y requests 2.25.0 (PyPI)"
"""

import sys
import uuid

from openinference.instrumentation import using_attributes

from tracing import flush_tracing, setup_tracing

setup_tracing()  # antes de construir el grafo, para que todo quede instrumentado

from graph import graph  # noqa: E402
from state import MAX_STEPS, initial_state  # noqa: E402

DEMO_QUERY = (
    "Tengo estas dependencias: lodash 4.17.15 (npm), django 3.2.0 (PyPI), "
    "log4j-core 2.14.1 (Maven) y guzzlehttp/guzzle 7.4.0 (Packagist). "
    "¿Qué vulnerabilidades tienen y cuál debería arreglar primero?"
)

ICONS = {"supervisor": "🧭", "researcher": "🔎", "analyst": "📊", "synthesizer": "📝"}


def run(query: str) -> dict:
    print(f"\n👤 CONSULTA: {query}\n" + "=" * 80)
    final_state = {}
    # using_attributes agrupa todos los spans de esta corrida en una sesión de
    # Phoenix y les agrega metadata filtrable (sin efecto si no hay tracing).
    with using_attributes(
        session_id=str(uuid.uuid4()),
        metadata={"query": query},
        tags=["vuln-orchestrator", "demo"],
    ):
        _stream(query, final_state)

    print("\n" + "=" * 80 + "\n" + final_state.get("final_answer", "(sin respuesta)"))
    flush_tracing()
    return final_state


def _stream(query: str, final_state: dict) -> None:
    # stream_mode="updates": un evento por nodo ejecutado, con lo que escribió.
    for event in graph.stream(
        initial_state(query),
        config={"recursion_limit": MAX_STEPS * 3, "run_name": "vuln-orchestrator"},
        stream_mode="updates",
    ):
        for node, update in event.items():
            final_state.update(update)
            icon = ICONS.get(node, "•")
            if node == "supervisor":
                print(f"\n{icon} SUPERVISOR -> {update['messages'][0].content}")
            elif node == "synthesizer":
                print(f"\n{icon} SÍNTESIS FINAL lista")
            else:
                run_n = update["revisions"][node]
                preview = update["messages"][0].content[:300].replace("\n", " ")
                print(f"\n{icon} {node.upper()} (ejecución #{run_n}): {preview}...")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else DEMO_QUERY)
