"""Genera tráfico observable en Phoenix: 5 consultas complejas + escenarios de fallo.

    uv run phoenix serve                                  # en otra terminal
    uv run python scripts/generate_traffic.py             # todos los escenarios
    uv run python scripts/generate_traffic.py F1          # solo algunos (por id)
    uv run python scripts/generate_traffic.py Q3 F1 F2 --suffix=-fix   # re-ejecución post-fix

Cada escenario es una traza en el proyecto `vuln-orchestrator-traffic`, con
session_id = id del escenario y metadata filtrable (scenario, kind, query).
El resumen de cada corrida se guarda en docs/traffic_runs.json.
"""

import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tracing import flush_tracing, setup_tracing  # noqa: E402

PROJECT = "vuln-orchestrator-traffic"
setup_tracing(project_name=PROJECT)

from openinference.instrumentation import using_attributes  # noqa: E402

import agents.research_agent as research_module  # noqa: E402
import tools.vuln_search as vuln_search  # noqa: E402
from graph import graph  # noqa: E402
from state import MAX_STEPS, initial_state  # noqa: E402

SCENARIOS = [
    {
        "id": "Q1-java-spring",
        "kind": "consulta",
        "query": "Auditá este backend Java: org.springframework:spring-web 5.3.0, "
                 "com.fasterxml.jackson.core:jackson-databind 2.9.8 y org.apache.struts:struts2-core 2.5.10 "
                 "(Maven). ¿Cuál tiene riesgo de ejecución remota de código y en qué orden actualizo?",
    },
    {
        "id": "Q2-node-api",
        "kind": "consulta",
        "query": "Mi API en Node usa express 4.17.1, jsonwebtoken 8.5.1, axios 0.21.0 y minimist 1.2.0 (npm). "
                 "¿Qué vulnerabilidades tienen, cuáles se explotan activamente y qué actualizo primero?",
    },
    {
        "id": "Q3-python-web",
        "kind": "consulta",
        "query": "Proyecto Python con requests 2.25.0, pyyaml 5.3, flask 1.0, jinja2 2.10 y pillow 8.0.0 (PyPI). "
                 "Priorizá la remediación y decime a qué versión subir cada uno.",
    },
    {
        "id": "Q4-php-laravel",
        "kind": "consulta",
        "query": "Aplicación PHP con laravel/framework 8.0.0, symfony/http-kernel 4.4.0, "
                 "phpmailer/phpmailer 6.0.0 y twig/twig 2.0.0 (Packagist). ¿Qué riesgo tiene y qué arreglo primero?",
    },
    {
        "id": "Q5-polyglot",
        "kind": "consulta",
        "query": "Tengo microservicios en 4 lenguajes: log4j-core 2.14.1 (Maven), lodash 4.17.15 (npm), "
                 "django 3.2.0 (PyPI) y guzzlehttp/guzzle 7.4.0 (Packagist). Armá un plan de remediación "
                 "priorizado y contame si alguna vulnerabilidad se explota activamente.",
    },
    {
        "id": "F1-tools-down",
        "kind": "fallo",
        "fault": "tools_down",
        "query": "Revisá express 4.17.1 (npm) y requests 2.25.0 (PyPI). ¿Qué vulnerabilidades tienen?",
    },
    {
        "id": "F2-out-of-scope",
        "kind": "fallo",
        "query": "Analizá las vulnerabilidades del firmware 3.15 de mi router TP-Link Archer C7 "
                 "y de Windows 10 21H2. ¿Cuál parcheo primero?",
    },
]


@contextmanager
def tools_down():
    """Fault injection: OSV.dev 'desconectado' (excepción inesperada en la tool)
    y Tavily con API key inválida. Restaura todo al salir."""
    original_post = vuln_search.httpx.post
    original_key = os.environ.get("TAVILY_API_KEY", "")

    def broken_post(*args, **kwargs):
        raise ConnectionError("OSV.dev desconectado (fault injection)")

    vuln_search.httpx.post = broken_post
    os.environ["TAVILY_API_KEY"] = "tvly-invalid-key-fault-injection"
    research_module._research_agent = research_module.build_research_agent()
    try:
        yield
    finally:
        vuln_search.httpx.post = original_post
        os.environ["TAVILY_API_KEY"] = original_key
        research_module._research_agent = research_module.build_research_agent()


@contextmanager
def no_fault():
    yield


def run_scenario(sc: dict) -> dict:
    print(f"\n▶ {sc['id']} ({sc['kind']})")
    fault = tools_down if sc.get("fault") == "tools_down" else no_fault
    t0 = time.perf_counter()
    summary = {"id": sc["id"], "kind": sc["kind"], "query": sc["query"]}
    with fault(), using_attributes(
        session_id=sc["id"],
        metadata={"scenario": sc["id"], "kind": sc["kind"], "query": sc["query"]},
        tags=["traffic", sc["kind"]],
    ):
        try:
            final = graph.invoke(
                initial_state(sc["query"]),
                config={"recursion_limit": MAX_STEPS * 3, "run_name": sc["id"]},
            )
            summary |= {
                "status": "ok",
                "supervisor_steps": final["step_count"],
                "runs": final["revisions"],
                "pending_issues": final.get("pending_issues", []),
                "route": [c["content"].split(".")[0] for c in final["contributions"] if c["agent"] == "supervisor"],
                "final_answer_head": final["final_answer"][:600],
            }
        except Exception as exc:  # el fallo también queda registrado en la traza
            summary |= {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    summary["seconds"] = round(time.perf_counter() - t0, 1)
    print(f"  {summary['status']} en {summary['seconds']}s", summary.get("route") or summary.get("error"))
    return summary


def main(args: list[str]) -> None:
    # --suffix=-fix renombra las trazas (ej. 'F1-tools-down-fix') para comparar antes/después.
    suffix = next((a.split("=", 1)[1] for a in args if a.startswith("--suffix=")), "")
    selected = [a for a in args if not a.startswith("--")]
    scenarios = [s | {"id": s["id"] + suffix} for s in SCENARIOS
                 if not selected or any(s["id"].startswith(x) for x in selected)]
    out = Path("docs/traffic_runs.json")
    previous = json.loads(out.read_text()) if out.exists() else []
    results = [run_scenario(s) for s in scenarios]
    flush_tracing()
    # Se agregan al historial (permite comparar antes/después de un fix).
    out.write_text(json.dumps(previous + results, ensure_ascii=False, indent=2))
    print(f"\nResumen guardado en {out}")


if __name__ == "__main__":
    main(sys.argv[1:])
