"""Observabilidad con Arize Phoenix (OpenTelemetry + OpenInference).

`setup_tracing()` instrumenta LangChain/LangGraph: cada nodo del grafo, cada
llamada al LLM (prompt, respuesta, tokens) y cada tool queda registrada como un
span. En Phoenix se ve el árbol completo de la delegación:

    LangGraph
    ├── supervisor   -> ChatOpenAI (decisión estructurada)
    ├── researcher   -> agente ReAct -> query_osv x4, web_search
    ├── supervisor
    ├── analyst      -> agente ReAct -> rank_dependencies
    ├── supervisor
    └── synthesizer  -> ChatOpenAI

Phoenix local:  uv run phoenix serve   ->  http://localhost:6006
"""

import os

import httpx
from dotenv import load_dotenv

load_dotenv()

DEFAULT_ENDPOINT = "http://localhost:6006"
_tracer_provider = None


def setup_tracing(project_name: str | None = None):
    """Activa el tracing si PHOENIX_TRACING no es 'false' y Phoenix responde.
    Es idempotente: llamarla varias veces no duplica la instrumentación."""
    global _tracer_provider
    if _tracer_provider is not None:
        return _tracer_provider
    if os.getenv("PHOENIX_TRACING", "true").lower() == "false":
        return None

    base = os.getenv("PHOENIX_COLLECTOR_ENDPOINT", DEFAULT_ENDPOINT).rstrip("/")
    # Si Phoenix no está levantado, seguimos sin tracing en vez de llenar la
    # consola de errores del exporter.
    if not os.getenv("PHOENIX_API_KEY"):
        try:
            httpx.get(base, timeout=2)
        except httpx.HTTPError:
            print(f"⚠️  Phoenix no responde en {base}: se ejecuta sin tracing "
                  "(levantalo con `uv run phoenix serve`).")
            return None

    from openinference.instrumentation.langchain import LangChainInstrumentor
    from phoenix.otel import register

    _tracer_provider = register(
        project_name=project_name or os.getenv("PHOENIX_PROJECT_NAME", "vuln-orchestrator"),
        endpoint=f"{base}/v1/traces",
        batch=True,       # exporta en segundo plano (no frena al grafo)
        verbose=False,
    )
    LangChainInstrumentor().instrument(tracer_provider=_tracer_provider)
    print(f"🔭 Tracing activo -> {base}")
    return _tracer_provider


def flush_tracing() -> None:
    """Envía los spans pendientes. Llamarla al final de un script corto."""
    if _tracer_provider is not None:
        _tracer_provider.force_flush()
