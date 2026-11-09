"""Analiza las trazas del proyecto de tráfico en Phoenix y genera métricas + gráficos.

    uv run python scripts/analyze_traces.py

Salida en docs/observability/: metrics.json y 4 gráficos PNG.
Responde: ¿qué span tuvo mayor latencia (LLM o recuperación)?, ¿cuántos tokens
consumió el proceso de razonamiento más largo?, ¿cómo quedaron registrados los errores?
"""

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from phoenix.client import Client  # noqa: E402

PROJECT = "vuln-orchestrator-traffic"
OUT = Path("docs/observability")
NODES = ("supervisor", "researcher", "analyst", "synthesizer")
RETRIEVAL_TOOLS = ("query_osv", "web_search")
ORDER = ["Q1-java-spring", "Q2-node-api", "Q3-python-web", "Q4-php-laravel", "Q5-polyglot",
         "F1-tools-down", "F2-out-of-scope", "Q3-python-web-fix", "F1-tools-down-fix",
         "F2-out-of-scope-fix", "F2-out-of-scope-fix2"]

# Precio de lista OpenAI gpt-4o-mini (USD por millón de tokens) usado como referencia.
PRICE_IN, PRICE_CACHED, PRICE_OUT = 0.15, 0.075, 0.60

# Paleta categórica validada (orden fijo) + neutro para "otros".
BLUE, ORANGE, AQUA, YELLOW, GRAY = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#c9c8c2"
INK, INK2, SURFACE = "#0b0b0b", "#52514e", "#fcfcfb"
AGENT_COLORS = {"supervisor": BLUE, "researcher": ORANGE, "analyst": AQUA, "synthesizer": YELLOW}

TOK_P, TOK_C, TOK_T = ("attributes.llm.token_count.prompt", "attributes.llm.token_count.completion",
                       "attributes.llm.token_count.total")
TOK_CACHE = "attributes.llm.token_count.prompt_details.cache_read"


def load_spans() -> pd.DataFrame:
    df = Client(base_url="http://localhost:6006").spans.get_spans_dataframe(
        project_identifier=PROJECT, limit=50_000)
    df = df.reset_index(drop=True)
    df["span_id"] = df["context.span_id"]
    df["latency"] = (pd.to_datetime(df.end_time) - pd.to_datetime(df.start_time)).dt.total_seconds()
    for col in (TOK_P, TOK_C, TOK_T, TOK_CACHE):
        df[col] = pd.to_numeric(df.get(col, 0), errors="coerce").fillna(0)

    by_id = df.set_index("span_id")
    parent = by_id["parent_id"].to_dict()
    name = by_id["name"].to_dict()
    kind = by_id["span_kind"].to_dict()

    def ancestors(sid):
        while sid in parent and isinstance(parent[sid], str):
            sid = parent[sid]
            yield sid

    roots, nodes = [], []
    for sid in df.span_id:
        chain = [sid, *ancestors(sid)]
        roots.append(name[chain[-1]])
        # El nodo del grafo es el ancestro CHAIN más alto con nombre de nodo.
        node_names = [name[s] for s in chain if name[s] in NODES and kind[s] == "CHAIN"]
        nodes.append(node_names[-1] if node_names else None)
    df["scenario"], df["node"] = roots, nodes
    return df


def wall_time(spans: pd.DataFrame) -> float:
    """Tiempo de reloj cubierto por los spans (unión de intervalos).
    Las tools corren EN PARALELO (ToolNode), así que sumar latencias sobrestima."""
    intervals = sorted(zip(pd.to_datetime(spans.start_time), pd.to_datetime(spans.end_time)))
    total, cur_start, cur_end = 0.0, None, None
    for start, end in intervals:
        if cur_end is None or start > cur_end:
            if cur_end is not None:
                total += (cur_end - cur_start).total_seconds()
            cur_start, cur_end = start, end
        else:
            cur_end = max(cur_end, end)
    if cur_end is not None:
        total += (cur_end - cur_start).total_seconds()
    return total


def cost(prompt, completion, cached) -> float:
    return ((prompt - cached) * PRICE_IN + cached * PRICE_CACHED + completion * PRICE_OUT) / 1e6


def trace_metrics(df: pd.DataFrame) -> list[dict]:
    rows = []
    for scenario, t in df.groupby("scenario"):
        root = t[t.parent_id.isna()].iloc[0]
        llm, tools = t[t.span_kind == "LLM"], t[t.span_kind == "TOOL"]
        retrieval = tools[tools.name.isin(RETRIEVAL_TOOLS)]
        p, c, ca = llm[TOK_P].sum(), llm[TOK_C].sum(), llm[TOK_CACHE].sum()
        rows.append({
            "scenario": scenario,
            "status": root.status_code,
            "latency_s": round(root.latency, 1),
            "spans": len(t),
            "llm_calls": len(llm),
            "tool_calls": len(tools),
            "tool_errors": int((tools.status_code == "ERROR").sum()),
            # Tiempo de reloj (unión de intervalos): no se duplica el paralelismo.
            "llm_time_s": round(wall_time(llm), 1),
            "retrieval_time_s": round(wall_time(retrieval), 1),
            "retrieval_time_sum_s": round(retrieval.latency.sum(), 1),  # suma (con paralelismo)
            "other_tool_time_s": round(tools.latency.sum() - retrieval.latency.sum(), 2),
            "prompt_tokens": int(p), "completion_tokens": int(c), "cached_tokens": int(ca),
            "total_tokens": int(llm[TOK_T].sum()),
            "cost_usd": round(cost(p, c, ca), 5),
            "tokens_by_node": {n: int(llm[llm.node == n][TOK_T].sum()) for n in NODES},
        })
    return sorted(rows, key=lambda r: ORDER.index(r["scenario"]) if r["scenario"] in ORDER else 99)


def top_spans(df: pd.DataFrame, n=10) -> list[dict]:
    leaf = df[df.span_kind.isin(["LLM", "TOOL"])].sort_values("latency", ascending=False).head(n)
    return [{"scenario": r.scenario, "node": r.node, "kind": r.span_kind, "name": r["name"],
             "latency_s": round(r.latency, 2), "tokens": int(r[TOK_T]),
             "prompt_tokens": int(r[TOK_P]), "completion_tokens": int(r[TOK_C])} for _, r in leaf.iterrows()]


def reasoning_processes(df: pd.DataFrame) -> list[dict]:
    """Cada ejecución de un nodo especialista = un proceso de razonamiento ReAct."""
    out = []
    node_spans = df[(df.span_kind == "CHAIN") & df.name.isin(["researcher", "analyst"]) & (df.node == df.name)]
    by_id = df.set_index("span_id")
    parent = by_id["parent_id"].to_dict()

    def is_desc(sid, ancestor):
        while isinstance(parent.get(sid), str):
            sid = parent[sid]
            if sid == ancestor:
                return True
        return False

    for _, ns in node_spans.iterrows():
        if isinstance(parent.get(ns.span_id), str) and by_id.loc[parent[ns.span_id], "name"] == ns["name"]:
            continue  # es un span interno con el mismo nombre; nos quedamos con el del nodo
        sub = df[(df.scenario == ns.scenario) & df.span_id.map(lambda s: is_desc(s, ns.span_id))]
        llm = sub[sub.span_kind == "LLM"].sort_values("start_time")
        if llm.empty:
            continue
        out.append({
            "scenario": ns.scenario, "agent": ns["name"], "latency_s": round(ns.latency, 1),
            "llm_iterations": len(llm), "tool_calls": int((sub.span_kind == "TOOL").sum()),
            "prompt_tokens": int(llm[TOK_P].sum()), "completion_tokens": int(llm[TOK_C].sum()),
            "total_tokens": int(llm[TOK_T].sum()),
            "cost_usd": round(cost(llm[TOK_P].sum(), llm[TOK_C].sum(), llm[TOK_CACHE].sum()), 5),
            "iterations": [{"prompt": int(r[TOK_P]), "completion": int(r[TOK_C]),
                            "latency_s": round(r.latency, 2)} for _, r in llm.iterrows()],
        })
    return sorted(out, key=lambda r: -r["total_tokens"])


def errors(df: pd.DataFrame) -> list[dict]:
    err = df[df.status_code == "ERROR"]
    return [{"scenario": r.scenario, "kind": r.span_kind, "name": r["name"], "node": r.node,
             "message": str(r.status_message).split("Traceback")[0][:160]} for _, r in err.iterrows()]


# --------------------------------------------------------------------------- charts
def _style(ax, title):
    ax.set_title(title, loc="left", fontsize=12, color=INK, pad=12, fontweight="bold")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color("#d6d5d0")
    ax.tick_params(colors=INK2, labelsize=9)
    ax.set_facecolor(SURFACE)


def chart_latency(traces):
    fig, ax = plt.subplots(figsize=(9, 5.2), facecolor=SURFACE)
    names = [t["scenario"] for t in traces][::-1]
    llm = [t["llm_time_s"] for t in traces][::-1]
    ret = [t["retrieval_time_s"] for t in traces][::-1]
    other = [max(t["latency_s"] - t["llm_time_s"] - t["retrieval_time_s"], 0) for t in traces][::-1]
    kw = dict(height=0.62, edgecolor=SURFACE, linewidth=1.5)
    ax.barh(names, llm, color=BLUE, label="Generación LLM", **kw)
    ax.barh(names, ret, left=llm, color=ORANGE, label="Recuperación (OSV + Tavily)", **kw)
    ax.barh(names, other, left=[a + b for a, b in zip(llm, ret)], color=GRAY, label="Orquestación / otros", **kw)
    for i, t in enumerate(traces[::-1]):
        ax.text(t["latency_s"] + 0.6, i, f"{t['latency_s']:.1f}s".replace(".", ","), va="center", fontsize=8.5, color=INK2)
    ax.set_xlabel("segundos", color=INK2, fontsize=9)
    ax.grid(axis="x", color="#ebeae5", linewidth=0.8)
    ax.set_axisbelow(True)
    _style(ax, "Latencia por traza: ¿dónde se va el tiempo?")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=3, frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "latency_breakdown.png", dpi=200)
    plt.close(fig)


def chart_tokens(traces):
    fig, ax = plt.subplots(figsize=(9, 5.2), facecolor=SURFACE)
    names = [t["scenario"] for t in traces][::-1]
    left = [0] * len(names)
    for node in NODES:
        vals = [t["tokens_by_node"][node] for t in traces][::-1]
        ax.barh(names, vals, left=left, color=AGENT_COLORS[node], label=node, height=0.62,
                edgecolor=SURFACE, linewidth=1.5)
        left = [a + b for a, b in zip(left, vals)]
    for i, t in enumerate(traces[::-1]):
        ax.text(t["total_tokens"] + 300, i, f"{t['total_tokens']:,} tok · US${t['cost_usd']:.4f}".replace(",", "#").replace(".", ",").replace("#", "."),
                va="center", fontsize=8, color=INK2)
    ax.set_xlabel("tokens", color=INK2, fontsize=9)
    ax.set_xlim(0, max(t["total_tokens"] for t in traces) * 1.32)
    ax.grid(axis="x", color="#ebeae5", linewidth=0.8)
    ax.set_axisbelow(True)
    _style(ax, "Tokens por traza y por agente")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=4, frameon=False, fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT / "tokens_by_agent.png", dpi=200)
    plt.close(fig)


def chart_reasoning(proc):
    fig, ax = plt.subplots(figsize=(8, 4), facecolor=SURFACE)
    it = proc["iterations"]
    xs = [f"#{i + 1}" for i in range(len(it))]
    p = [x["prompt"] for x in it]
    c = [x["completion"] for x in it]
    ax.bar(xs, p, color=BLUE, width=0.55, label="Tokens de entrada (prompt)", edgecolor=SURFACE, linewidth=1.5)
    ax.bar(xs, c, bottom=p, color=ORANGE, width=0.55, label="Tokens de salida (completion)",
           edgecolor=SURFACE, linewidth=1.5)
    for i, x in enumerate(it):
        ax.text(i, x["prompt"] + x["completion"] + 120, f"{x['prompt'] + x['completion']:,}".replace(",", "."),
                ha="center", fontsize=8.5, color=INK2)
    ax.set_xlabel("Iteración del ciclo ReAct (llamada al LLM)", color=INK2, fontsize=9)
    ax.set_ylabel("tokens", color=INK2, fontsize=9)
    ax.grid(axis="y", color="#ebeae5", linewidth=0.8)
    ax.set_axisbelow(True)
    _style(ax, f"Razonamiento más largo: {proc['agent']} en {proc['scenario']}")
    ax.legend(frameon=False, fontsize=9, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUT / "longest_reasoning.png", dpi=200)
    plt.close(fig)


def chart_top_spans(spans):
    fig, ax = plt.subplots(figsize=(9, 4.6), facecolor=SURFACE)
    labels = [f"{s['name']} · {s['node']} · {s['scenario']}" for s in spans][::-1]
    vals = [s["latency_s"] for s in spans][::-1]
    colors = [BLUE if s["kind"] == "LLM" else ORANGE for s in spans][::-1]
    ax.barh(labels, vals, color=colors, height=0.6)
    for i, v in enumerate(vals):
        ax.text(v + 0.1, i, f"{v:.1f}s".replace(".", ","), va="center", fontsize=8.5, color=INK2)
    ax.set_xlabel("segundos", color=INK2, fontsize=9)
    ax.grid(axis="x", color="#ebeae5", linewidth=0.8)
    ax.set_axisbelow(True)
    _style(ax, "Los 10 spans hoja más lentos (LLM vs herramienta)")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BLUE, label="LLM"), Patch(color=ORANGE, label="Herramienta")],
              frameon=False, fontsize=9, loc="lower right")
    fig.tight_layout()
    fig.savefig(OUT / "top_spans.png", dpi=200)
    plt.close(fig)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    df = load_spans()
    traces = trace_metrics(df)
    spans = top_spans(df)
    procs = reasoning_processes(df)
    errs = errors(df)
    llm, tools = df[df.span_kind == "LLM"], df[df.span_kind == "TOOL"]
    retr = tools[tools.name.isin(RETRIEVAL_TOOLS) & (tools.status_code == "OK")]
    summary = {
        "project": PROJECT,
        "traces": len(traces),
        "spans": len(df),
        "llm_calls": len(llm),
        "tool_calls": len(tools),
        "total_tokens": int(llm[TOK_T].sum()),
        "total_cost_usd": round(sum(t["cost_usd"] for t in traces), 4),
        "llm_latency": {"mean": round(llm.latency.mean(), 2), "p50": round(llm.latency.median(), 2),
                        "max": round(llm.latency.max(), 2)},
        "retrieval_latency": {"mean": round(retr.latency.mean(), 2), "p50": round(retr.latency.median(), 2),
                              "max": round(retr.latency.max(), 2)},
        "latency_share": {
            "llm": round(sum(t["llm_time_s"] for t in traces) / sum(t["latency_s"] for t in traces), 3),
            "retrieval": round(sum(t["retrieval_time_s"] for t in traces) / sum(t["latency_s"] for t in traces), 3),
        },
        "prices_usd_per_1m": {"input": PRICE_IN, "cached_input": PRICE_CACHED, "output": PRICE_OUT},
        "model": str(llm["attributes.llm.model_name"].dropna().iloc[0]),
    }
    (OUT / "metrics.json").write_text(json.dumps(
        {"summary": summary, "traces": traces, "top_spans": spans, "reasoning": procs[:8], "errors": errs},
        ensure_ascii=False, indent=2))
    chart_latency(traces)
    chart_tokens(traces)
    chart_reasoning(procs[0])
    chart_top_spans(spans)
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print("top span:", spans[0])
    print("razonamiento más largo:", {k: v for k, v in procs[0].items() if k != "iterations"})
    print("errores:", len(errs), {e["scenario"] for e in errs})


if __name__ == "__main__":
    main()
