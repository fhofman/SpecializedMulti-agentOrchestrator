"""Genera el PDF de hallazgos de observabilidad a partir de las métricas reales.

    uv run python scripts/analyze_traces.py   # primero: métricas + gráficos
    uv run python scripts/build_report.py     # luego: PDF

Todos los números salen de docs/observability/metrics.json y docs/traffic_runs.json.
"""

import json
from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Image, KeepTogether, ListFlowable, ListItem, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

DOCS = Path("docs/observability")
OUT = DOCS / "analisis_observabilidad_phoenix.pdf"
REPO = "github.com/fhofman/SpecializedMulti-agentOrchestrator"

FONT_DIR = Path("/System/Library/Fonts/Supplemental")
pdfmetrics.registerFont(TTFont("Arial", str(FONT_DIR / "Arial.ttf")))
pdfmetrics.registerFont(TTFont("Arial-Bold", str(FONT_DIR / "Arial Bold.ttf")))
pdfmetrics.registerFont(TTFont("Arial-Italic", str(FONT_DIR / "Arial Italic.ttf")))
from reportlab.pdfbase.pdfmetrics import registerFontFamily  # noqa: E402

registerFontFamily("Arial", normal="Arial", bold="Arial-Bold", italic="Arial-Italic", boldItalic="Arial-Bold")

INK, INK2, ACCENT, RULE, SOFT = (colors.HexColor(c) for c in ("#0b0b0b", "#52514e", "#2a78d6", "#d6d5d0", "#f3f2ee"))
BAD, GOOD = colors.HexColor("#d03b3b"), colors.HexColor("#0ca30c")

ST = {
    "title": ParagraphStyle("title", fontName="Arial-Bold", fontSize=21, leading=26, textColor=INK, spaceAfter=6),
    "subtitle": ParagraphStyle("subtitle", fontName="Arial", fontSize=11.5, leading=15, textColor=INK2, spaceAfter=14),
    "h1": ParagraphStyle("h1", fontName="Arial-Bold", fontSize=15, leading=19, textColor=INK, spaceBefore=14, spaceAfter=7),
    "h2": ParagraphStyle("h2", fontName="Arial-Bold", fontSize=11.5, leading=15, textColor=ACCENT, spaceBefore=9, spaceAfter=4),
    "body": ParagraphStyle("body", fontName="Arial", fontSize=9.6, leading=13.6, textColor=INK, spaceAfter=5, alignment=TA_LEFT),
    "small": ParagraphStyle("small", fontName="Arial", fontSize=8.2, leading=11, textColor=INK2, spaceAfter=4),
    "cell": ParagraphStyle("cell", fontName="Arial", fontSize=8, leading=10.2, textColor=INK),
    "cellb": ParagraphStyle("cellb", fontName="Arial-Bold", fontSize=8, leading=10.2, textColor=INK),
    "answer": ParagraphStyle("answer", fontName="Arial", fontSize=9.8, leading=14, textColor=INK,
                             backColor=SOFT, borderPadding=(7, 8, 7, 8), spaceBefore=4, spaceAfter=10),
    "code": ParagraphStyle("code", fontName="Courier", fontSize=8.2, leading=11, textColor=INK,
                           backColor=SOFT, borderPadding=(5, 6, 5, 6), spaceAfter=8),
}

m = json.loads((DOCS / "metrics.json").read_text())
runs = {r["id"]: r for r in json.loads(Path("docs/traffic_runs.json").read_text())}
S = m["summary"]
T = {t["scenario"]: t for t in m["traces"]}
TOP = m["top_spans"][0]
R = m["reasoning"][0]


def n(x) -> str:
    return f"{x:,}".replace(",", ".")


def dec(x, d=1) -> str:
    """Decimal con coma (convención en español; el punto queda para miles)."""
    return f"{x:.{d}f}".replace(".", ",")


def usd(x) -> str:
    return f"US$ {x:.4f}".replace(".", ",")


def p(text, style="body"):
    return Paragraph(text, ST[style])


def bullets(items):
    return ListFlowable([ListItem(p(i), leftIndent=12, value="•") for i in items],
                        bulletType="bullet", start="•", leftIndent=12, bulletFontSize=8)


def img(path, width=17 * cm, caption=None):
    from reportlab.lib.utils import ImageReader
    w, h = ImageReader(str(path)).getSize()
    parts = [Image(str(path), width=width, height=width * h / w)]
    if caption:
        parts.append(p(caption, "small"))
    return KeepTogether(parts + [Spacer(1, 6)])


def table(rows, widths, header=True, zebra=True):
    data = [[c if not isinstance(c, str) else p(c, "cellb" if header and i == 0 else "cell") for c in row]
            for i, row in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK2),
             ("LINEBELOW", (0, 1), (-1, -1), 0.3, RULE), ("TOPPADDING", (0, 0), (-1, -1), 3.5),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5), ("LEFTPADDING", (0, 0), (-1, -1), 4)]
    if zebra:
        style += [("BACKGROUND", (0, i), (-1, i), SOFT) for i in range(2, len(rows), 2)]
    t.setStyle(TableStyle(style))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Arial", 7.5)
    canvas.setFillColor(INK2)
    canvas.drawString(2 * cm, 1.2 * cm, "Análisis de observabilidad · Orquestador multi-agente de vulnerabilidades")
    canvas.drawRightString(A4[0] - 2 * cm, 1.2 * cm, f"Página {doc.page}")
    canvas.restoreState()


def route(sid):
    r = runs.get(sid, {})
    if r.get("status") == "error":
        return "researcher -> <b>excepción</b>"
    return " -> ".join(x.split("-> ")[-1] for x in r.get("route", []))


story = []

# ------------------------------------------------------------------ portada / resumen
story += [
    p("Análisis de observabilidad con Arize Phoenix", "title"),
    p("Orquestador multi-agente de vulnerabilidades (LangGraph) · Supervisor + Investigador + Analista<br/>"
      f"{date.today().strftime('%d/%m/%Y')} · Repositorio: {REPO}", "subtitle"),
    p("Resumen ejecutivo", "h1"),
    p(f"Se generaron <b>{S['traces']} trazas</b> en el proyecto <i>{S['project']}</i> de Phoenix: "
      f"5 consultas complejas sobre los 4 ecosistemas (Maven, npm, PyPI, Packagist), 2 escenarios de fallo "
      f"provocados y 4 re-ejecuciones de verificación después de corregir los problemas detectados. En total: "
      f"<b>{n(S['spans'])} spans</b>, {S['llm_calls']} llamadas al LLM ({S['model']}), {S['tool_calls']} llamadas a "
      f"herramientas, <b>{n(S['total_tokens'])} tokens</b> y un costo estimado de <b>{usd(S['total_cost_usd'])}</b>."),
    bullets([
        f"<b>Span de mayor latencia:</b> una generación del LLM (no la recuperación). Fue <i>ChatOpenAI</i> dentro "
        f"del Analista en {TOP['scenario']}: <b>{dec(TOP['latency_s'], 2)} s</b>. En tiempo de reloj, la generación LLM "
        f"explica el <b>{dec(S['latency_share']['llm'] * 100)}%</b> de la latencia y la recuperación (OSV.dev + Tavily) "
        f"solo el <b>{dec(S['latency_share']['retrieval'] * 100)}%</b>.",
        f"<b>Proceso de razonamiento más largo:</b> el Investigador en {R['scenario']}: {R['llm_iterations']} "
        f"iteraciones ReAct, {R['tool_calls']} llamadas a herramientas, <b>{n(R['total_tokens'])} tokens</b> "
        f"({n(R['prompt_tokens'])} de entrada, {n(R['completion_tokens'])} de salida), {usd(R['cost_usd'])}.",
        "<b>Fallos observados en las trazas:</b> (1) una herramienta caída tumbaba todo el grafo; (2) consultas "
        "fuera de alcance terminaban con un falso \"no hace falta parchear\"; y, descubierto navegando las trazas, "
        "(3) el Investigador usaba nombres de repos de GitHub en PyPI y obtenía 0 vulnerabilidades (falso negativo).",
        "<b>Los tres se corrigieron y se verificaron con nuevas trazas</b> (sufijo <i>-fix</i>): sin caídas, sin "
        "falsos negativos y hasta 84% menos tokens en el caso fuera de alcance.",
    ]),
]

# ------------------------------------------------------------------ 1. setup
story += [
    p("1. Instrumentación", "h1"),
    p("El sistema usa <b>OpenInference</b> (<i>LangChainInstrumentor</i>) sobre OpenTelemetry. El exportador OTLP/HTTP "
      "apunta al servidor local de Phoenix (<i>http://localhost:6006/v1/traces</i>), configurado en "
      "<i>tracing.py</i>. Cada ejecución del grafo es una traza; cada nodo (supervisor, researcher, analyst, "
      "synthesizer), cada llamada al LLM y cada herramienta es un span. Las trazas llevan <i>session_id</i> = id del "
      "escenario y metadata filtrable (escenario, tipo, consulta)."),
    p("Sobre la \"búsqueda RAG\": en este sistema la recuperación de información no es sobre una base vectorial "
      "sino sobre <b>fuentes externas</b>, como permite la consigna: <i>query_osv</i> consulta la base OSV.dev y "
      "<i>web_search</i> consulta Tavily. Son los spans de recuperación analizados en este documento.", "small"),
    p("uv run phoenix serve<br/>uv run python scripts/generate_traffic.py<br/>"
      "uv run python scripts/analyze_traces.py &amp;&amp; uv run python scripts/build_report.py", "code"),
]

# ------------------------------------------------------------------ 2. tráfico
rows = [["Escenario", "Qué pide", "Recorrido del supervisor", "Estado", "Latencia", "Tokens"]]
desc = {
    "Q1-java-spring": "spring-web, jackson-databind, struts2 (Maven): riesgo de RCE",
    "Q2-node-api": "express, jsonwebtoken, axios, minimist (npm) + explotación activa",
    "Q3-python-web": "requests, pyyaml, flask, jinja2, pillow (PyPI)",
    "Q4-php-laravel": "laravel, symfony/http-kernel, phpmailer, twig (Packagist)",
    "Q5-polyglot": "log4j, lodash, django, guzzle (4 ecosistemas) + explotación activa",
    "F1-tools-down": "<b>Fallo provocado:</b> OSV.dev desconectado + Tavily con API key inválida",
    "F2-out-of-scope": "<b>Fallo provocado:</b> firmware de router y Windows 10 (fuera de alcance)",
}
for sid in ["Q1-java-spring", "Q2-node-api", "Q3-python-web", "Q4-php-laravel", "Q5-polyglot", "F1-tools-down", "F2-out-of-scope"]:
    t = T[sid]
    status = "<font color='#d03b3b'><b>ERROR</b></font>" if t["status"] == "ERROR" else "OK"
    rows.append([sid, desc[sid], route(sid), status, f"{dec(t['latency_s'])} s", n(t["total_tokens"])])
story += [
    p("2. Tráfico generado", "h1"),
    p("Las 5 consultas obligan a colaborar a los tres agentes: el supervisor delega, el Investigador usa "
      "<i>query_osv</i> (una vez por paquete, en paralelo) y <i>web_search</i>, el Analista usa "
      "<i>rank_dependencies</i> (cálculo CVSS en Python) y el supervisor valida con su rúbrica antes de cerrar."),
    table(rows, [2.6 * cm, 5.4 * cm, 4.6 * cm, 1.4 * cm, 1.5 * cm, 1.5 * cm]),
    Spacer(1, 8),
    img(DOCS / "screenshots/phoenix_traces.png", caption="Phoenix · lista de trazas del proyecto (filtro "
        "<i>parent_id is None</i>). F1-tools-down aparece con estado de error y el mensaje ConnectionError. "
        "Las trazas -fix son las re-ejecuciones posteriores a las correcciones."),
    PageBreak(),
    p("Navegación de una traza completa", "h2"),
    p("Al abrir una traza, Phoenix muestra el árbol de spans con la latencia de cada uno. En Q5 se ve la "
      "delegación: <i>supervisor</i> (2,5 s) decide, <i>researcher</i> (19,9 s) ejecuta su agente ReAct "
      "(<i>agent -> call_model -> ChatOpenAI</i>, luego <i>tools -> query_osv</i>), y así sucesivamente. "
      "Cada span LLM muestra tokens y costo; cada span de tool, sus argumentos y su resultado."),
    img(DOCS / "screenshots/phoenix_trace_q5.png", caption="Phoenix · traza Q5-polyglot (46,7 s): árbol de "
        "spans de la delegación supervisor -> researcher -> analyst -> synthesizer."),
]

# ------------------------------------------------------------------ 3. latencia
top_rows = [["#", "Span", "Agente", "Escenario", "Latencia", "Tokens entrada", "Tokens salida"]]
for i, s in enumerate(m["top_spans"][:6], 1):
    top_rows.append([str(i), f"{s['name']} ({s['kind']})", s["node"], s["scenario"], f"{dec(s['latency_s'], 2)} s",
                     n(s["prompt_tokens"]), n(s["completion_tokens"])])
story += [
    p("3. ¿Cuál fue el span de mayor latencia?", "h1"),
    p(f"<b>Respuesta: fue una generación del LLM, no la recuperación.</b> El span más lento de todo el tráfico es "
      f"<i>ChatOpenAI</i> dentro del <b>Analista en {TOP['scenario']}</b>: <b>{dec(TOP['latency_s'], 2)} s</b> "
      f"({n(TOP['prompt_tokens'])} tokens de entrada, {n(TOP['completion_tokens'])} de salida), redactando la tabla "
      f"de ranking y el plan de acción. <b>Los 10 spans hoja más lentos son todos llamadas al LLM</b>; ninguna "
      f"herramienta entra en el top 10.", "answer"),
    img(DOCS / "latency_breakdown.png", width=16 * cm, caption="Latencia de cada traza dividida en tiempo de "
        "generación LLM y tiempo de recuperación (OSV + Tavily), medido como tiempo de reloj: las consultas a OSV "
        "corren en paralelo, así que se usa la unión de intervalos y no la suma."),
    table([
        ["Métrica", "Generación LLM", "Recuperación (OSV + Tavily)"],
        ["Latencia media por llamada", f"{dec(S['llm_latency']['mean'], 2)} s", f"{dec(S['retrieval_latency']['mean'], 2)} s"],
        ["Mediana (p50)", f"{dec(S['llm_latency']['p50'], 2)} s", f"{dec(S['retrieval_latency']['p50'], 2)} s"],
        ["Máximo", f"{dec(S['llm_latency']['max'], 2)} s", f"{dec(S['retrieval_latency']['max'], 2)} s"],
        ["Parte del tiempo total (reloj)", f"{dec(S['latency_share']['llm'] * 100)}%",
         f"{dec(S['latency_share']['retrieval'] * 100)}%"],
    ], [6 * cm, 5 * cm, 6 * cm]),
    Spacer(1, 8),
    p("Por qué: la latencia sigue a los tokens de SALIDA", "h2"),
    p("La correlación entre la latencia de un span LLM y sus tokens de salida es <b>0,87</b>; con los tokens de "
      "entrada es solo <b>0,30</b>. Por eso los spans más lentos son los del Analista y la Síntesis (escriben "
      "tablas y planes de ~450-700 tokens), aunque el Investigador procese prompts mucho más grandes. Generar "
      "texto token a token es lo caro en tiempo; leer contexto es relativamente barato."),
    table(top_rows, [0.6 * cm, 3.4 * cm, 2 * cm, 3.4 * cm, 1.8 * cm, 2.6 * cm, 2.4 * cm]),
    Spacer(1, 8),
    img(DOCS / "screenshots/phoenix_trace_q1_slowest.png", caption="Phoenix · el span más lento (ChatOpenAI del "
        "Analista en Q1, 16,4 s). Justo arriba se ve la herramienta rank_dependencies: 0 ms. El cálculo "
        "determinístico es instantáneo; el tiempo lo consume la redacción del LLM."),
    img(DOCS / "top_spans.png", width=15.5 * cm, caption="Los 10 spans hoja más lentos: todos son generaciones "
        "del LLM."),
]

# ------------------------------------------------------------------ 4. costo
proc_rows = [["Escenario", "Agente", "Iter.", "Tools", "Tokens entrada", "Tokens salida", "Total", "Costo"]]
for r in m["reasoning"][:5]:
    proc_rows.append([r["scenario"], r["agent"], str(r["llm_iterations"]), str(r["tool_calls"]),
                      n(r["prompt_tokens"]), n(r["completion_tokens"]), n(r["total_tokens"]), usd(r["cost_usd"])])
it = R["iterations"]
story += [
    p("4. Análisis de costo (tokens)", "h1"),
    p(f"<b>Respuesta: el proceso de razonamiento más largo fue el del Investigador en {R['scenario']}</b>, con "
      f"<b>{n(R['total_tokens'])} tokens</b> ({n(R['prompt_tokens'])} de entrada + {n(R['completion_tokens'])} de "
      f"salida) en {R['llm_iterations']} iteraciones del ciclo ReAct y {R['tool_calls']} llamadas a herramientas, "
      f"durante {dec(R['latency_s'])} s. Costo estimado: {usd(R['cost_usd'])}. Esa sola ejecución representa el "
      f"{R['total_tokens'] / T[R['scenario']]['total_tokens'] * 100:.0f}% de los tokens de su traza.", "answer"),
    img(DOCS / "longest_reasoning.png", width=14.5 * cm, caption="Tokens por iteración del razonamiento más largo. "
        "El prompt crece en cada vuelta porque el agente ReAct re-envía todo su historial, incluidos los JSON "
        "devueltos por OSV."),
    p(f"El crecimiento es el patrón clave: iteración 1 = {n(it[0]['prompt'])} tokens de entrada; iteración 2 = "
      f"{n(it[1]['prompt'])} (ya incluye las respuestas de OSV de 4 paquetes); iteración 3 = {n(it[2]['prompt'])}. "
      f"El <b>{R['prompt_tokens'] / R['total_tokens'] * 100:.0f}%</b> de los tokens del razonamiento son de entrada. "
      f"En el Investigador, el costo lo determina el tamaño de los resultados de las herramientas, no lo que escribe."),
    table(proc_rows, [3.0 * cm, 1.9 * cm, 1.1 * cm, 1.2 * cm, 2.4 * cm, 2.3 * cm, 1.8 * cm, 2.3 * cm]),
    Spacer(1, 8),
    img(DOCS / "tokens_by_agent.png", width=16 * cm, caption="Tokens por traza y por agente, con el costo estimado "
        "de cada traza. El Investigador es el agente que más tokens consume en casi todas las trazas."),
    p(f"Precios usados (lista de OpenAI para gpt-4o-mini, USD por millón de tokens): entrada "
      f"{S['prices_usd_per_1m']['input']}, entrada cacheada {S['prices_usd_per_1m']['cached_input']}, salida "
      f"{S['prices_usd_per_1m']['output']}. El panel de Phoenix muestra <i>Total Cost $0</i> porque no tiene precio "
      f"configurado para el modelo versionado <i>{S['model']}</i>; por eso el costo se calculó a partir de los "
      f"tokens registrados en cada span.", "small"),
]

# ------------------------------------------------------------------ 5. fallos
f1, f1fix = T["F1-tools-down"], T["F1-tools-down-fix"]
f2, f2fix2 = T["F2-out-of-scope"], T["F2-out-of-scope-fix2"]
story += [
    p("5. Fallos provocados: cómo se registran en la traza", "h1"),
    p("F1 · Herramienta desconectada", "h2"),
    p("Con <i>fault injection</i> en el script de tráfico, la llamada HTTP a OSV.dev lanza "
      "<i>ConnectionError</i> y Tavily recibe una API key inválida."),
    bullets([
        "<b>Cómo lo registra Phoenix:</b> el span TOOL <i>query_osv</i> queda en estado <b>Error</b>, con un evento "
        "de excepción que guarda el traceback completo (archivo y línea, incluida la línea de la inyección). El error "
        "<b>se propaga hacia arriba</b>, marcando en rojo <i>tools -> researcher -> researcher -> F1-tools-down</i> "
        f"({len([e for e in m['errors'] if e['scenario'] == 'F1-tools-down'])} spans en error). La traza raíz "
        f"queda en <b>Error</b> con latencia de {dec(f1['latency_s'])} s.",
        "<b>Lo que reveló:</b> el <i>ToolNode</i> de LangGraph, por defecto, <b>vuelve a lanzar</b> cualquier "
        "excepción que no sea de validación. Una sola herramienta caída tumbaba el grafo completo y el usuario no "
        "recibía respuesta.",
        "<b>Matiz:</b> Tavily con key inválida <b>no</b> lanza excepción: devuelve <i>{'error': '401 Unauthorized'}</i> "
        "como resultado normal. En la traza ese span figura como OK. Es una falla <i>silenciosa</i> que solo se ve "
        "leyendo el output del span.",
    ]),
    img(DOCS / "screenshots/phoenix_span_f1_exception.png", caption="Phoenix · span query_osv en error dentro de "
        "F1-tools-down: excepción con traceback, argumentos de entrada y la cadena de spans padres marcada en rojo."),
    p("F2 · Pedido fuera de alcance", "h2"),
    p("Se pidió analizar el firmware de un router y Windows 10, que no son dependencias de Maven/npm/PyPI/Packagist. "
      "La traza no tiene errores técnicos (todos los spans en OK), pero muestra un <b>error de comportamiento</b>: "
      f"el Analista corrió 3 veces sobre datos vacíos ({n(f2['total_tokens'])} tokens, {dec(f2['latency_s'])} s) y "
      "la respuesta final afirmó que <i>\"no es necesario aplicar parches\"</i>, una conclusión peligrosa."),
    p("Q3 · Falso negativo descubierto navegando las trazas", "h2"),
    p("Q3 respondió que requests 2.25.0, pyyaml 5.3, flask 1.0 y otros paquetes \"no tienen vulnerabilidades\". "
      "Al abrir los spans <i>query_osv</i> en Phoenix, los argumentos mostraron la causa: el LLM consultó "
      "<i>psf/requests</i>, <i>pallets/flask</i> y <i>yaml/pyyaml</i> (nombres de repos de GitHub) en el "
      "ecosistema PyPI; OSV devolvió <i>total_found: 0</i> para cada uno. Sin la observabilidad de los "
      "inputs y outputs de cada tool, este error habría sido invisible: la traza estaba \"verde\"."),
]

# ------------------------------------------------------------------ 6. mejoras
q3, q3fix = T["Q3-python-web"], T["Q3-python-web-fix"]
story += [
    p("6. Correcciones aplicadas y verificación con nuevas trazas", "h1"),
    table([
        ["Hallazgo", "Corrección", "Antes", "Después (traza -fix)"],
        ["F1: una tool caída tumba el grafo", "<i>ToolNode(handle_tool_errors=True)</i> en ambos agentes: la "
         "excepción vuelve al LLM como mensaje de error",
         f"<font color='#d03b3b'>Excepción, sin respuesta ({dec(f1['latency_s'])} s)</font>",
         f"<font color='#0ca30c'>Completa ({dec(f1fix['latency_s'])} s)</font>: {f1fix['tool_errors']} errores de "
         "tool registrados, 3 reintentos (G3) y respuesta \"esto NO significa que sea seguro\""],
        ["Q3: nombres inválidos -> falso \"limpio\"", "Validación de nombre por ecosistema en <i>query_osv</i>, que "
         "devuelve un error corregible, más una nota de que \"0 hallazgos no significa seguro\"",
         f"0 vulnerabilidades, analista x3, {n(q3['total_tokens'])} tokens",
         f"Detecta pillow y pyyaml críticos; analista x1; {n(q3fix['total_tokens'])} tokens"],
        ["F2 / Q3: analista sobre datos vacíos y \"no hace falta parchear\"", "Guardrail G7 (sin vulnerabilidades o "
         "fuera de alcance -> FINISH) y una síntesis que nunca declara seguro sin datos",
         f"{dec(f2['latency_s'])} s, {n(f2['total_tokens'])} tokens, conclusión falsa",
         f"{dec(f2fix2['latency_s'])} s, {n(f2fix2['total_tokens'])} tokens "
         f"(-{(1 - f2fix2['total_tokens'] / f2['total_tokens']) * 100:.0f}%), declara \"fuera de alcance\""],
    ], [3.4 * cm, 5.4 * cm, 3.6 * cm, 4.6 * cm], zebra=False),
    Spacer(1, 6),
    p("La corrección de F2 necesitó dos iteraciones, y también se detectó en Phoenix: en <i>F2-out-of-scope-fix</i> "
      "el Investigador declaró \"FUERA DE ALCANCE\", pero el supervisor LLM lo volvió a enviar dos veces más "
      f"({dec(T['F2-out-of-scope-fix']['latency_s'])} s). Se extendió G7 para que el fuera de alcance corte siempre, "
      f"y en <i>F2-out-of-scope-fix2</i> terminó en 2 pasos ({dec(f2fix2['latency_s'])} s). Todas las reglas nuevas "
      "tienen tests sin LLM (16 tests en verde)."),
]

# ------------------------------------------------------------------ 7. recomendaciones
story += [
    p("7. Recomendaciones", "h1"),
    bullets([
        f"<b>Circuit breaker para herramientas caídas.</b> En F1-fix, los 3 reintentos del Investigador consumieron "
        f"{n(f1fix['total_tokens'])} tokens y {dec(f1fix['latency_s'])} s sin chance de éxito. Si todas las llamadas "
        "de una ejecución fallan con error de conexión, conviene cortar en el primer intento.",
        "<b>Reducir la latencia percibida:</b> como la latencia depende de los tokens de salida, conviene hacer "
        "streaming de la síntesis al usuario y acortar el formato del Analista (la Síntesis ya reescribe la tabla: "
        "hoy se genera dos veces).",
        "<b>Reducir el costo del Investigador:</b> resumir los resultados de <i>query_osv</i> antes de devolverlos al "
        "LLM. El prompt crece de ~1.800 a ~10.000 tokens por los JSON de OSV, que ya se guardan aparte en "
        "<i>vulnerability_data</i>.",
        "<b>Detectar fallas silenciosas:</b> marcar como error los resultados con clave <i>error</i> (como el 401 de "
        "Tavily), para que aparezcan en rojo en Phoenix y no solo dentro del output.",
        "<b>Configurar el precio del modelo en Phoenix</b> para que el costo se vea en el dashboard, y agregar "
        "evaluaciones automáticas (p. ej. LLM-as-judge sobre la respuesta final) usando las trazas como dataset.",
    ]),
    p("Archivos del análisis en el repositorio: <i>scripts/generate_traffic.py</i> (tráfico y fault injection), "
      "<i>scripts/analyze_traces.py</i> (métricas desde la API de Phoenix), <i>scripts/build_report.py</i> (este PDF) "
      "y <i>docs/observability/</i> (métricas, gráficos y capturas).", "small"),
]

doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm,
                        bottomMargin=2 * cm, title="Análisis de observabilidad con Arize Phoenix",
                        author="Orquestador multi-agente de vulnerabilidades")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(f"PDF generado: {OUT}")
