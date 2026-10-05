"""流程組裝：LangGraph 拓撲與條件路由。每個節點做什麼見 nodes/__init__.py。

    node0 ─┬─ 網址無效 ─────────────────────────→ node5（unknown + 稽核）
           └─ node1 觀察 ─┬─ 沒有可判讀的頁面 ──→ node5（unknown + 稽核）
                          └─ node2 → node3 → node4 → node5

LLM 實例在建圖時注入（make_node）；node5 不收 llm。
"""
import functools
import uuid

from langgraph.graph import END, StateGraph

from crawler.plan import ObservationSettings
from llm import llm_cloak, llm_code, llm_phish
from nodes.node0_liveness import liveness_node
from nodes.node1_scraper import scrape_js_node
from nodes.node2_js_analyzer import analyze_js_node
from nodes.node3_phishing_classifier import classify_phishing_node
from nodes.node4_cloaking_analyzer import analyze_cloaking_node
from nodes.node5_output import output_node
from schemas.state import AnalysisState
from schemas.versions import SCHEMA_VERSION


def make_node(fn, **kwargs):
    return functools.partial(fn, **kwargs)


def _route_after_liveness(state: AnalysisState) -> str:
    return "alive" if state["alive"] else "dead"


def _route_after_scrape(state: AnalysisState) -> str:
    # 「網址有效」與「抓得到頁面」是兩件事：觀察可能逾時、被擋、拿到空文件。
    return "analyze" if state.get("raw_html") else "dead"


def build_graph():
    graph = StateGraph(AnalysisState)
    graph.add_node("node0_liveness",             liveness_node)
    graph.add_node("node1_scraper",              scrape_js_node)
    graph.add_node("node2_js_analyzer",          make_node(analyze_js_node, llm=llm_code))
    graph.add_node("node3_phishing_classifier",  make_node(classify_phishing_node, llm=llm_phish))
    graph.add_node("node4_cloaking_analyzer",    make_node(analyze_cloaking_node, llm=llm_cloak))
    graph.add_node("node5_output",               output_node)   # 不吃 llm

    graph.add_conditional_edges("node0_liveness", _route_after_liveness,
                                {"alive": "node1_scraper", "dead": "node5_output"})
    # Node 2 不可跳過：Node 3/4 的規則比對可讀原始碼，壓縮成 `n.wD` 的字串比對不到
    # `navigator.webdriver`。這是整條管線唯一真正的順序依賴。
    graph.add_conditional_edges("node1_scraper", _route_after_scrape,
                                {"analyze": "node2_js_analyzer", "dead": "node5_output"})
    # node3 與 node4 的先後沒有語意 —— 釣魚與 cloaking 互不為前提，兩者寫不相交的欄位。
    # 串成線性只是因為 LangGraph 的分岔合流要寫 reducer，並行沒有任何好處。
    graph.add_edge("node2_js_analyzer",          "node3_phishing_classifier")
    graph.add_edge("node3_phishing_classifier",  "node4_cloaking_analyzer")
    graph.add_edge("node4_cloaking_analyzer",    "node5_output")
    graph.add_edge("node5_output",               END)
    graph.set_entry_point("node0_liveness")
    return graph.compile()


# compile 只做一次，所有 URL 共用。compiled graph 是 stateless（每次 invoke 傳入新 state），
# 多 thread 並行呼叫 invoke() 安全。
_COMPILED_GRAPH = None


def get_graph():
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = build_graph()
    return _COMPILED_GRAPH


def create_initial_state(url, source_record=None, run_id=None, settings=None) -> AnalysisState:
    """settings 預設讀環境變數；批次執行時由 cli.Run 傳入同一份快照，整批一致。"""
    settings = settings or ObservationSettings.from_env()
    return AnalysisState(
        schema_version=SCHEMA_VERSION, run_id=run_id or uuid.uuid4().hex, analysis_id=uuid.uuid4().hex,
        url=url, source_record=source_record or {},
        observation_settings=settings.record(), run_config_sha256=settings.config_sha256(),
        observation_plan="",
        alive=True, liveness_reason="",
        bot_crawl={}, human_crawl={}, variant_observations={},
        raw_html="", analysis_source="", analysis_profile_id="", analysis_final_url="",
        observation_issues=[], js_scripts=[], deobfuscated_js=[],
        phishing_rule_result={}, rule_phishing_verdict="not_run", phishing_verdict="unknown",
        phishing_reason="not_observed", phishing_basis="", phishing_caveats=[],
        llm_phishing_assessment="not_run",
        # 舊布林只是投影：False 不代表 not_detected，phishing_verdict 保留 unknown。
        is_phishing=False, phishing_confidence=0.0, phishing_indicators=[],
        static_evidence={}, signals=[], rule_cloaking_label="unknown", cloaking_label="unknown",
        cloaking_reason="not_observed", cloaking_basis="", cloaking_uncertainty=[],
        llm_cloaking_assessment="not_run", cloaking_verified=False,
        cloaking_confidence_tier="AMBIGUOUS", dual_crawl_results={},
        model_outputs=[], evidence={}, observed_at="", report="", errors=[],
    )
