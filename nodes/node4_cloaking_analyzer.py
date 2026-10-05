"""Node 4：cloaking —— 前端 JS 特徵 → 訊號表 → 規則與閘門（三態標籤）→ 模型說明（另存）。

標籤只由 analysis/cloaking.label_cloaking() 決定，它不收 llm 參數。模型在標籤定案之後才
被呼叫，只拿差異證據（不拿規則結果或標籤），輸出寫進 llm_cloaking_assessment 與稽核 JSON。
唯一會讀模型輸出的是舊診斷欄 cloaking_tier（S4），它不是標籤。
"""
import json

from analysis.cloaking import (_similarity_score, _structural_divergence, decide_cloaking,  # noqa: F401
                               label_cloaking, legacy_dual_results)
from analysis.signals import compute_signals, variant_differences
from analysis.static_cloaking import s4_applies, static_detect
from crawler.records import detect_gates, observation_issues
from llm.contract import assessment_value, model_observation
from llm.prompts import CLOAKING_ASSESSMENT_PROMPT, render_evidence


def _detect_gates(html, gate_crossed=None):
    """相容介面（v2）：閘門清單。不跨越任何閘門，gate_crossed 不影響結果。"""
    return detect_gates(html)


def _static_detect(state, llm=None):
    """相容介面（v2）：回傳 (是否命中 S1–S3, 特徵)。純規則；llm 參數保留但不使用。"""
    js = "\n".join(s["deobfuscated"] for s in state.get("deobfuscated_js", []))
    fired, techniques = static_detect(js, state.get("raw_html", ""))
    return bool(fired), techniques


def _observation_summary(record):
    summary = {"kind": record.get("kind", ""), "access_index": record.get("access_index", 0),
               "status": record.get("status_code", 0), "final_url": record.get("final_url", ""),
               "redirect_chain": record.get("redirect_chain", [])[:6], "title": record.get("title", ""),
               "text_excerpt": (record.get("text_content") or "")[:300],
               "issues": observation_issues(record, "html")}
    if record.get("kind") == "browser":
        summary.update(page_url=record.get("page_url", ""), dom_title=record.get("dom_title", ""),
                       dom_text_excerpt=(record.get("dom_text") or "")[:300])
    return summary


def cloaking_evidence(state, signals, techniques):
    """給模型的差異證據：各次觀察摘要 + 訊號表（每個訊號的證據截短）。不含任何標籤。"""
    bot, human = state.get("bot_crawl") or {}, state.get("human_crawl") or {}
    named = {"bot#1": bot, "bot#2": bot.get("confirmation"), "human#1": human,
             "human#2": human.get("confirmation")}
    return {"url": state["url"],
            "observations": {name: _observation_summary(rec) for name, rec in named.items() if rec},
            "signals": [{"id": s["id"], "category": s["category"], "status": s["status"],
                         "evidence": json.dumps(s["evidence"], ensure_ascii=True, default=str)[:600]}
                        for s in signals],
            "frontend_js_categories": sorted(k for k in techniques if k != "static_rule")}


def analyze_cloaking_node(state, llm):
    print("\n[Node 4] Cloaking 分析（訊號表 → 規則與閘門 → 模型說明）...", flush=True)
    js = "\n".join(s["deobfuscated"] for s in state.get("deobfuscated_js", []))
    fired, techniques = static_detect(js, state.get("raw_html", ""))
    bot, human = state.get("bot_crawl") or {}, state.get("human_crawl") or {}
    signals = compute_signals(bot, human, variants=state.get("variant_observations") or {},
                              static_rules=fired, static_techniques=techniques)
    decision = label_cloaking(bot, human, state["url"], frontend_rules=fired,
                              variant_differences=variant_differences(signals))
    state.update(static_evidence=techniques, signals=signals,
                 rule_cloaking_label=decision["rule_label"], cloaking_label=decision["label"],
                 cloaking_reason=decision["reason"], cloaking_basis=decision["basis"],
                 cloaking_uncertainty=decision["reasons"] if decision["label"] == "unknown" else [],
                 cloaking_verified=decision["label"] == "true",
                 dual_crawl_results=legacy_dual_results(decision, bot, human))

    model = None
    if decision["rule_label"] != "unknown":      # 主配對沒有文件就沒有差異可解讀
        model = model_observation(llm, "cloaking", render_evidence(
            CLOAKING_ASSESSMENT_PROMPT, cloaking_evidence(state, signals, techniques)))
        state["model_outputs"] = state.get("model_outputs", []) + [model]
        if model["status"] == "invalid_or_unavailable":
            state["errors"] = state.get("errors", []) + ["[Node4] LLM error: " + model["reason"]]
    state["llm_cloaking_assessment"] = assessment_value(model)

    # 舊診斷欄：CONFIRMED = 標籤 true；SUSPECTED = 規則原始陽性或前端特徵（含 S4）但標籤未定
    static_detected = bool(fired) or s4_applies(state["llm_cloaking_assessment"] == "supports_cloaking",
                                                techniques, fired)
    state["cloaking_confidence_tier"] = (
        "CONFIRMED" if decision["label"] == "true"
        else "SUSPECTED" if decision["rule_label"] == "true" or static_detected else "AMBIGUOUS")
    print(f"  → 規則={decision['rule_label']} → 標籤={decision['label']}"
          f"（{decision['reason'][:120]}）| 模型={state['llm_cloaking_assessment']}", flush=True)
    return state
