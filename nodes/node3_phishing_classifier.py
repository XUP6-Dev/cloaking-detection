"""Node 3：釣魚判定（定義在 analysis/phishing.py）。規則結果、最終判定、模型分析分開寫回。"""
from analysis.phishing import classify
from crawler.records import summarize_html


def classify_phishing_node(state, llm=None):
    html = state.get("raw_html", "")
    summary = summarize_html(html) if html else {"title": "", "text": ""}
    result = classify(html, state.get("analysis_final_url") or state["url"],
                      state.get("deobfuscated_js", []), state.get("observation_issues", []),
                      llm=llm, title=summary["title"], text=summary["text"])
    state.update(phishing_rule_result=result["rule"], rule_phishing_verdict=result["rule_verdict"],
                 phishing_verdict=result["verdict"], phishing_reason=result["reason"],
                 phishing_basis=result["basis"], phishing_caveats=result["caveats"],
                 llm_phishing_assessment=result["llm_assessment"],
                 # 舊布林只在最終判定為 phishing 時為 True；unknown 請讀 phishing_verdict
                 is_phishing=result["verdict"] == "phishing",
                 phishing_confidence=result["confidence"], phishing_indicators=result["indicators"])
    model = result["model"]
    if model is not None:
        state["model_outputs"] = state.get("model_outputs", []) + [model]
        if model["status"] == "invalid_or_unavailable":
            state["errors"] = state.get("errors", []) + ["[Node3] LLM error: " + model["reason"]]
    return state
