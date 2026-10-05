"""CSV 欄位與逐列投影 —— 兩份 CSV 都從這一個函式取值。

v2 有兩條投影（Node 5 一條、main.py 一條），同一列曾出現 is_phishing=False 與空白兩種值。
現在 result_row() 是唯一來源：summary（cloaking_report_*.csv）取它的子集，
batch_results_*.csv 取全部；成功列與失敗列都經過它，欄位集合必然相同。

新欄位一律附加在既有欄位之後；讀取請按欄名，不要按位置。
"""
import json
from datetime import datetime

from analysis.signals import summarize
from schemas.evidence import utc_now
from schemas.labels import cloaking_projection, phishing_projection
from schemas.versions import MEASUREMENT_VERSION, SCHEMA_VERSION

LEGACY_FIELDS = ["url", "alive", "is_phishing", "cloaking"]

# batch_results 的診斷欄（v2 原有，順序不變）。bot_* = 基準 HTTP、human_* = 瀏覽器（主觀察）。
DIAG_FIELDS = [
    "phishing_confidence", "phishing_indicators",
    "cloaking_fired", "cloaking_tier", "dynamic_reliability",
    "human_mechanisms", "human_high_spec", "content_similarity",
    "bot_channel_blocked", "bot_status_code", "human_status_code",
    "bot_html_length", "human_html_length", "bot_error", "human_error",
    "bot_mechanisms", "hidden_from_bot", "bot_is_phishing", "human_is_phishing",
    "reverse_diff", "rule_fired_raw", "crawl_order", "pair_mode",
]

AUDIT_FIELDS = [
    # v2
    "schema_version", "measurement_version", "run_id", "batch_id", "source_label",
    "phishing_verdict", "cloaking_label", "evidence", "reason", "source",
    "observed_at", "profile_id", "source_fetched_at", "raw_url", "normalized_url",
    # v3：規則結果／模型分析／最終標籤分開保存，並附判定依據、不確定原因、證據來源與設定
    "rule_phishing_verdict", "llm_phishing_assessment",
    "rule_cloaking_label", "llm_cloaking_assessment",
    "phishing_basis", "cloaking_basis", "uncertainty_reasons", "evidence_sources",
    "cloaking_signals", "cloaking_signals_not_tested",
    "observation_plan", "run_config_sha256", "llm_model", "prompt_version",
]

SUMMARY_FIELDS = LEGACY_FIELDS + AUDIT_FIELDS
BATCH_FIELDS = (["url", "label", "alive", "is_phishing", "cloaking"] + DIAG_FIELDS
                + ["error_count", "analyzed_at"] + AUDIT_FIELDS + ["status"])


def _llm_identity():
    import llm
    from llm.prompts import PROMPT_VERSION
    model = "disabled" if llm.providers.DISABLED_REASON else f"ollama:{llm.MODEL_NAME}"
    return model, PROMPT_VERSION


def audit_columns(state):
    source = state.get("source_record") or {}
    bot, human = state.get("bot_crawl") or {}, state.get("human_crawl") or {}
    observed, not_tested = summarize(state.get("signals") or [])
    phishing_unknown = (state.get("phishing_reason", "").split(";")
                        if state.get("phishing_verdict") == "unknown" else [])
    # Node 4 沒跑到（網址無效、沒有可判讀的頁面）時，理由在 cloaking_reason
    cloaking_unknown = ((state.get("cloaking_uncertainty") or state.get("cloaking_reason", "").split(";"))
                        if state.get("cloaking_label") == "unknown" else [])
    names = [name for name, record in (("bot#1", bot), ("bot#2", bot.get("confirmation")),
                                       ("human#1", human), ("human#2", human.get("confirmation")))
             if record]
    model, prompt_version = _llm_identity()
    return {
        "schema_version": SCHEMA_VERSION, "measurement_version": MEASUREMENT_VERSION,
        "run_id": state.get("run_id", ""), "batch_id": source.get("batch_id", ""),
        "source_label": source.get("source_label", "unlabeled"),
        "phishing_verdict": state.get("phishing_verdict", "unknown"),
        "cloaking_label": state.get("cloaking_label", "unknown"),
        "evidence": json.dumps(state.get("evidence", {}), ensure_ascii=False),
        "reason": json.dumps({"phishing": state.get("phishing_reason", "not_observed"),
                              "cloaking": state.get("cloaking_reason", "not_observed")}, ensure_ascii=False),
        "source": source.get("source", "manual_input"),
        "observed_at": state.get("observed_at") or utc_now(),
        "profile_id": json.dumps({slot: record.get("profile_id", "unobserved")
                                  for slot, record in (("bot", bot), ("human", human))}),
        "source_fetched_at": source.get("fetched_at", ""),
        "raw_url": source.get("raw_url", state.get("url", "")),
        "normalized_url": source.get("normalized_url", state.get("url", "")),
        "rule_phishing_verdict": state.get("rule_phishing_verdict", "not_run"),
        "llm_phishing_assessment": state.get("llm_phishing_assessment", "not_run"),
        "rule_cloaking_label": state.get("rule_cloaking_label", "unknown"),
        "llm_cloaking_assessment": state.get("llm_cloaking_assessment", "not_run"),
        "phishing_basis": state.get("phishing_basis", ""),
        "cloaking_basis": state.get("cloaking_basis", ""),
        "uncertainty_reasons": json.dumps(
            {"phishing": sorted(set(filter(None, phishing_unknown + list(state.get("phishing_caveats") or [])))),
             "cloaking": cloaking_unknown}, ensure_ascii=False),
        "evidence_sources": json.dumps({"phishing": state.get("analysis_source", ""), "cloaking": names,
                                        "variants": sorted(state.get("variant_observations") or {})}),
        "cloaking_signals": observed, "cloaking_signals_not_tested": not_tested,
        "observation_plan": state.get("observation_plan", ""),
        "run_config_sha256": state.get("run_config_sha256", ""),
        "llm_model": model, "prompt_version": prompt_version,
    }


def result_row(state):
    """一列完整結果（batch_results 的欄位 + report）。"""
    dual = state.get("dual_crawl_results") or {}
    bot, human = state.get("bot_crawl") or {}, state.get("human_crawl") or {}
    settings = state.get("observation_settings") or {}
    source = state.get("source_record") or {}
    return {
        "url": state["url"],
        # 分母：第二方來源的清單標籤（不是本系統的判定，也不是人工真值）。
        # 絕不可流進 pairs/meta.json —— 標註者知道「這站被標為釣魚」就不是盲標了。
        "label": source.get("label", ""),
        "alive": state.get("alive", True),
        "is_phishing": phishing_projection(state.get("phishing_verdict", "unknown")),
        "cloaking": cloaking_projection(state.get("cloaking_label", "unknown")),
        # 信心度是歸因釣魚誤判的線索：0.95 一定是 Layer 1，落在 0.45 附近的是 Layer 2 擦邊。
        "phishing_confidence": state.get("phishing_confidence", 0.0),
        "phishing_indicators": "|".join(state.get("phishing_indicators") or []),
        "cloaking_fired": "|".join(dual.get("fired_rules") or []),
        "cloaking_tier": state.get("cloaking_confidence_tier", ""),
        "dynamic_reliability": dual.get("dynamic_reliability", ""),
        "human_mechanisms": "|".join(dual.get("human_mechanisms") or []),
        "human_high_spec": "|".join(dual.get("human_high_spec") or []),
        "content_similarity": dual.get("content_similarity", ""),
        "bot_channel_blocked": dual.get("bot_channel_blocked", ""),
        "bot_status_code": dual.get("bot_status_code", bot.get("status_code", "")),
        "human_status_code": dual.get("human_status_code", human.get("status_code", "")),
        "bot_html_length": dual.get("bot_html_length", bot.get("html_length", "")),
        "human_html_length": dual.get("human_html_length", human.get("html_length", "")),
        # error 逐列留著才分得出「被送空白頁」與「觀察失敗」—— 兩者 html_length 都是 0
        "bot_error": dual.get("bot_error") or bot.get("error") or "",
        "human_error": dual.get("human_error") or human.get("error") or "",
        "bot_mechanisms": "|".join(dual.get("bot_mechanisms") or []),
        "hidden_from_bot": "|".join(dual.get("hidden_from_bot") or []),
        "bot_is_phishing": dual.get("bot_is_phishing", ""),
        "human_is_phishing": dual.get("human_is_phishing", ""),
        "reverse_diff": "|".join(dual.get("reverse_diff") or []),
        "rule_fired_raw": dual.get("rule_fired_raw", ""),
        # 這一列「實際」跑的順序，不是設定值 —— split 之下設定只說明「有切分」
        "crawl_order": human.get("crawl_order") or bot.get("crawl_order") or settings.get("crawl_order", ""),
        "pair_mode": settings.get("pair_mode") or human.get("pair_mode", ""),
        "error_count": len(state.get("errors", [])),
        "report": state.get("report", ""),
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        **audit_columns(state),
    }


def summary_row(state):
    row = result_row(state)
    return {key: row[key] for key in SUMMARY_FIELDS}
