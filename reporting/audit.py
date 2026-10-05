"""逐列稽核 JSON：audit_records/<run_id>/<analysis_id>.json，"x" 模式建立、不可覆寫。

內容分層保存：觀察紀錄（大型內容換成證據檔路徑＋SHA-256）、訊號表、規則結果、
模型輸出、最終標籤與閘門理由。CSV 的 evidence 欄記這個檔的路徑與雜湊。
"""
import json
from pathlib import Path

from crawler.records import audit_view
from schemas.evidence import jsonable, sha256, utc_now
from schemas.versions import MEASUREMENT_VERSION, RULE_VERSION, SCHEMA_VERSION

AUDIT_ROOT = Path(__file__).resolve().parents[1] / "audit_records"
PHI_PATH = Path(__file__).resolve().parents[1] / "analysis" / "page_mechanisms.py"
_FINAL_KEYS = ("phishing_verdict", "rule_phishing_verdict", "llm_phishing_assessment", "phishing_reason",
               "phishing_basis", "phishing_caveats", "cloaking_label", "rule_cloaking_label",
               "llm_cloaking_assessment", "cloaking_reason", "cloaking_basis", "cloaking_uncertainty")


def _script_view(script):
    view = {k: v for k, v in script.items() if k not in ("content", "deobfuscated", "model_code")}
    for key in ("content", "deobfuscated"):
        text = script.get(key) or ""
        view[f"{key}_sha256"], view[f"{key}_length"] = sha256(text), len(text)
    view["deobfuscated_excerpt"] = (script.get("deobfuscated") or "")[:20000]
    if script.get("model_code"):
        view["model_code"] = script["model_code"][:20000]   # 模型重建：參考用，規則不讀
    return view


def finalize_audit(state):
    if state.get("evidence", {}).get("audit_path"):
        return state
    state["observed_at"] = utc_now()
    payload = {
        "schema_version": SCHEMA_VERSION, "measurement_version": MEASUREMENT_VERSION,
        "rule_version": RULE_VERSION, "rule_sha256": sha256(PHI_PATH.read_bytes()),
        "url": state.get("url"), "run_id": state.get("run_id"), "analysis_id": state.get("analysis_id"),
        "source_record": state.get("source_record", {}), "observed_at": state["observed_at"],
        "observation_settings": state.get("observation_settings", {}),
        "observation_plan": state.get("observation_plan", ""),
        "run_config_sha256": state.get("run_config_sha256", ""),
        "crawl_records": {"bot": audit_view(state.get("bot_crawl")), "human": audit_view(state.get("human_crawl"))},
        "variant_observations": {k: audit_view(v) for k, v in (state.get("variant_observations") or {}).items()},
        "analysis_source": state.get("analysis_source", ""),
        "analysis_observation_issues": state.get("observation_issues", []),
        "deterministic_scripts": [_script_view(s) for s in state.get("deobfuscated_js", [])],
        "phishing_rule_result": state.get("phishing_rule_result", {}),
        "static_evidence": state.get("static_evidence", {}),
        "signals": state.get("signals", []),
        "cloaking_rule_result": state.get("dual_crawl_results", {}),
        "model_outputs": state.get("model_outputs", []),
        "final": {key: state.get(key, "") for key in _FINAL_KEYS},
        "errors": state.get("errors", []),
        # 不可信字串可能含孤立的 UTF-16 surrogate：JSON 以 \u 跳脫保存，雜湊用 surrogatepass。
        "text_hash_encoding": "utf-8/surrogatepass",
    }
    directory = AUDIT_ROOT / state["run_id"]
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{state['analysis_id']}.json"
    data = json.dumps(jsonable(payload), ensure_ascii=True, indent=2).encode("utf-8")
    with path.open("xb") as handle:
        handle.write(data)
    state["evidence"] = {"audit_path": str(path), "sha256": sha256(data)}
    return state
