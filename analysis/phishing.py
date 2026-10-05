"""釣魚判定：本專案自行定義的規則，不是 PhishParrot 的分類器（該論文沒有提供可沿用的
分類標籤或規則，見 README「PhishParrot 核對」）。

  規則結果 rule_phishing_verdict
      φ（evaluate_page，Layer 1 布林裁決 + Layer 2 累加）＋高混淆腳本加權（v2 原樣）
      → phishing / not_detected；沒有可判讀的文件時為 not_run
  最終判定 phishing_verdict
      phishing      規則陽性（看到的證據就是證據；觀察不完整只列為 caveats）
      not_detected  規則陰性，且觀察沒有任何完整性問題 —— 不是「證明安全」
      unknown       沒有可判讀的文件，或規則陰性但觀察不完整（沒看到的部分可能正是答案）
  模型分析 llm_phishing_assessment
      只拿證據（不拿規則結果）給本機模型，輸出另存；不影響上面兩欄。

判定用頁面是瀏覽器 JS 執行後的 DOM（攻擊面是使用者看到的頁面）；不可用時退回基準 HTTP 的
原始文件，並以 analysis_without_js_execution 標註。
"""
import re

from analysis.page_mechanisms import (DECISIVE_CONFIDENCE, LAYER2_CONFIDENCE_CAP,
                                      PHISHING_CONFIDENCE_THRESHOLD, evaluate_page)
from crawler.records import blocking, caveats
from llm.contract import assessment_value, model_observation
from llm.prompts import PHISHING_ASSESSMENT_PROMPT, render_evidence
from schemas.evidence import jsonable
from schemas.versions import RULE_VERSION

_FORM = re.compile(r"<form\b[^>]*>", re.I)
_INPUT_TYPE = re.compile(r"<input\b[^>]*\btype\s*=\s*[\"']?([a-z]+)", re.I)


def _format_indicators(hits):
    return [f"{cat}: {', '.join(str(h) for h in values[:2])}" for cat, values in hits.items()]


def rule_result(html, url, scripts):
    """φ + 混淆加權。只有確定性去混淆結果進規則；模型重建的程式碼不進。"""
    extra = "\n".join(s.get("deobfuscated", "") for s in scripts)
    result = evaluate_page(html, url, extra_js=extra)
    score = result["score"]
    high_obf = sum(s.get("obfuscation_score", 0) > 0.6 for s in scripts)
    if high_obf:
        score = min(LAYER2_CONFIDENCE_CAP, score + min(0.15, high_obf * 0.05))
        result["indicators"]["heavy_obfuscation"] = [f"{high_obf} high-obfuscation scripts"]
    positive = bool(result["decisive"]) or score >= PHISHING_CONFIDENCE_THRESHOLD
    if result["decisive"]:
        basis = "layer1:" + ",".join(result["decisive"])
    else:
        relation = ">=" if positive else "<"
        basis = f"layer2_score={score:.3f}{relation}{PHISHING_CONFIDENCE_THRESHOLD}"
    return {**jsonable(result), "rule_version": RULE_VERSION, "score_after_obfuscation": score,
            "verdict": "phishing" if positive else "not_detected", "basis": basis,
            "score_semantics": "heuristic_not_probability"}


def page_evidence(html, url, title, text, scripts):
    """給模型的證據：頁面可見內容與結構摘要。不含規則結果，模型的意見才是獨立的。"""
    return {"url": url, "title": title, "visible_text_excerpt": (text or "")[:1500],
            "forms": len(_FORM.findall(html or "")),
            "input_types": sorted(set(t.lower() for t in _INPUT_TYPE.findall(html or "")))[:20],
            "script_excerpt": "\n".join(s.get("deobfuscated", "") for s in scripts)[:1500]}


def classify(html, url, scripts, issues, *, llm=None, title="", text=""):
    """回傳判定的所有欄位；呼叫端（Node 3）負責寫回 state。"""
    blocked = blocking(issues)
    pending = caveats(issues)
    if not html or blocked:
        reasons = blocked or ["unreadable_content"]
        return {"rule": {}, "rule_verdict": "not_run", "verdict": "unknown", "reason": ";".join(reasons),
                "basis": "no_readable_document", "caveats": pending, "confidence": 0.0,
                "indicators": [], "model": None, "llm_assessment": assessment_value(None)}
    rule = rule_result(html, url, scripts)
    if rule["verdict"] == "phishing":
        verdict, reason = "phishing", "rules_positive"
    elif pending:
        verdict, reason = "unknown", ";".join(pending)
    else:
        verdict, reason = "not_detected", "no_rule_threshold_met"
    model = model_observation(llm, "phishing",
                              render_evidence(PHISHING_ASSESSMENT_PROMPT,
                                              page_evidence(html, url, title, text, scripts)))
    return {"rule": rule, "rule_verdict": rule["verdict"], "verdict": verdict, "reason": reason,
            "basis": rule["basis"], "caveats": pending,
            "confidence": round(DECISIVE_CONFIDENCE if rule["decisive"] else rule["score_after_obfuscation"], 3),
            "indicators": _format_indicators(rule["indicators"]),
            "model": model, "llm_assessment": assessment_value(model)}
