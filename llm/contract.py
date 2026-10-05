"""模型輸出契約：JSON Schema、嚴格驗證、每次呼叫的稽核紀錄。

模型輸出只會被「保存」與「投影成 llm_* 欄位」，從不寫進規則結果或最終標籤。
驗證失敗、模型不可用、逾時都降級為 unavailable 並記錄原因 —— 不會因為模型掛掉而
產生確定標籤，也不會因為模型說了什麼而改變確定標籤。
"""
import copy
import json

from jsonschema import Draft202012Validator

from llm import providers
from llm.prompts import PROMPT_VERSION, SYSTEM_BOUNDARY, TEMPLATES
from schemas.evidence import sha256, utc_now
from schemas.labels import (LLM_CLOAKING_ASSESSMENTS, LLM_NOT_RUN, LLM_PHISHING_ASSESSMENTS,
                            LLM_UNAVAILABLE)

_SHORT_LIST = {"type": "array", "maxItems": 20, "items": {"type": "string", "maxLength": 500}}
SCHEMAS = {
    "phishing": {"type": "object", "additionalProperties": False,
                 "required": ["assessment", "key_indicators", "explanation"],
                 "properties": {"assessment": {"type": "string", "enum": list(LLM_PHISHING_ASSESSMENTS)},
                                "key_indicators": _SHORT_LIST,
                                "explanation": {"type": "string", "maxLength": 2000}}},
    "cloaking": {"type": "object", "additionalProperties": False,
                 "required": ["assessment", "alternative_explanations", "evidence_refs", "explanation"],
                 "properties": {"assessment": {"type": "string", "enum": list(LLM_CLOAKING_ASSESSMENTS)},
                                "alternative_explanations": _SHORT_LIST,
                                "evidence_refs": _SHORT_LIST,
                                "explanation": {"type": "string", "maxLength": 3000}}},
    "code": {"type": "object", "additionalProperties": False, "required": ["code"],
             "properties": {"code": {"type": "string", "maxLength": 20000}}},
}


def validate_response(raw, task):
    """完整 JSON 才接受：不截取大括號、不把字串 "false" 當布林、拒絕 NaN 與重複鍵。"""
    def reject_constant(value):
        raise ValueError(f"non_finite_json:{value}")

    def unique_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate_json_key")
            out[key] = value
        return out

    if not isinstance(raw, str) or len(raw) > 100000:
        raise ValueError("invalid_response_type_or_size")
    value = json.loads(raw, parse_constant=reject_constant, object_pairs_hook=unique_pairs)
    Draft202012Validator(SCHEMAS[task]).validate(value)
    return value


def model_observation(llm, task, prompt):
    """呼叫一次模型並回傳完整稽核紀錄（提示詞、版本、模型 digest、原始回應、驗證狀態）。"""
    audit = {"task": task, "prompt_version": PROMPT_VERSION, "observed_at": utc_now(),
             "prompt": prompt, "prompt_sha256": sha256(prompt),
             "template_sha256": sha256(TEMPLATES[task]), "system": SYSTEM_BOUNDARY,
             "status": "unavailable", "output": None,
             "advisory_only": True}
    if llm is None:
        audit["reason"] = providers.DISABLED_REASON or "provider_disabled_or_unavailable"
        return audit
    audit["model"] = copy.deepcopy(getattr(llm, "audit_metadata",
                                           {"provider": type(llm).__name__, "version": "unreported"}))
    try:
        if hasattr(llm, "invoke_json"):
            raw = llm.invoke_json(prompt, SCHEMAS[task], SYSTEM_BOUNDARY)
        else:   # 測試替身或自訂 provider：只要求 invoke(prompt) -> str
            raw = llm.invoke(SYSTEM_BOUNDARY + "\n" + prompt + "\nJSON Schema:\n" + json.dumps(SCHEMAS[task]))
        raw = getattr(raw, "content", raw)
        audit["raw_response"] = raw
        audit["output"] = validate_response(raw, task)
        audit["status"] = "valid"
    except Exception as exc:
        audit["status"] = "invalid_or_unavailable"
        audit["reason"] = f"{type(exc).__name__}: {exc}"[:2000]
    # 呼叫後再取一次：Ollama 在呼叫時才查得到 digest 與伺服器版本。存快照，不存參照。
    audit["model"] = copy.deepcopy(getattr(llm, "audit_metadata", audit["model"]))
    return audit


def assessment_value(audit):
    """稽核紀錄 → CSV 的 llm_*_assessment 值。"""
    if audit is None:
        return LLM_NOT_RUN
    if audit.get("status") == "valid":
        return audit["output"]["assessment"]
    return LLM_UNAVAILABLE
