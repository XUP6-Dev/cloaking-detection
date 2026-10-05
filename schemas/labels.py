"""標籤值域與舊欄位投影。

每個判定都分三層保存，三層不可互相覆寫：
  規則結果（rule_*）  只看規則、在觀察品質閘門之前 —— 用來稽核閘門擋掉了什麼
  模型分析（llm_*）   只作說明與人工複核提示，**不進入最終標籤**
  最終標籤            規則結果經過觀察品質／替代解釋閘門之後的結論

unknown 與 false（或 not_detected）永遠分開計：「量過但測不準」和「驗過沒有」
不是同一件事，任何統計都不可把前者併入後者。
"""
PHISHING_VERDICTS = ("phishing", "not_detected", "unknown")
RULE_PHISHING_VERDICTS = ("phishing", "not_detected", "not_run")
CLOAKING_LABELS = ("true", "false", "unknown")

LLM_PHISHING_ASSESSMENTS = ("phishing", "not_phishing", "insufficient_evidence")
LLM_CLOAKING_ASSESSMENTS = ("supports_cloaking", "does_not_support_cloaking", "insufficient_evidence")
# 模型停用、連不上、逾時或輸出不符 schema —— 原因寫在稽核 JSON 的 model_outputs。
LLM_UNAVAILABLE = "unavailable"
# 沒有可用的觀察證據（網址無效、四次觀察都失敗），刻意不呼叫模型。
LLM_NOT_RUN = "not_run"

# 舊 `cloaking` 欄的第三態。不寫成 False —— 未經測量不等於測得為否。
CLOAKING_UNKNOWN = "N/A"


def cloaking_projection(label):
    """cloaking_label → 舊 `cloaking` 欄（True / False / "N/A"）。"""
    return {"true": True, "false": False}.get(label, CLOAKING_UNKNOWN)


def phishing_projection(verdict):
    """phishing_verdict → 舊 `is_phishing` 欄（True / False / "N/A"）。

    v2 把 unknown 投影成 False，兩份 CSV 又各自投影，同一列曾出現 False 與空白兩種值。
    v3 起與 cloaking 欄同規則：unknown 一律寫 N/A，兩份 CSV 共用這個函式。
    """
    return {"phishing": True, "not_detected": False}.get(verdict, CLOAKING_UNKNOWN)
