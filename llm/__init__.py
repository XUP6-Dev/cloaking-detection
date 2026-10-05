"""本機 LLM：provider、提示詞、輸出契約。模型只產生說明與第二意見，不決定任何標籤。

  providers.py  Ollama（預設）與 none；設定讀環境變數
  prompts.py    提示詞模板與版本
  contract.py   JSON Schema、嚴格驗證、每次呼叫的稽核紀錄

模組層的 llm_code / llm_phish / llm_cloak 由 graph.py 注入各節點；測試把它們換成 None
或替身。.env 只補「尚未設定」的變數，不覆寫已存在的環境變數。
"""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from llm import providers                                   # noqa: E402
from llm.providers import OllamaLocal, make_llm             # noqa: E402,F401

CONFIG = providers.settings_from_env()
LLM_PROVIDER, MODEL_NAME = CONFIG["provider"], CONFIG["model"]

# 各任務的輸出長度預算不同；逾時與重試由 OLLAMA_TIMEOUT / OLLAMA_RETRIES 統一設定。
llm_code, _reason = make_llm(num_predict=2048)
llm_phish, _ = make_llm(num_predict=512)
llm_cloak, _ = make_llm(num_predict=768)
providers.DISABLED_REASON = _reason
if _reason:
    print(f"[LLM] 模型停用（{_reason}）—— llm_* 欄位記為 unavailable，規則判定不受影響")
else:
    print(f"[LLM] provider=ollama model={MODEL_NAME} base_url={CONFIG['base_url']}")


def audit_config():
    """寫進 manifest 的模型設定（不含任何秘密）。"""
    from llm.prompts import template_hashes
    meta = getattr(llm_phish, "audit_metadata", {})
    return {**CONFIG, "disabled_reason": providers.DISABLED_REASON,
            "parameters": meta.get("parameters", {}), "prompts": template_hashes()}
