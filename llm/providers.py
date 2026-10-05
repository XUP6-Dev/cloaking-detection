"""本機 LLM provider：只支援 Ollama（預設）與 none（停用）。

設定（建議放在 .vscode/launch.json，不要在 PowerShell 下 $env:，殘留值會帶進下一批）：
  LLM_PROVIDER     ollama | none
  LLM_MODEL        本機已安裝的模型名稱，例如 qwen3.5:9b
  OLLAMA_BASE_URL  只接受 loopback 的 http origin，例如 http://127.0.0.1:11434
  OLLAMA_TIMEOUT   每次 HTTP 請求秒數（0 < t ≤ 600）
  OLLAMA_RETRIES   額外重試次數（0–3）
  OLLAMA_NUM_CTX   context 長度；明確設定，避免 Ollama 預設值靜默截掉長提示詞

v2 的雲端 provider（deepseek / anthropic / openai / google / lmstudio）已移除：
頁面內容是不可信的釣魚素材，不送往第三方 API；雲端模型也拿不到可稽核的 digest。
設定成這些值不會改用別的 provider —— 模型停用並在 manifest 與每次呼叫記錄原因。
"""
import os
import time
from urllib.parse import urlsplit

import requests

SUPPORTED_PROVIDERS = ("ollama", "none")
DEFAULT_MODEL = "qwen3.5:9b"
DEFAULT_BASE_URL = "http://127.0.0.1:11434"

# import 時由 llm/__init__.py 設定：模型停用時每筆稽核紀錄都寫這個原因。
DISABLED_REASON = ""


class OllamaLocal:
    """Ollama 原生 API。不自動下載模型、不讀環境 proxy、不跟隨導向、沒有雲端備援。"""

    def __init__(self, model, base_url=DEFAULT_BASE_URL, timeout=60, retries=1, num_predict=512,
                 num_ctx=8192):
        p = urlsplit(base_url)
        if (p.scheme != "http" or p.hostname not in ("127.0.0.1", "localhost", "::1")
                or p.username or p.password or p.query or p.fragment or p.path not in ("", "/")):
            raise ValueError("OLLAMA_BASE_URL must be a local loopback HTTP origin")
        if "cloud" in model.lower():
            raise ValueError("cloud_models_disabled")
        if not 0 < timeout <= 600 or not 0 <= retries <= 3:
            raise ValueError("invalid_ollama_timeout_or_retries")
        self.model, self.base_url = model, base_url.rstrip("/")
        self.timeout, self.retries = timeout, retries
        # temperature 0 + 固定 seed：同模型同提示詞盡量給同答案（仍不保證位元級可重現）
        self.options = {"temperature": 0, "seed": 0, "num_predict": num_predict, "num_ctx": num_ctx}
        self.audit_metadata = {"provider": "ollama", "model": model, "base_url": self.base_url,
                               "timeout_seconds": timeout, "retries": retries,
                               "parameters": dict(self.options), "think": False,
                               "model_digest": "unavailable", "server_version": "unavailable"}

    def invoke_json(self, prompt, schema, system):
        """非串流 /api/chat，format=JSON Schema。每次都重查 digest 與版本，寫進稽核。"""
        with requests.Session() as session:
            session.trust_env = False
            for attempt in range(self.retries + 1):
                try:
                    tags = session.get(self.base_url + "/api/tags", timeout=self.timeout,
                                       allow_redirects=False)
                    tags.raise_for_status()
                    names = {self.model, self.model + ":latest"}
                    installed = next((m for m in tags.json()["models"]
                                      if m.get("name") in names or m.get("model") in names), None)
                    if not installed or installed.get("remote_host") or installed.get("remote_model"):
                        raise ValueError("local_model_not_installed")
                    self.audit_metadata["model_digest"] = installed.get("digest", "unreported")
                    ver = session.get(self.base_url + "/api/version", timeout=self.timeout,
                                      allow_redirects=False)
                    ver.raise_for_status()
                    self.audit_metadata["server_version"] = ver.json().get("version", "unreported")
                    response = session.post(
                        self.base_url + "/api/chat", timeout=self.timeout, allow_redirects=False,
                        json={"model": self.model, "stream": False, "think": False, "format": schema,
                              "options": self.options,
                              "messages": [{"role": "system", "content": system},
                                           {"role": "user", "content": prompt}]})
                    try:
                        response.raise_for_status()
                    except requests.HTTPError as exc:
                        try:
                            detail = str(response.json().get("error", ""))[:1000]
                        except ValueError:
                            detail = "non_json_error_response"
                        raise requests.HTTPError(f"Ollama chat HTTP failure: {detail or exc}") from exc
                    body = response.json()
                    if not body.get("done") or body.get("error"):
                        raise ValueError("incomplete_ollama_response")
                    return body["message"]["content"]
                except (requests.RequestException, ValueError, KeyError):
                    if attempt == self.retries:
                        raise
                    time.sleep(min(2 ** attempt, 4))


def settings_from_env(env=None):
    """讀取並檢查設定；不合法的值不拋例外，而是回傳 error（模型因此停用）。"""
    env = os.environ if env is None else env
    provider = env.get("LLM_PROVIDER", "ollama").strip().lower()
    config = {"provider": provider, "model": env.get("LLM_MODEL", DEFAULT_MODEL),
              "base_url": env.get("OLLAMA_BASE_URL", DEFAULT_BASE_URL), "error": ""}
    try:
        config["timeout"] = float(env.get("OLLAMA_TIMEOUT", "60"))
        config["retries"] = int(env.get("OLLAMA_RETRIES", "1"))
        config["num_ctx"] = int(env.get("OLLAMA_NUM_CTX", "8192"))
    except ValueError:
        config["error"] = "invalid_ollama_numeric_setting"
    if provider not in SUPPORTED_PROVIDERS:
        config["error"] = f"unsupported_provider:{provider}"
    elif provider == "none":
        config["error"] = "LLM_PROVIDER=none"
    return config


def make_llm(num_predict, env=None):
    """依設定建立 provider；停用或設定錯誤時回傳 (None, 原因)。"""
    config = settings_from_env(env)
    if config["error"]:
        return None, config["error"]
    try:
        return OllamaLocal(config["model"], config["base_url"], config["timeout"], config["retries"],
                           num_predict, config["num_ctx"]), ""
    except ValueError as exc:
        return None, f"invalid_ollama_config:{exc}"
