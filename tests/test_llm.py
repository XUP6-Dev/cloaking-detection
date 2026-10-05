"""本機 LLM：嚴格的輸出驗證、Ollama provider、降級。不呼叫任何真模型（HTTP 層以替身取代）。"""
import pytest

import llm.providers as providers
from analysis.deobfuscation import Deobfuscator
from llm.contract import assessment_value, model_observation, validate_response
from llm.prompts import PROMPT_VERSION
from llm.providers import OllamaLocal, make_llm, settings_from_env

VALID_PHISHING = '{"assessment":"not_phishing","key_indicators":[],"explanation":"fixture"}'


@pytest.mark.parametrize("raw", [
    '{"assessment":"false","key_indicators":[],"explanation":""}',             # 不在 enum
    '{"assessment":false,"key_indicators":[],"explanation":""}',               # 型別錯
    '{"assessment":"phishing","key_indicators":"oops","explanation":""}',
    '{"assessment":"phishing","key_indicators":[],"explanation":"","confidence":NaN}',
    '{"assessment":"phishing","key_indicators":[],"explanation":"","execute":"bad"}',
    '{"assessment":"phishing","assessment":"not_phishing","key_indicators":[],"explanation":""}',
    '```json\n' + VALID_PHISHING + '\n```',                                     # 不截取大括號
    '{"assessment":"phishing","key_indicators":[]}',                            # 缺欄位
])
def test_invalid_model_output_rejected(raw):
    with pytest.raises(Exception):
        validate_response(raw, "phishing")


def test_valid_outputs_accepted_for_each_task():
    assert validate_response(VALID_PHISHING, "phishing")["assessment"] == "not_phishing"
    cloaking = ('{"assessment":"insufficient_evidence","alternative_explanations":["ab_test"],'
                '"evidence_refs":["repeat_instability"],"explanation":"fixture"}')
    assert validate_response(cloaking, "cloaking")["assessment"] == "insufficient_evidence"
    assert validate_response('{"code":"var a=1;"}', "code")["code"] == "var a=1;"


def test_ollama_schema_metadata_retry_and_unavailable(monkeypatch):
    posts = []

    class Response:
        def __init__(self, body): self.body = body
        def raise_for_status(self): pass
        def json(self): return self.body

    class Session:
        trust_env = True
        def __enter__(self): return self
        def __exit__(self, *args): pass

        def get(self, url, **kwargs):
            assert self.trust_env is False and kwargs["allow_redirects"] is False
            return Response({"models": [{"name": "fixture:1", "digest": "sha256:test"}]}
                            if url.endswith("tags") else {"version": "fixture-server"})

        def post(self, url, **kwargs):
            posts.append(kwargs)
            if len(posts) == 1:
                raise providers.requests.Timeout("fixture")
            return Response({"done": True, "message": {"content": VALID_PHISHING}})

    monkeypatch.setattr(providers.requests, "Session", Session)
    monkeypatch.setattr(providers.time, "sleep", lambda _: None)
    model = OllamaLocal("fixture:1", "http://127.0.0.1:11434", timeout=1, retries=1)
    answer = model_observation(model, "phishing", "untrusted fixture")
    assert answer["status"] == "valid" and len(posts) == 2
    assert posts[0]["json"]["format"]["type"] == "object"
    assert posts[0]["json"]["options"] == {"temperature": 0, "seed": 0, "num_predict": 512, "num_ctx": 8192}
    assert answer["model"]["model_digest"] == "sha256:test"
    assert answer["model"]["server_version"] == "fixture-server"
    assert answer["prompt_version"] == PROMPT_VERSION and answer["prompt_sha256"] and answer["template_sha256"]
    assert assessment_value(answer) == "not_phishing"
    missing = model_observation(OllamaLocal("missing", "http://localhost:11434", retries=0), "phishing", "x")
    assert missing["status"] == "invalid_or_unavailable" and assessment_value(missing) == "unavailable"


def test_ollama_endpoint_must_be_local_and_model_must_be_local():
    with pytest.raises(ValueError):
        OllamaLocal("fixture:1", "https://cloud.invalid")
    with pytest.raises(ValueError):
        OllamaLocal("fixture:1", "http://192.168.1.5:11434")
    with pytest.raises(ValueError):
        OllamaLocal("model:cloud", "http://localhost:11434")


@pytest.mark.parametrize("provider", ["openai", "anthropic", "deepseek", "google", "lmstudio"])
def test_removed_cloud_providers_disable_the_model_instead_of_switching(provider):
    config = settings_from_env({"LLM_PROVIDER": provider})
    assert config["error"] == f"unsupported_provider:{provider}"
    assert make_llm(512, {"LLM_PROVIDER": provider}) == (None, f"unsupported_provider:{provider}")


def test_configurable_endpoint_and_model():
    env = {"LLM_PROVIDER": "ollama", "LLM_MODEL": "qwen2.5:7b", "OLLAMA_BASE_URL": "http://localhost:11500",
           "OLLAMA_TIMEOUT": "30", "OLLAMA_RETRIES": "0", "OLLAMA_NUM_CTX": "4096"}
    model, reason = make_llm(256, env)
    assert not reason and model.model == "qwen2.5:7b" and model.base_url == "http://localhost:11500"
    assert model.audit_metadata["parameters"]["num_ctx"] == 4096 and model.retries == 0
    assert make_llm(256, {"LLM_PROVIDER": "none"}) == (None, "LLM_PROVIDER=none")


def test_disabled_model_is_recorded_not_silent(monkeypatch):
    monkeypatch.setattr(providers, "DISABLED_REASON", "LLM_PROVIDER=none")
    audit = model_observation(None, "cloaking", "fixture")
    assert audit["status"] == "unavailable" and audit["reason"] == "LLM_PROVIDER=none"
    assert assessment_value(audit) == "unavailable" and assessment_value(None) == "not_run"


def test_model_metadata_is_a_snapshot():
    class Model:
        audit_metadata = {"model_digest": "before"}
        def invoke(self, prompt): return VALID_PHISHING
    model = Model()
    result = model_observation(model, "phishing", "fixture")
    model.audit_metadata["model_digest"] = "after"
    assert result["model"]["model_digest"] == "before"


def test_llm_reconstruction_cannot_change_deterministic_code():
    class Advisory:
        def invoke(self, prompt): return '{"code":"const invented = 999;"}'
    original = "[]!+()" * 20
    a, b = Deobfuscator().deobfuscate(original, Advisory()), Deobfuscator().deobfuscate(original, None)
    assert a["deobfuscated"] == b["deobfuscated"]
    assert a["model_code"] == "const invented = 999;" and a["model_outputs"][0]["status"] == "valid"
