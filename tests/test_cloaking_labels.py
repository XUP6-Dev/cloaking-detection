"""v3 cloaking 標籤：規則結果經過觀察品質與替代解釋閘門後的三態。

每個情境對應一個「單一差異不得直接證明 cloaking」的替代解釋：頁面更新、短暫故障、
A/B 測試或隨機內容、非同步／JS 渲染、存取順序、反爬蟲。閘門擋下時標籤是 unknown，
理由寫在 reasons —— 絕不默默變成 false。
"""
import copy
import inspect
import json

import pytest

import graph
from analysis.cloaking import decide_cloaking, label_cloaking
from analysis.signals import compute_signals, summarize
from nodes.node4_cloaking_analyzer import analyze_cloaking_node
from support import CLEAN, LOGIN_PAGE, MALICIOUS, URL, browser, pair, record

SHELL = '<html><head><title>App</title></head><body><div id="root"></div><script src="/app.js"></script></body></html>'
SHELL_RENDERED = SHELL.replace('<div id="root"></div>',
                               '<div id="root"><form action="/x"><input type="password" name="p"></form></div>')


def label(bot, human, **kw):
    return label_cloaking(bot, human, URL, **kw)


def test_replicated_mechanism_difference_is_true():
    d = label(*pair(record(CLEAN), browser(MALICIOUS)))
    assert (d["rule_label"], d["label"]) == ("true", "true"), d["reasons"]
    assert "C1" in d["basis"] and "webhook_exfiltration" in d["basis"]


def test_identical_stable_pages_are_false():
    d = label(*pair(record(CLEAN), browser(CLEAN)))
    assert (d["rule_label"], d["label"]) == ("false", "false"), d["reasons"]


def test_difference_seen_once_is_unknown():
    """A/B 測試／輪播：主配對有差、重複配對沒差 → 不能歸因於 client 類型。"""
    d = label(*pair(record(CLEAN), browser(MALICIOUS), human2=browser(CLEAN)))
    assert d["rule_label"] == "true" and d["label"] == "unknown"
    assert "difference_not_replicated" in d["reasons"]


def test_first_access_only_content_is_unknown_and_flagged():
    """只對第一次存取給真內容（burn-after-read）：先到的一側獨有機制 → 反向差 + 同側不穩。"""
    bot, human = pair(record(MALICIOUS), browser(CLEAN), bot2=record(CLEAN))
    d = label(bot, human)
    assert d["label"] == "unknown"
    assert "reverse_difference_or_order_effect" in d["reasons"] and "bot_unstable_mechanisms" in d["reasons"]
    first = {s["id"]: s for s in compute_signals(bot, human)}["first_access_only"]
    assert first["status"] == "observed" and first["evidence"]["mechanisms_only_in_first_access"]


def test_page_update_between_observations_is_unknown():
    """同側兩次狀態不同（短暫故障或頁面更新）→ unknown。"""
    d = label(*pair(record(CLEAN), browser(CLEAN), bot2=record(CLEAN, status=503)))
    assert d["label"] == "unknown" and "bot#2:http_error_status" in d["reasons"]


def test_nonce_only_variation_still_allows_false():
    """每次請求都換的 token 只讓雜湊不同；狀態、主機、機制、結構穩定 → 仍可判 false。"""
    page = "<html><head><title>Docs</title></head><body><p>Docs</p><p>token={}</p></body></html>"
    d = label(*pair(record(page.format(1)), browser(page.format(2)),
                    bot2=record(page.format(3)), human2=browser(page.format(4))))
    assert d["label"] == "false", d["reasons"]


def test_systematic_difference_without_mechanisms_is_unknown():
    """兩種 client 穩定地拿到不同頁面，但 φ 認不出任何機制 → 不能宣稱 false（φ 的盲區）。"""
    a = "<html><head><title>Under construction</title></head><body><p>Soon</p></body></html>"
    b = "<html><head><title>Invoice ready</title></head><body><p>Download your invoice</p></body></html>"
    d = label(*pair(record(a), browser(b)))
    assert d["rule_label"] == "false" and d["label"] == "unknown"
    assert "systematic_title_difference_without_mechanism_evidence" in d["reasons"]


def test_js_rendered_content_is_not_cloaking_but_blocks_false():
    """兩種 client 收到同一份 SPA 外殼；表單由 JS 渲染 → 不是差別遞送（rule false），
    但只在 JS 執行後出現的機制從未跨 client 比較過 → 不能判 false。"""
    d = label(*pair(record(SHELL), browser(SHELL, dom=SHELL_RENDERED)))
    assert d["rule_label"] == "false" and d["label"] == "unknown"
    assert "human#1:js_rendered_mechanisms_not_compared" in d["reasons"]


def test_challenge_on_browser_side_blocks_both_directions():
    gated = MALICIOUS.replace("<body", '<body><div class="g-recaptcha"></div><span', 1)
    d = label(*pair(record(CLEAN), browser(gated)))
    assert d["rule_label"] == "true" and d["label"] == "unknown"
    assert "human#1:challenge_or_block_page" in d["reasons"]


def test_bot_blocked_with_high_spec_human_replicated_is_true():
    """C2：基準 client 穩定被擋、瀏覽器穩定拿到高特異性惡意頁 → true。"""
    d = label(*pair(record("", status=403), browser(MALICIOUS)))
    assert d["label"] == "true" and "C2" in d["basis"], d["reasons"]


def test_anti_bot_block_with_ordinary_page_is_unknown_not_false():
    """WAF 擋非瀏覽器 client、瀏覽器拿到一般登入頁：不是 cloaking 的證據，但也沒比到內容 → unknown。"""
    d = label(*pair(record("", status=403), browser(LOGIN_PAGE)))
    assert d["rule_label"] == "false" and d["label"] == "unknown"
    assert "bot#1:http_error_status" in d["reasons"]


def test_frontend_cloaking_code_blocks_false():
    d = label(*pair(record(CLEAN), browser(CLEAN)), frontend_rules=["S1"])
    assert d["label"] == "unknown" and "frontend_cloaking_code_present:S1" in d["reasons"]


def test_variant_difference_blocks_false_but_cannot_make_true():
    d = label(*pair(record(CLEAN), browser(CLEAN)), variant_differences=["mobile"])
    assert d["label"] == "unknown" and "variant_difference_unconfirmed:mobile" in d["reasons"]


def test_missing_browser_document_makes_rule_unknown():
    d = label(*pair(record(CLEAN), browser("", status=0, error="TimeoutError: fixture")))
    assert d["rule_label"] == "unknown" and d["label"] == "unknown"
    assert "human#1:crawl_error" in d["reasons"]


def test_missing_replicate_is_unknown():
    bot, human = record(CLEAN), browser(MALICIOUS)
    d = label(bot, human)
    assert d["rule_label"] == "true" and d["label"] == "unknown"
    assert "bot#2:missing_observation" in d["reasons"] or "missing_replicate_pair" in d["reasons"]


def test_cloaking_decision_never_takes_a_model():
    """CLAUDE.md 不變量：LLM 不進 cloaking 裁決路徑 —— 連參數都不收。"""
    for fn in (decide_cloaking, label_cloaking):
        assert "llm" not in inspect.signature(fn).parameters


# ── Node 4：模型只寫自己的欄位 ─────────────────────────────────────
class _SaysCloaking:
    def __init__(self):
        self.prompts = []

    def invoke(self, prompt):
        self.prompts.append(prompt)
        return ('{"assessment": "supports_cloaking", "alternative_explanations": [], '
                '"evidence_refs": ["client_type_response_difference"], "explanation": "fixture"}')


class _Broken:
    def invoke(self, prompt):
        return "not json"


def _state(bot, human):
    s = graph.create_initial_state(URL)
    s.update(bot_crawl=bot, human_crawl=human, raw_html=human.get("dom_html", ""))
    return s


@pytest.mark.parametrize("pages,expected", [((CLEAN, CLEAN), "false"), ((CLEAN, MALICIOUS), "true"),
                                            ((MALICIOUS, CLEAN), "unknown")])
def test_model_output_never_changes_labels(pages, expected):
    bot, human = pair(record(pages[0]), browser(pages[1]))
    model = _SaysCloaking()
    with_model = analyze_cloaking_node(_state(bot, human), model)
    without = analyze_cloaking_node(_state(bot, human), None)
    broken = analyze_cloaking_node(_state(bot, human), _Broken())
    for s in (with_model, without, broken):
        assert s["cloaking_label"] == expected, s["cloaking_reason"]
        assert s["rule_cloaking_label"] == with_model["rule_cloaking_label"]
    assert with_model["llm_cloaking_assessment"] == "supports_cloaking"
    assert without["llm_cloaking_assessment"] == "unavailable"
    assert broken["llm_cloaking_assessment"] == "unavailable"
    assert any("[Node4] LLM error" in e for e in broken["errors"])
    # 模型只拿證據：提示詞裡沒有規則結果、標籤或閘門理由
    for leaked in ("rule_cloaking_label", "cloaking_label", "difference_not_replicated", "basis"):
        assert leaked not in model.prompts[0], leaked


def test_node4_fills_legacy_columns_and_tier():
    s = analyze_cloaking_node(_state(*pair(record(CLEAN), browser(MALICIOUS))), None)
    dual = s["dual_crawl_results"]
    assert s["cloaking_verified"] and s["cloaking_confidence_tier"] == "CONFIRMED"
    assert dual["rule_fired_raw"] and dual["fired_rules"] == ["C1"] and dual["dynamic_reliability"] == "HIGH"
    gated = analyze_cloaking_node(_state(*pair(record(CLEAN), browser(MALICIOUS),
                                               human2=browser(CLEAN))), None)
    assert gated["cloaking_confidence_tier"] == "SUSPECTED" and gated["cloaking_uncertainty"]


# ── 訊號表：每個訊號都有實際觀察值 ─────────────────────────────────
def test_signals_record_actual_evidence():
    bot, human = pair(record(CLEAN, request_headers={"User-Agent": "baseline-ua"}),
                      browser(MALICIOUS, request_headers={"user-agent": "browser-ua"}))
    signals = {s["id"]: s for s in compute_signals(bot, human)}
    ua = signals["client_type_response_difference"]
    assert ua["status"] == "observed"
    assert ua["evidence"]["user_agents"]["bot#1"] == "baseline-ua"
    assert ua["evidence"]["user_agents"]["human#1"] == "browser-ua"
    assert "mechanisms" in ua["evidence"]["pairs"][0]["differences"]
    assert signals["decoy_candidate"]["status"] == "observed"
    assert signals["repeat_instability"]["status"] == "not_observed"
    for variant in ("referer_presence_effect", "desktop_mobile_difference"):
        assert signals[variant]["status"] == "not_tested"
        assert signals[variant]["evidence"] == {"reason": "variant_disabled"}
    for signal in signals.values():
        assert {"id", "category", "status", "compared", "evidence"} <= set(signal)
        json.dumps(signal["evidence"])                      # 證據必須可寫進稽核 JSON
    observed, not_tested = summarize(list(signals.values()))
    assert "client_type_response_difference" in observed.split("|")
    assert set(not_tested.split("|")) == {"referer_presence_effect", "desktop_mobile_difference"}


def test_variant_signal_compares_against_stable_controls():
    bot, human = pair(record(CLEAN), browser(CLEAN))
    mobile = browser(MALICIOUS, variant="mobile")
    signals = {s["id"]: s for s in compute_signals(bot, human, variants={"mobile": mobile})}
    device = signals["desktop_mobile_difference"]
    assert device["status"] == "observed" and "mechanisms" in device["evidence"]["differs_from_all_controls"]
    assert device["evidence"]["replicated"] is False
    referer = {s["id"]: s for s in compute_signals(bot, human, variants={"referer": record(CLEAN)})}
    assert referer["referer_presence_effect"]["status"] == "not_observed"


def test_js_and_delay_signals():
    late = copy.deepcopy(browser(SHELL, dom=SHELL_RENDERED))
    late["dom_domcontentloaded_html"] = SHELL
    late["dom_snapshots"][0]["text_length"] = 0
    bot, human = pair(record(SHELL), late)
    signals = {s["id"]: s for s in compute_signals(bot, human)}
    assert signals["js_modified_dom"]["status"] == "observed"
    assert signals["js_modified_dom"]["evidence"]["human#1"]["mechanisms_added_by_js"]
    assert signals["delayed_content"]["status"] == "observed"
    # 可見文字沿用 v2 的切法（含 <title>，C1/C4 依賴它），所以有標題的外殼不算空白頁
    assert signals["blank_page"]["status"] == "not_observed"
    empty = "<html><body><div id=root></div></body></html>"
    blank = {s["id"]: s for s in compute_signals(*pair(record(empty), browser(empty)))}["blank_page"]
    assert blank["status"] == "observed" and blank["evidence"]["bot#1"]["document_text_empty"]
