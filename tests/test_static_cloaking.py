"""前端 JS cloaking 特徵 S1–S3（analysis/static_cloaking.py）。

定義：偵測環境 → 依結果改變使用者看到的東西。兩半都不能單獨成立，所以每條規則都是連言。
命中只會讓 cloaking「不能判 false」，不會判 true（見 test_cloaking_labels.py）。
"""
from analysis.static_cloaking import s4_applies, static_detect


def _detect(js="", html=""):
    fired, techniques = static_detect(js, html)
    return bool(fired), techniques


def test_crawler_artifact_plus_redirect():
    """S1：爬蟲框架洩漏識別符 + 差異化跳轉"""
    detected, techs = _detect("""
        if (window.__cdc_ || window._phantom || navigator.webdriver) {
            location.href = 'https://benign-decoy.example/';
        }
    """)
    assert detected and any("[S1]" in t for t in techs.get("static_rule", [])), techs


def test_detection_alone_is_not_cloaking():
    """反例：只有 bot 偵測沒有差異化行動 —— anti-bot SDK 就長這樣"""
    detected, techs = _detect("""
        var isBot = navigator.webdriver || window._phantom || window.__cdc_;
        telemetry.push({bot: isBot});
    """)
    assert not detected, techs.get("static_rule")


def test_redirect_alone_is_not_cloaking():
    detected, techs = _detect("location.href = 'https://www.example.com/welcome';")
    assert not detected, techs.get("static_rule")


def test_modern_spa_is_not_cloaking():
    """一般的現代 React 站：DevTools hook + RWD + referrer 追蹤 + 外部連結跳轉。
    四個類別命中，舊加權版會累積過門檻，布林版不裁決。"""
    detected, techs = _detect("""
        if (typeof __REACT_DEVTOOLS_GLOBAL_HOOK__ !== 'undefined') { hook(); }
        if (screen.width < 768) { mobileLayout(); }
        document.referrer && track(document.referrer);
        if (navigator.userAgent.indexOf('Safari') > -1) { polyfill(); }
        location.href = 'https://docs.example.com/guide';
    """)
    assert len(techs) >= 4, list(techs)
    assert not detected, techs.get("static_rule")


def test_generic_probes_never_decide():
    detected, techs = _detect("""
        if (screen.width < 768) { location.href = 'https://m.example.com/'; }
        if (document.referrer.includes('google')) { track(); }
        if (navigator.userAgent.match(/bot/i)) { flag(); }
        geoip.lookup(remote_addr);
    """)
    assert not detected, techs.get("static_rule")


def test_fingerprint_conditional_plus_redirect():
    """S2：指紋條件分流 + 跳轉"""
    detected, techs = _detect("""
        var fp = getCanvasFp();
        if (knownBot(fp) && fingerprint.match(fp)) { location.replace('http://decoy/'); }
    """)
    assert detected and any("[S2]" in t for t in techs.get("static_rule", [])), techs


def test_clean_page():
    detected, techs = _detect("console.log('hello'); document.querySelector('.btn');")
    assert not detected and not techs.get("static_rule"), techs


def test_s4_needs_high_specificity_corroboration():
    """舊 S4 只影響 cloaking_tier：模型支持 + 規則層看到爬蟲框架洩漏才成立，一般性偵測不算。"""
    _, generic = _detect("if (screen.width < 768) { location.href='https://m.example.com/'; }")
    _, artifact = _detect("var a = navigator.webdriver;")
    assert not s4_applies(True, generic, [])
    assert s4_applies(True, artifact, [])
    assert not s4_applies(False, artifact, [])
