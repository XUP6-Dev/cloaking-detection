"""靜態前端 cloaking 特徵（S1–S3）：前端 JS 裡寫死的「偵測環境 → 依結果改變內容」。

定位：不裁決 cloaking。命中 S1–S3 代表「頁面有能力只對特定 client 換內容」—— 我們的
headless 瀏覽器可能正被送進誘餌分支，所以兩種 client 看到相同內容也不能宣稱
「沒有 cloaking」：最終標籤降級為 unknown（見 analysis/cloaking.py）。

舊版是加權制（門檻 0.40，各類別 0.08~0.30），權重沒有資料依據，門檻得不斷上調來壓
誤報 —— 那是在跟 navigator.userAgent / document.referrer 這些合法網站到處都是的模式
賽跑。真正的問題是把統計性特徵和高特異性特徵混在同一個加總裡，所以改成布林連言：
  單獨偵測不是 cloaking —— anti-bot SDK、RWD、analytics、React DevTools hook 都在偵測環境。
  單獨跳轉也不是 cloaking —— SPA 路由、地區導向都會跳轉。

v2 的 S4（LLM 判定 + 高特異性佐證）只影響舊診斷欄 cloaking_tier，見 s4_applies()。
"""
import re

_CRAWLER_ARTIFACTS = {          # 爬蟲框架注入的專屬識別符（高特異性）
    "automation_detection", "headless_feature_check",
}
# 一般性環境偵測：記錄為證據，但「不參與裁決」。合法網站大量使用
# （RWD 用 screen.width、analytics 用 document.referrer、每個 React 站都有
#   __REACT_DEVTOOLS_GLOBAL_HOOK__、hover 效果用 mousemove），布林化只會把現代網站判成 cloaking。
_GENERIC_PROBES = {
    "user_agent_check", "referrer_check", "screen_size_gate",
    "ip_geo_check", "devtools_detection", "mouse_behavior_gate",
}
_COND_FINGERPRINT = {           # pattern 內部已含 bot 條件，本身就是連言
    "fingerprint_conditional",
}
_EVASION_ACTIONS = {            # 依偵測結果改變行為
    "javascript_redirect", "time_based_evasion",
}

# (id, [(分組, 最少命中類別數), ...], 說明)
STATIC_CLOAKING_RULES = [
    ("S1", [(_CRAWLER_ARTIFACTS, 1), (_EVASION_ACTIONS, 1)],
     "爬蟲框架洩漏識別符 + 差異化跳轉"),
    ("S2", [(_COND_FINGERPRINT, 1), (_EVASION_ACTIONS, 1)],
     "指紋條件分流 + 差異化跳轉"),
    ("S3", [(_CRAWLER_ARTIFACTS, 1), (_COND_FINGERPRINT, 1)],
     "爬蟲偵測 + 指紋條件分流（偵測到就換內容，不需跳轉）"),
]

# 「一般性環境偵測不參與裁決」用 import 時的檢查鎖住，不是靠註解提醒：
# 有人把 user_agent_check 加進 _CRAWLER_ARTIFACTS，每個用 RWD 的網站都會變成 cloaking。
assert not any(_GENERIC_PROBES & group
               for _, requirements, _ in STATIC_CLOAKING_RULES
               for group, _ in requirements), \
    "一般性環境偵測混進了布林裁決規則：" + str(
        {c for _, req, _ in STATIC_CLOAKING_RULES for g, _ in req for c in _GENERIC_PROBES & g})

_ALL_CATEGORIES = (_CRAWLER_ARTIFACTS | _GENERIC_PROBES
                   | _COND_FINGERPRINT | _EVASION_ACTIONS)

# Cloaking 技術特徵庫（來源：Cloak of Visibility, IEEE S&P 2016；
# devtools / headless / mouse 三類來自 Breaking the Shield, WWW 2025 與 CrawlPhish）
CLOAKING_SIGNATURES = {
    "user_agent_check": {"patterns": [
        r"navigator\.userAgent", r"userAgent\.indexOf", r"userAgent\.match",
        r"/googlebot/i", r"/bingbot/i", r"/crawler/i", r"/spider/i", r"bot.{0,50}test\s*\(",
    ]},
    "referrer_check": {"patterns": [
        r"document\.referrer", r"HTTP_REFERER", r"referer\.includes", r"referer\.match",
    ]},
    "automation_detection": {"patterns": [
        r"navigator\.webdriver", r"window\._phantom", r"window\.callPhantom", r"__selenium",
        r"__webdriver", r"navigator\.plugins\.length\s*===?\s*0", r"screen\.width\s*===?\s*0",
        r"screen\.height\s*===?\s*0", r"window\.outerWidth\s*===?\s*0",
        r"window\.outerHeight\s*===?\s*0", r"navigator\.languages\.length\s*===?\s*0",
        r"document\.__\$webdriverAsyncExecutor",
    ]},
    "fingerprint_conditional": {"patterns": [
        r"canvas.{0,50}if\s*\(", r"toDataURL.{0,50}===", r"getImageData.{0,50}compare",
        r"WebGL.{0,50}if\s*\(", r"knownBot.{0,50}fingerprint", r"fp.{0,50}===.{0,50}bot",
    ]},
    "javascript_redirect": {"patterns": [
        r"window\.location\s*=\s*['\"]http", r"location\.replace\s*\(\s*['\"]http",
        r"location\.href\s*=\s*['\"]http", r"document\.location\s*=",
    ]},
    "time_based_evasion": {"patterns": [
        r"setTimeout\s*\(.{0,100}location", r"setInterval\s*\(.{0,100}location",
        r"setTimeout\s*\(.{0,100}inject", r"delay.{0,50}redirect",
    ]},
    "screen_size_gate": {"patterns": [
        r"screen\.width\s*[<>]=?\s*\d+", r"screen\.height\s*[<>]=?\s*\d+",
        r"window\.innerWidth\s*[<>]=?\s*\d+", r"window\.innerHeight\s*[<>]=?\s*\d+",
    ]},
    "ip_geo_check": {"patterns": [
        r"geoip", r"ip2location", r"ip_address", r"remote_addr",
        r"cloudflare.{0,50}country", r"CF-IPCountry",
    ]},
    "devtools_detection": {"patterns": [
        r"devtools", r"firebug", r"__REACT_DEVTOOLS", r"window\.devtools",
        r"setInterval.{0,50}debugger",                     # 持續觸發 debugger 暫停 devtools
        r"toString.{0,50}length.{0,50}>.{0,50}devtools",   # devtools 開啟時 toString 長度不同
    ]},
    "headless_feature_check": {"patterns": [
        r"document\.documentElement\.webdriver", r"navigator\.brave", r"chrome\.app\.isInstalled",
        r"outerHeight\s*===?\s*0", r"outerWidth\s*===?\s*0",   # headless 下為 0
        r"window\.__nightmare",                               # Nightmare.js 標記
        r"window\.domAutomation",                             # Selenium 注入旗標
        r"window\.__cdc_",                                    # ChromeDriver 注入的全域變數
    ]},
    "mouse_behavior_gate": {"patterns": [
        r"addEventListener\s*\(\s*['\"]mousemove", r"onmousemove\s*=", r"mousemove.{0,50}show",
        r"mouse.{0,50}interaction.{0,50}require",
        r"window\.addEventListener.{0,100}mouse.{0,100}\{[^}]*redirect",
    ]},
}

_CLOAKING_RE = {tech: [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
                for tech, rule in CLOAKING_SIGNATURES.items()}

# 四個分類集合必須恰好蓋住特徵庫：多出來的名字 = 規則引用不存在的類別（永遠不成立）；
# 少掉的名字 = 新特徵沒分類，預設變成只記錄不裁決（靜默降級）。
assert _ALL_CATEGORIES == set(_CLOAKING_RE), (
    f"分類集合與 CLOAKING_SIGNATURES 對不上 —— "
    f"集合多出: {sorted(_ALL_CATEGORIES - set(_CLOAKING_RE))} / "
    f"未分類: {sorted(set(_CLOAKING_RE) - _ALL_CATEGORIES)}")


def static_detect(js_text, html):
    """回傳 (觸發的 S 規則 id 清單, {類別: 命中的 pattern, …, "static_rule": [說明]})。純規則。"""
    combined = (js_text or "") + "\n" + (html or "")
    techniques = {}
    for technique, compiled in _CLOAKING_RE.items():
        hits = [pattern.pattern for pattern in compiled if pattern.search(combined)]
        if hits:
            techniques[technique] = hits
    hit_categories = set(techniques)
    fired = []
    for rule_id, requirements, label in STATIC_CLOAKING_RULES:
        if all(len(group & hit_categories) >= n for group, n in requirements):
            fired.append(rule_id)
            techniques.setdefault("static_rule", []).append(f"[{rule_id}] {label}")
    return fired, techniques


def s4_applies(llm_supports, techniques, fired):
    """舊 S4：模型支持 cloaking、規則層沒有 S1–S3，但看到爬蟲框架洩漏或指紋條件分流。
    一般性偵測不算佐證，否則等於讓模型對任何現代網站單方面成立。只影響 cloaking_tier。"""
    return bool(llm_supports and not fired
                and set(techniques) & (_CRAWLER_ARTIFACTS | _COND_FINGERPRINT))
