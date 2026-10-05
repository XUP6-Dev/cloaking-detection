"""Client 設定（profile）。每個欄位都寫進觀察紀錄與 manifest —— 它們是實驗變因，
改任何一個都要改 schemas/versions.py 的 MEASUREMENT_VERSION。

兩種 client 的差異就是這次量測的「軸」：
  基準 HTTP  requests 直接 GET；UA 誠實宣告為自動化工具；不執行 JavaScript
  瀏覽器     Playwright 原生 headless Chromium；原生 UA；執行 JavaScript
兩者共用同一個直接出口（不用 proxy，IP 維度刻意不極化）、每次觀察都是全新 session
（無 cookie 延續）、預設不送 Referer、不做任何互動。

刻意不做：把 UA 偽裝成真人瀏覽器、指紋修補／stealth、TLS 模仿、session 預熱、
滑鼠模擬、點擊閘門、CAPTCHA 求解、提交表單或輸入任何資料。

可選變體（預設關閉，見 crawler/plan.py）：
  referer  基準 HTTP 加上 Referer = 目標自己的 origin。只測「有沒有 Referer」，
           不冒充郵件或搜尋引擎來源 —— 只放行特定來源的 Referer 白名單式 cloaking 測不到。
  mobile   瀏覽器改用行動版面（viewport / is_mobile / has_touch，都是 Playwright 標準
           context 選項），UA 維持原生，不宣稱自己是手機 —— 只依 UA 判斷裝置的 cloaking 測不到。
"""
import os
from dataclasses import asdict, dataclass

from feeds.urls import origin
from schemas.versions import MEASUREMENT_VERSION


@dataclass(frozen=True)
class BaselineProfile:
    profile_id: str = "baseline-http"
    version: str = MEASUREMENT_VERSION
    # 「Mozilla/5.0 (compatible; …)」是自動化程式自我宣告的慣用格式（Googlebot 也是）。
    # 固定字串而非 requests 預設值：python-requests/x.y 會隨套件升級改變，紀錄就不可重現。
    user_agent: str = "Mozilla/5.0 (compatible; DefensiveMeasurement/3.0; baseline-http)"
    referer_policy: str = "none"          # "none" | "self-origin"
    connect_timeout_s: float = 10.0
    read_timeout_s: float = 20.0
    max_redirects: int = 10
    max_body_bytes: int = 5_000_000
    max_analysis_chars: int = 2_000_000
    verify_tls: bool = True

    def headers(self, url):
        """除了 UA 與（變體的）Referer 之外沿用 requests 預設標頭；實際送出值逐跳記錄。"""
        headers = {"User-Agent": self.user_agent}
        if self.referer_policy == "self-origin":
            headers["Referer"] = origin(url) + "/"
        return headers

    def record(self):
        return {**asdict(self), "kind": "http_baseline", "client": "requests",
                "javascript_enabled": False, "cookies": "fresh_session_per_observation",
                "egress_policy": "shared_direct_no_proxy", "egress_verification": "not_measured",
                "interaction": "none"}


@dataclass(frozen=True)
class BrowserProfile:
    profile_id: str = "browser-desktop"
    version: str = MEASUREMENT_VERSION
    locale: str = "en-US"
    timezone_id: str = "UTC"
    javascript_enabled: bool = True
    width: int = 1280
    height: int = 720
    device_scale_factor: float = 1.0
    is_mobile: bool = False
    has_touch: bool = False
    navigation_timeout_ms: int = 20000
    load_timeout_ms: int = 10000          # 等 load 事件的上限；逾時不算失敗，記錄後繼續
    settle_ms: int = 2000                 # load 之後再等的時間，讓非同步內容出現
    max_requests: int = 200               # 單次觀察的請求上限（含導向每一跳）
    max_analysis_chars: int = 2_000_000
    max_external_scripts: int = 10        # 讀取內容的外部腳本數上限（只分析同主機的）
    max_script_bytes: int = 300_000

    def context_options(self):
        # 沒有 user_agent、extra_http_headers、proxy：全部維持 Chromium 原生值。
        return {"locale": self.locale, "timezone_id": self.timezone_id,
                "viewport": {"width": self.width, "height": self.height},
                "device_scale_factor": self.device_scale_factor,
                "is_mobile": self.is_mobile, "has_touch": self.has_touch,
                "java_script_enabled": self.javascript_enabled,
                "accept_downloads": False, "service_workers": "block",
                "ignore_https_errors": False}

    def record(self):
        return {**asdict(self), "kind": "browser", "client": "playwright-chromium",
                "context_options": self.context_options(),
                "launch": {"headless": True, "chromium_sandbox": True, "args": ["--no-proxy-server"]},
                "user_agent": "native_playwright_chromium", "cookies": "fresh_context_per_observation",
                "egress_policy": "shared_direct_no_proxy", "egress_verification": "not_measured",
                "interaction": "none", "dialogs": "dismissed", "popups": "closed",
                "permissions": "none_granted"}


BASELINE = BaselineProfile()
BROWSER = BrowserProfile()
VARIANT_PROFILES = {
    "referer": BaselineProfile(profile_id="baseline-http-self-referer", referer_policy="self-origin"),
    "mobile": BrowserProfile(profile_id="browser-mobile-layout", width=390, height=844,
                             device_scale_factor=3.0, is_mobile=True, has_touch=True),
}


def profile_for(is_human):
    """相容介面（v2）：human 槽 = 瀏覽器、bot 槽 = 基準 HTTP。

    v1 的 HUMAN_PROFILE（偽裝成特定地區真人）已退役；殘留設定明確報錯，
    避免舊 launch 設定被誤當成新版設定跑完整批。
    """
    if os.environ.get("HUMAN_PROFILE"):
        raise ValueError("legacy_HUMAN_PROFILE_retired_see_README_v3")
    return BROWSER if is_human else BASELINE
