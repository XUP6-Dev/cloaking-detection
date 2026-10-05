"""觀察紀錄（ObservationRecord）的欄位契約 —— crawler/ 產生，analysis/ 與 reporting/ 讀取。

兩種 client 的紀錄用**同一組欄位**描述伺服器回應，所以可以直接逐欄比較：
  kind="http_baseline"  requests 直接 GET，不執行 JavaScript
  kind="browser"        Playwright Chromium，執行 JavaScript

`html` 一律是「伺服器送來的主文件」（解碼後、JS 執行前）。瀏覽器另外有 `dom_*`
欄位保存 JS 執行後的 DOM。cloaking 比較只用 `html` 對 `html`：拿基準端的原始文件去比
瀏覽器渲染後的 DOM，會把「頁面靠 JS 渲染」誤讀成「伺服器對不同 client 給不同內容」。

所有頁面內容（HTML、JS、文字、標頭、對話框訊息）都是不可信資料，只被記錄與比對，
從不被當成指令或設定。
"""
from typing import Any, TypedDict


class ObservationRecord(TypedDict, total=False):
    # ── 身分、順序與時間 ─────────────────────────────────────────
    record_version: str          # = MEASUREMENT_VERSION
    record_id: str               # uuid；也是 observations/<record_id>/ 的目錄名
    kind: str                    # "http_baseline" | "browser"
    role: str                    # "bot" | "human"：歷史槽名，bot=基準 HTTP、human=瀏覽器
    replicate: int               # 1 = 主觀察、2 = 重複觀察（存在 confirmation）
    access_index: int            # 這個 URL 在本 run 的第幾次存取（1 起算）；量「存取次數」效應
    crawl_order: str             # 這一列實際的順序（bot_first / human_first）
    pair_mode: str               # bot_human / human_human / bot_bot（A/A 對照）
    variant: str                 # "" | "referer" | "mobile"
    profile_id: str
    profile: dict[str, Any]      # 完整 client 設定快照（可重現）
    client: dict[str, Any]       # {"name", "version"}：requests 或 chromium 的實際版本
    observed_at: str             # 這次觀察開始的 UTC 時間
    finished_at: str
    fetch_time_sec: float

    # ── 伺服器回應：兩種 client 共用，可逐欄比較 ─────────────────
    request_headers: dict[str, str]        # 第一跳實際送出的請求標頭
    status_code: int                        # 主文件最後一跳的 HTTP 狀態；0 = 沒收到回應
    final_url: str                          # HTTP 導向結束的 URL（不含前端導向）
    redirect_chain: list[str]               # 伺服器 3xx 導向鏈
    navigation_responses: list[dict]        # 每一跳 {url, status, headers, observed_at, request}
    response_headers: dict[str, str]        # 最後一跳的回應標頭
    content_type: str
    charset: str                            # 解碼用的字元集與其來源
    html: str                               # 主文件內容（解碼後；瀏覽器 = JS 執行前）
    html_length: int
    html_sha256: str                        # 解碼後文字的雜湊
    body_sha256: str                        # 收到的原始位元組的雜湊
    truncated: bool                         # 超過分析上限而截斷
    text_content: str                       # html 的可見文字（去 script/style/noscript）
    title: str
    scripts: dict[str, Any]                 # {"inline": [{sha256, length}], "external": [url]}

    # ── 瀏覽器專屬：JS 執行後 ────────────────────────────────────
    dom_html: str                           # 等待載入與 settle 後的 DOM
    dom_text: str
    dom_title: str
    dom_sha256: str
    dom_length: int
    dom_truncated: bool
    dom_snapshots: list[dict]               # [{at, sha256, html_length, text_length}] 量延遲載入
    dom_domcontentloaded_html: str          # 第一個快照的 DOM（稽核時只留雜湊與檔案）
    page_url: str                           # settle 後主框架所在 URL（含前端導向）
    client_navigations: list[dict]          # 主文件之後的前端導向（meta refresh / JS）
    subresources: list[dict]                # {url, type, method, status}
    external_scripts: list[dict]            # {url, sha256, length, first_party, content?}
    console_errors: list[str]
    page_errors: list[str]
    failed_requests: list[dict]             # {url, type, method, failure, content_affecting}
    blocked_requests: list[dict]            # {url, type, method, reason, content_affecting}
    dialogs: list[dict]                     # 自動關閉的 alert/confirm/prompt（訊息為不可信文字）
    downloads: list[str]                    # 被拒絕的下載
    popups: list[str]                       # 被關閉的新視窗
    browser_version: str
    playwright_version: str
    screenshot_path: str                    # 既有的截圖保存（未新增影像分析）
    screenshot_sha256: str

    # ── 結果 ─────────────────────────────────────────────────────
    error: str | None                       # 沒收到回應時的錯誤
    error_kind: str                         # timeout / dns / tls / connection_reset / ...
    observation_issues: list[str]           # 見 crawler/records.py 的分級
    artifacts: dict[str, str]               # {raw_html, dom_html, screenshot, record}: 檔案路徑
    confirmation: "ObservationRecord"       # 同一槽的第二次觀察（replicate=2）
