# 防禦性釣魚 / Cloaking 量測 — v3（dual-observation）

這是一台**量測儀器**：對來自威脅情資清單的 URL，用兩種 client 觀察同一個網址，輸出兩個獨立的
判定 —— 這頁是不是釣魚頁（`phishing_verdict`）、伺服器有沒有依 client 類型遞送不同的惡意內容
（`cloaking_label`）—— 並保存每個判定的依據、證據來源、執行設定與不確定原因。

- 每個預設值都是實驗變因。改了任何一個，改動前後的批次就不能合併統計
  （`measurement_version` 會不同，`evaluate.py` 會拒絕合併）。
- 本版不是 PhishParrot 的重現，也不使用它的分類器（見〈PhishParrot 核對〉）。
- v2 → v3 的完整搬移表與語意變更見 [docs/migration_v3.md](docs/migration_v3.md)；
  v2 的設計紀錄見 [docs/research_v2.md](docs/research_v2.md)，v1 見 [docs/README.v1.md](docs/README.v1.md)。

## 目錄結構

```
cli.py              命令列入口（fetch-feed / run / evaluate / check）與批次流程（Run 物件）
graph.py            流程組裝：LangGraph 拓撲與條件路由
main.py             相容入口（v2）：python main.py … = python cli.py run …
fetch_feed.py       相容入口（v2）：python fetch_feed.py … = python cli.py fetch-feed …
evaluate.py         批次統計（cohort 分布、規則→最終、unknown 理由、訊號）
annotate.py         盲標檢視頁；score_annotations.py：盲標 precision 與 κ
build_urls.py       MUD 資料集挑選工具；threat_intel.py：外部信譽查詢（不在管線內）
setup_playwright.py 安裝並驗證與 .venv 相符的 Chromium

feeds/        feed 匯入：URL 保守正規化、不可變批次快照、PhishHunt 介面
crawler/      觀察：client 設定、請求邊界、基準 HTTP、Playwright、觀察計畫、紀錄格式
analysis/     判定：φ（page_mechanisms）、去混淆、釣魚、前端特徵、cloaking 規則與閘門、訊號表
llm/          本機 Ollama provider、提示詞（含版本）、輸出契約與嚴格驗證
schemas/      版本常數、狀態與紀錄的欄位契約、標籤值域
reporting/    CSV 欄位與唯一投影、稽核 JSON、manifest、盲標配對、主控台摘要
nodes/        六個管線節點（薄轉接：讀 state → 呼叫上面的模組 → 寫 state）
tests/        全部測試（不連外：只用合成 HTML 與本機 loopback 伺服器）
docs/         遷移紀錄、v2 研究紀錄、歷史 README、10/04 實驗 notebook
```

產生的資料（皆不進版本控制）：`feed_batches/`（不可變清單快照）、`observations/<record_id>/`
（每次觀察的證據檔：`raw.html`、`dom.html`、`dom_domcontentloaded.html`、`screenshot.png`、`record.json`）、
`audit_records/<run_id>/`（逐列稽核 JSON，大型內容以上述證據檔的路徑＋SHA-256 引用）、`csv_reports/`
（CSV 與 manifest）、`results/`（逐列文字報告）、`pairs/`（盲標配對，選用）。每個 URL 有 4 次觀察，
證據檔約數 MB；300 筆的批次預留 1–2 GB。

## 資料流程

```
PhishHunt feed.txt ──fetch-feed──▶ feed_batches/<batch_id>/  (feed.txt 原始位元組、records.json、
                                    rejected.json、urls.txt、manifest.json：來源、取得時間、雜湊)
                                          │  run --batch（讀取前驗證雜湊；整批共用一份設定快照）
                                          ▼
每個 URL（graph.py）：
 node0 驗證網址 ─ 無效 ─────────────────────────────────────────────────▶ node5
 node1 觀察計畫（crawler/plan.py）：B1 → H1 → B2 → H2（先後依 URL 的 SHA-1 決定）
        B = 基準 HTTP（requests，不執行 JS）   H = Playwright Chromium（執行 JS）
        ＋可選變體（referer / mobile）各一次 ─ 沒有可判讀的頁面 ──────────▶ node5
 node2 JS 去混淆（判定用頁面的內嵌腳本＋瀏覽器載入的同主機腳本）
 node3 釣魚判定：φ(瀏覽器 DOM + 去混淆 JS) → 規則結果 → 觀察完整性 → 最終判定；模型說明另存
 node4 cloaking：前端特徵 S1–S3 → 訊號表 → C1–C5（B1↔H1、B2↔H2 主文件）→ 閘門 → 三態標籤；
       標籤定案後才請模型解讀差異證據（另存）
 node5 稽核 JSON（大型內容以證據檔＋SHA-256 引用）→ summary CSV 附加一列 → 文字報告
                                          │
                                          ▼
csv_reports/run_<時間>_<run_id>.json（manifest）、cloaking_report_<時間>.csv（逐列附加）、
batch_results_<時間>.csv（整批，含診斷欄）、audit_records/…、observations/…
```

## 安裝與執行

一律使用專案 `.venv`（系統 Python 與 Playwright 的瀏覽器快取版本可能不符）：

```powershell
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe setup_playwright.py
.venv\Scripts\python.exe cli.py check                      # 本機 Chromium 與 Ollama 狀態（不連外）
.venv\Scripts\python.exe cli.py fetch-feed 300             # 只下載清單，不造訪其中 URL
.venv\Scripts\python.exe cli.py run --batch feed_batches/<batch_id>
.venv\Scripts\python.exe cli.py evaluate csv_reports/batch_results_<時間>.csv
```

- 清單抓完立刻跑，別隔夜：釣魚站存活期以小時計，過期清單會把「站死了」混進結果。
- 設定走 `.vscode/launch.json` 的 config（主批、純規則、A/A 對照、只匯入、環境檢查），
  **不要在 PowerShell 下 `$env:`**：變數會留在整個 session，下一批沿用且毫無提示。
  某個 CSV 是哪種設定跑的，以 `csv_reports/run_*.json` 為準（含 `run_config_sha256`，與每一列相同）。
- `--input FILE` 可離線匯入存檔的清單；`source` 會記成該檔的 file URI，不謊稱是當日 feed。
- `--limit N` 只跑前 N 筆（冒煙測試用）；`--url URL` 跑單一網址（來源標記為 unlabeled）。

| 環境變數（旋鈕） | 預設 | 意義 |
|---|---|---|
| `CRAWL_SCOPE` | `passive` | 請求邊界：`passive`（只允許公網位址）/ `local_test`（只允許 loopback 同 origin）/ `authorized_test`（`AUTHORIZED_TEST_ORIGINS` + `TEST_AUTHORIZATION`） |
| `PAIR_MODE` | `bot_human` | 兩槽的 client：`bot_human`（主批）/ `human_human`、`bot_bot`（A/A 噪音底線） |
| `CRAWL_ORDER` | `split` | 依 URL 的 SHA-1 逐筆決定誰先；`bot_first` / `human_first` 為強制覆寫 |
| `OBSERVATION_VARIANTS` | 空 | `referer`、`mobile`（逗號分隔），各加一次觀察 |
| `SAVE_PAIR_HTML` | `0` | `1` = 寫出盲標配對 `pairs/` |
| `EGRESS_LABEL` | 空（launch.json 每次執行時詢問） | 出口網路的自報標籤，寫進 manifest 的 `egress`（旁附本機 Wi-Fi SSID）；**不進** `run_config_sha256`，比較不同網路的批次時要自己看這一欄 |
| `LLM_PROVIDER` 等 | 見下節 | |

## 本機 Ollama：設定與降級

模型只做三件事：還原混淆 JS 的參考版本、對釣魚頁面的說明、對兩種 client 差異證據的解讀。
**三者都不進入任何規則結果或最終標籤**；模型拿到的是證據（頁面文字、結構摘要、訊號表），
拿不到規則結果或標籤，所以它的意見是獨立的第二意見，可用來排序人工複核。

```json
"env": {
  "LLM_PROVIDER": "ollama",
  "LLM_MODEL": "qwen3.5:9b",
  "OLLAMA_BASE_URL": "http://127.0.0.1:11434",
  "OLLAMA_TIMEOUT": "60",
  "OLLAMA_RETRIES": "1",
  "OLLAMA_NUM_CTX": "8192"
}
```

| 變數 | 規則 |
|---|---|
| `LLM_PROVIDER` | `ollama` 或 `none`。v2 的雲端／LM Studio provider 已移除；設成那些值會**停用模型並記錄原因**，不會改用別的 provider |
| `OLLAMA_BASE_URL` | 只接受 loopback 的 `http://` origin（127.0.0.1 / localhost / ::1） |
| `LLM_MODEL` | 本機已安裝的模型；名稱含 `cloud` 一律拒絕；不會自動下載 |
| `OLLAMA_TIMEOUT` / `OLLAMA_RETRIES` | 每次 HTTP 請求秒數（0–600）／額外重試次數（0–3） |
| `OLLAMA_NUM_CTX` | 明確設定 context 長度，避免 Ollama 預設值靜默截掉長提示詞 |

- 呼叫方式：Ollama 原生 `/api/chat`、非串流、`format` = JSON Schema、`temperature 0`、`seed 0`、
  `think: false`，不讀環境 proxy、不跟隨導向。
- 每次呼叫的稽核紀錄：模型名稱、digest、Ollama 版本、參數、`prompt_version`、提示詞與模板的
  SHA-256、原始回應、驗證狀態、失敗原因。manifest 另記所有模板的雜湊。
- 驗證：完整 JSON 才接受（不截取大括號、拒絕重複鍵、NaN、多餘欄位、錯型別、enum 以外的值）。
- **降級**：模型停用、連不上、逾時、回傳格式錯誤 → 該欄記 `unavailable`（原因在稽核 JSON），
  規則結果與最終標籤**完全不變**；模型判斷證據不足時回 `insufficient_evidence`。
  沒有任何可用觀察時不呼叫模型，記 `not_run`。不會因為模型掛掉或說了什麼而產生確定標籤。
- 2026-10-05 本機實測：Ollama 0.34.4、`qwen3.5:9b` 已安裝（digest `6488c96f…`），但推論回 HTTP 500
  「llama-server binary not found」—— 這台機器的 Ollama 安裝不完整，需重新安裝 Ollama 才會有模型
  說明；在那之前管線以純規則照跑，`llm_*` 欄位為 `unavailable`。

## 觀察：兩種 client

| | 基準 HTTP（bot 槽） | Playwright 瀏覽器（human 槽） |
|---|---|---|
| client | requests（版本記錄於紀錄） | 原生 headless Chromium（Playwright 1.63；版本記錄於紀錄） |
| User-Agent | 誠實宣告：`Mozilla/5.0 (compatible; DefensiveMeasurement/3.0; baseline-http)` | 原生（例如 `HeadlessChrome/…`），不覆寫 |
| JavaScript | 不執行 | 執行；等 DOMContentLoaded → load（≤10 s）→ settle 2 s |
| 保存 | 每一跳的請求／回應標頭與狀態、導向鏈、主文件（解碼後＋原始位元組雜湊）、可見文字、標題、內嵌腳本雜湊、外部腳本網址 | 同左（主文件取自導覽回應，JS 執行前）＋ JS 執行後 DOM（兩個快照）、前端導向、子資源、同主機外部腳本內容、主控台錯誤、頁面例外、失敗／被擋請求、對話框、下載、新視窗、截圖（既有功能，未新增影像分析） |
| 共同條件 | 同一出口（不用 proxy，IP 刻意不極化）、每次觀察全新 session（無 cookie 延續）、不送 Referer、驗證 TLS、不互動 | |

**觀察計畫**：交錯四次 `B1 → H1 → B2 → H2`（或 `H1 → B1 → H2 → B2`）。兩側各有一次在對方之前、
一次在對方之後，頁面更新、短暫故障或「只給第一次存取真內容」會表現成同側兩次不一致，而不是被誤讀成
兩種 client 的差異。每筆紀錄帶 `access_index`、`replicate`、`crawl_order` 與時間戳。

**可選變體**（`OBSERVATION_VARIANTS`，排在四次觀察之後，各一次、不重複）：

- `referer`：基準 HTTP 加 `Referer: <目標自己的 origin>/`。只測「有沒有 Referer」，不冒充郵件或搜尋引擎。
- `mobile`：瀏覽器改用行動版面（390×844、`is_mobile`、`has_touch`，都是 Playwright 標準 context 選項），
  UA 維持原生，不宣稱自己是手機。

**安全邊界**（是控制，不是規避）：只放行 GET/HEAD；websocket、eventsource、beacon 一律擋；子框架導覽擋；
每一跳（含 HTTP 導向，透過 Chromium request-stage 攔截）送出前檢查範圍；`passive` 只允許公網位址
（擋 loopback 與私有網段）；單次觀察 ≤200 個請求；拒絕下載、關閉新視窗、自動關閉對話框、不授予任何
權限；不點擊、不輸入、不捲動、不提交；不解 CAPTCHA。非 HTML 的回應（壓縮檔、執行檔…）不讀內容也不存檔。
不使用 stealth、指紋修補、UA 偽裝、TLS 模仿或 session 預熱。頁面內容、HTTP 回應、feed 文字與模型輸出
一律是不可信資料：只被記錄與比對，從不被當成設定或指令。

## 標籤定義

每個判定分三層保存，互不覆寫：**規則結果**（`rule_*`，閘門前）、**模型分析**（`llm_*`，只作說明）、
**最終標籤**。`source_label`（例如 `phishunt_suspicious`）是來源清單的標記 —— 威脅情資，不是人工真值，
也不參與任何判定。

### 釣魚：`phishing_verdict`

本專案自行定義（PhishParrot 沒有提供可沿用的分類規則）：

- 判定用頁面：瀏覽器 JS 執行後的 DOM（攻擊面是使用者看到的頁面）＋去混淆後的 JS。瀏覽器的兩次觀察都
  沒有文件時，退回基準 HTTP 的原始文件並加註 `analysis_without_js_execution`。實際來源在 `evidence_sources`。
- 規則結果 `rule_phishing_verdict`：φ（`analysis/page_mechanisms.py`，Layer 1 布林裁決 + Layer 2 累加，
  閾值 0.45）＋高混淆腳本加權 → `phishing` / `not_detected`；沒有可判讀文件時 `not_run`。
  依據寫在 `phishing_basis`（`layer1:D1,D3` 或 `layer2_score=0.52>=0.45`）。
- 最終：
  - `phishing`：規則陽性。看到的證據就是證據；觀察不完整只列入 `uncertainty_reasons.phishing`。
  - `not_detected`：規則陰性**且**觀察完整。不是「證明安全」。
  - `unknown`：沒有文件（`missing_observation`、`crawl_error`、`empty_document`、`non_html_document`），
    或規則陰性但觀察不完整（挑戰頁、互動閘門、截斷、內容類請求被擋或失敗、空白頁、非 2xx、
    對話框／下載／新視窗、未執行 JS）。

### Cloaking：`cloaking_label`

本專案的定義：**同一個 URL、同一個出口、同一段時間內，伺服器依 client 類型（非瀏覽器 HTTP client ↔
執行 JS 的瀏覽器）遞送不同內容，差異涉及 φ 認得的惡意機制，並在兩組交錯觀察中重現。**

- 比較的是兩種 client 收到的**伺服器主文件**（同一層）。拿原始文件去比渲染後 DOM，會把
  「頁面靠 JS 渲染」誤讀成差別遞送。
- 規則結果 `rule_cloaking_label`：主配對（B1↔H1）跑 C1–C5（`analysis/cloaking.decide_cloaking`，
  自 v1 原樣保留）：
  C1 兩邊都拿到頁面但瀏覽器多出惡意機制；C2 基準端 403/404/503 而瀏覽器 200 且含高特異性機制；
  C3 協議層中斷（只在兩槽都是瀏覽器時可能）；C4 基準端空頁而瀏覽器含高特異性機制；
  C5 導向分叉且只有瀏覽器落在含機制的頁面。瀏覽器沒有文件或基準端沒有回應 → `unknown`。
- 最終 `cloaking_label`（`analysis/cloaking.label_cloaking`，全布林、無閾值、不收 llm 參數）：
  - `true`：規則陽性，且重複配對（B2↔H2）觸發相同規則、隱藏的機制集合相同；瀏覽器兩次都是完整、
    非挑戰頁的 2xx 文件；基準端兩次都有回應（403／空頁／挑戰頁正是 C2/C4 的證據）；沒有反向差；
    隱藏的機制含高特異性機制。
  - `false`：兩組配對都沒有規則觸發；四次都是完整、可讀、非挑戰、無互動閘門的 2xx 文件；同側兩次的
    狀態／最終主機／機制一致；兩側之間沒有「系統性差異」（同側穩定、兩側不同）的狀態、主機、機制、
    標題、表單主機、腳本主機或文件雜湊；沒有只在 JS 執行後才出現的機制；沒有前端 cloaking 程式碼
    （S1–S3）；變體沒有出現差異；沒有反向差。它的意思是「**在本次兩種 client、同出口、無 Referer、
    桌面版面的條件下未觀察到**」，不是「這個網站沒有 cloaking」。
  - `unknown`：其餘全部，閘門理由逐條寫在 `uncertainty_reasons.cloaking` 與稽核 JSON。
- `llm_cloaking_assessment`：標籤定案後，模型只拿差異證據（觀察摘要＋訊號表）判讀，回
  `supports_cloaking` / `does_not_support_cloaking` / `insufficient_evidence`；停用或失敗為
  `unavailable`。它只影響舊診斷欄 `cloaking_tier` 的 S4，不影響標籤。

單一欄位或單次差異不得證明 cloaking。替代解釋與對應的閘門：

| 替代解釋 | 處理方式 | 典型理由代碼 |
|---|---|---|
| 頁面更新 | 交錯觀察；同側兩次不一致 → unknown | `bot_unstable_status`、`human_unstable_mechanisms` |
| 短暫故障 | 四次觀察都要可用；任一次錯誤或非 2xx → 不能判 false | `bot#2:crawl_error`、`human#1:http_error_status` |
| A/B 測試、隨機內容 | 差異必須在第二組配對重現 | `difference_not_replicated` |
| 非同步載入、JS 渲染 | 比伺服器主文件；JS 執行後才出現的機制擋 false；DOMContentLoaded／settle 兩個快照記錄延遲 | `human#1:js_rendered_mechanisms_not_compared` |
| 存取順序、只給第一次 | SHA-1 順序切分＋交錯；反向差擋任何確定標籤；`first_access_only` 訊號 | `reverse_difference_or_order_effect` |
| 反爬蟲／WAF | C2–C4 需要瀏覽器端的高特異性機制；被擋但沒比到內容 → unknown（不是 false） | `bot#1:http_error_status` |
| 每次請求不同的 token | 只比離散特徵；同側也會變的特徵不算系統性差異 | — |
| φ 認不出的差異 | 兩側穩定地拿到不同頁面但機制相同 → unknown | `systematic_title_difference_without_mechanism_evidence` |
| 前端偵測自動化後換內容 | 兩種 client 都是自動化，看到相同不代表沒有；S1–S3 命中擋 false | `frontend_cloaking_code_present:S1` |
| 互動閘門、CAPTCHA | 不跨越；任一側擋 false；瀏覽器端挑戰頁擋 true | `human#1:challenge_or_block_page` |

## Cloaking 訊號

`analysis/signals.py` 對每個 URL 產生一張訊號表（存在稽核 JSON 的 `signals`；CSV 的 `cloaking_signals`
列出 `observed` 的 id、`cloaking_signals_not_tested` 列出本次沒做的）。每個訊號都保存實際觀察值。
`status`：`observed`（有差異或現象）、`not_observed`（比較了，沒有）、`not_tested`（本次設定沒做這種
觀察 —— 不是「沒有」）、`unmeasurable`（該做的觀察失敗）。**訊號本身不裁決**，標籤只由上一節的規則與閘門決定。

| 類別（對應參考文章的觀察方向） | 訊號 id | 保存的證據 |
|---|---|---|
| User-Agent／瀏覽器類型 | `client_type_response_difference` | 兩側實際送出的 UA、每組配對逐欄差異（狀態、最終主機、標題、機制、表單／腳本主機、文件與文字雜湊）、文字相似度（描述用）、結構分歧、系統性差異 |
| Referer 有無 | `referer_presence_effect` | 送出的 Referer、變體與兩個對照的導向鏈與差異、只計「與所有對照都不同且對照彼此一致」的特徵；變體未開時 `not_tested` |
| 桌面／行動 | `desktop_mobile_difference` | 同上，比 DOM（版面變體） |
| HTTP 狀態 | `http_status_difference` | 四次觀察的狀態碼 |
| 頁面文字 | `visible_text_difference` | 文字長度、相似度、摘錄、是否系統性 |
| DOM／JS 行為 | `js_modified_dom` | JS 新增／移除的機制、主文件與 DOM 的文字長度與標題 |
| JS 內容 | `script_inventory_difference` | 兩側內嵌腳本雜湊、外部腳本網址的差集 |
| 前端 cloaking 程式碼 | `frontend_cloaking_code` | S1–S3 命中、一般性偵測類別與 pattern |
| 錯誤訊息 | `browser_errors` | 主控台錯誤數、頁面例外、失敗／被擋請求（含是否影響內容）、對話框、下載、新視窗、load 逾時、基準端錯誤類別 |
| 多段導向 | `multi_hop_redirect` | 每次觀察的導向鏈、跳數、跨主機 |
| 前端導向 | `client_side_redirect` | 主文件 URL、settle 後 URL、前端導覽清單 |
| 延遲載入 | `delayed_content` | 兩個 DOM 快照的雜湊與長度、DOMContentLoaded 之後才出現的機制 |
| 空白頁 | `blank_page` | 主文件／DOM 可見文字是否為空、長度 |
| 錯誤頁 | `error_page` | 非 2xx 狀態、像錯誤頁的標題 |
| 看似正常的替代頁 | `decoy_candidate` | 一側可讀 2xx 且零機制、另一側有機制的配對 |
| 重複觀察內容 | `repeat_instability` | 同側兩次的逐欄差異、每次存取的時間、耗時與間隔 |
| 存取次數 | `first_access_only` | 只出現在第一次存取的機制或狀態 |

## 輸出欄位

兩份 CSV 都由 `reporting/rows.result_row()` 這一個投影產生（v2 有兩條投影，曾經不一致）。
新欄位一律附加在既有欄位之後；**讀取請按欄名**。

| 欄位 | 意義 |
|---|---|
| `url, alive, is_phishing, cloaking` | 舊四欄（`cloaking_report_*.csv` 的前四欄）。`alive`：True=收到 HTTP 回應、False=網址無效、空白=無法觀察（不代表站已失效）。`is_phishing` / `cloaking`：True / False / N/A |
| `source_label`, `source`, `source_fetched_at`, `batch_id`, `raw_url`, `normalized_url` | 逐列來源（不是真值）；`label` 是舊分母欄的投影（只在 batch_results） |
| `phishing_verdict` / `rule_phishing_verdict` / `llm_phishing_assessment` | 最終／規則／模型 |
| `cloaking_label` / `rule_cloaking_label` / `llm_cloaking_assessment` | 最終／規則／模型 |
| `phishing_basis`, `cloaking_basis` | 判定依據（觸發的規則與數值） |
| `uncertainty_reasons` | JSON：`{"phishing": [...], "cloaking": [...]}`，unknown 的原因與陽性判定的觀察缺口 |
| `evidence`, `evidence_sources` | 稽核 JSON 路徑與 SHA-256；判定用頁面來源（例如 `human#1:dom`）與參與比較的觀察 |
| `cloaking_signals`, `cloaking_signals_not_tested` | observed／未測的訊號 id |
| `observation_plan`, `run_config_sha256`, `profile_id`, `crawl_order`, `pair_mode` | 本列實際的觀察順序與設定（對應 manifest） |
| `llm_model`, `prompt_version` | 模型與提示詞版本（完整參數在 manifest 與稽核 JSON） |
| `schema_version`, `measurement_version`, `run_id`, `observed_at`, `reason` | 版本、執行 ID、判定完成時間、舊的理由欄 |
| `batch_results` 的診斷欄 | `bot_*` = 基準 HTTP 主觀察、`human_*` = 瀏覽器主觀察；`rule_fired_raw`、`cloaking_fired`、`hidden_from_bot`、`reverse_diff` 等同 v2 |

`pairs/<hash>/meta.json`（盲標）只有 `url, bot_status, human_status, fetch_time, crawl_order, pair_mode`：
不含任何判定，也不含 `label` / `source_label`（先驗會讓 κ 與 precision 虛高；有測試鎖住）。

## PhishParrot 核對

依論文原文核對（Nakano, Koide, Chiba, *PhishParrot: LLM-Driven Adaptive Crawling to Unveil Cloaked
Phishing Sites*, IEEE GLOBECOM 2025, [arXiv:2508.02035](https://arxiv.org/abs/2508.02035)）：

- **它是爬蟲環境最佳化系統，不是釣魚分類器。** 四個階段：收集爬取資訊（Table I：網域／註冊商／DNS／
  TLS 憑證、HTTP 請求與回應、HTML 可見文字與 DOM 結構、IP 地理位置／ASN／瀏覽器語言）→ 以
  text-embedding-3-small 檢索相似案例（cosine ≥ 0.65、MMR λ = 0.7，成功／失敗各 5 例）→ LLM 產生
  最佳使用者 profile（17 種 OS×瀏覽器的 HTTP 標頭、IP 位置、資料中心／住宅／行動網路）→ Playwright 存取。
- **標籤**：「成功爬取／失敗爬取」由三位資安工程師一致同意標註；釣魚與否交給下游偵測器
  （ChatPhishDetector、VisualPhishnet、StackModel），評估真值取 VirusTotal ≥ 5 個引擎。
  URL 來自 CrowdCanary、urlscan.io 與 PhishTank。論文**沒有釋出可直接沿用的分類標籤、規則或 schema**，
  也沒有設定或變化 Referer —— 因此本專案的釣魚判定（φ）與 cloaking 定義都是自行定義，不宣稱與其等價。
- **採用**：結構化的觀察紀錄（HTTP 請求／回應、HTML 文字與結構、環境設定逐筆保存）；
  「爬取是否成功」與「網站是否惡意」分開記錄（本專案的觀察問題分級與 unknown）。
- **不採用**：住宅／行動網路與地理分流（本次不處理網路來源與代理）；17 種 OS×瀏覽器 UA 偽裝與受害者
  profile 最佳化（違反不偽裝的限制）；讓 LLM 選擇爬取設定（爬取設定只能來自啟動程序）；雲端 embedding；
  以第三方信譽或 feed 當真值。

參考文章（NoSpamProxy〈How cloaking disguises phishing attacks〉、SpoofGuard〈User-Agent cloaking in
phishing websites〉）只取其中的**觀察方向**（UA／瀏覽器類型、Referer、裝置、狀態與錯誤頁、空白／替代頁、
多段導向、時間與存取次數），對應到上表的訊號；文章中的規避或隱匿操作不實作。文章建議的住宅 IP、多地區
觀察不在本次範圍。

## 已知盲點、限制與誤判來源

**看得見與看不見的手法**：

| 手法 | 本架構 | 原因 |
|---|---|---|
| 伺服器依 UA／client 類型分流（非瀏覽器 vs 瀏覽器） | ✔ 可判 true | 主要對比 |
| 前端 JS 偵測自動化後換內容 | △ 只能擋 false | 兩種 client 都是自動化；只有 S1–S3 看得到程式碼 |
| 伺服器偵測 headless／TLS 指紋，對兩種 client 都給誘餌 | ✘（兩邊一致 → 可能判 false） | 沒有「像真人」的一側，這是不偽裝的代價 |
| IP、地理、ASN、住宅網路分流 | ✘ | 同出口、不改網路來源 |
| Referer 白名單（只放行郵件／搜尋來源） | ✘（只能選測「有無」） | 不冒充第三方來源 |
| 依 UA 判斷行動裝置 | ✘（只能選測版面） | 不改 UA |
| 時間窗、活動時段 | △ | 單批次的四次觀察相距數十秒；跨時間要比較多批 |
| 只給第一次造訪 | △ 記錄為訊號、標籤 unknown | 同出口無法從設計上排除 |
| CAPTCHA、互動閘門後的內容 | ✘ | 不互動、不解 |
| 依 cookie 的回訪分流 | ✘ | 每次觀察全新 session |
| 子框架、檔案下載中的內容 | ✘ | 子框架導覽被擋；非 HTML 不讀 |
| φ 認不出的惡意內容 | ✘（有系統性差異時降為 unknown） | φ 的 recall 是 cloaking 判定的上界 |

**可能的誤判**：

- cloaking 偽陽性：伺服器為了 SEO 對機器人回傳簡化頁（dynamic rendering）且 φ 剛好在瀏覽器版命中
  高特異性機制；φ 本身的偽陽性（高特異性規則仍是啟發式，未以獨立標註校準）；依 UA 雜湊分桶、
  兩次都落同一桶的 A/B 測試。
- cloaking 偽陰性（判 false 但其實有）：上表 ✘ 的所有手法；`false` 只代表本次條件下未觀察到。
- unknown 偏多是設計結果：四次觀察任一不完整就不判 false。統計時 unknown 必須留在分母、單獨列出；
  `evaluate.py` 報三種比例（unknown 全當 false／排除／全當 true），只描述此 cohort 與此 client 組合，
  不是釣魚網站母體盛行率。
- 釣魚判定：φ 的 URL 特徵會把 IP 主機、非標準 port 計入（loopback 測試頁也會因此判 phishing）；
  同主機外部腳本可能是函式庫，`scope=all` 的程式碼類規則可能誤中；JS 內容只觀察到 settle 時間內出現的部分；
  `not_detected` 不是安全證明。
- 模型：自報的判斷沒有校準；同模型、同提示詞、temperature 0 仍不保證位元級可重現。

**運作限制**：DNS 檢查與實際連線之間有時間差（rebinding），程式層無法消除；browser context 不是 OS／網路
隔離；GET 端點也可能有伺服器端副作用。正式量測應在獨立 VM、無憑證的使用者環境，以出口防火牆阻擋私有網段。
`observations/` 保存的是不可信的釣魚 HTML 與 JS：只以文字或隔離環境檢視，不要在日常登入的瀏覽器開啟。
本工作區沒有 `.git`，manifest 的 `git_commit` 為空，以 `code_sha256`（每個 `.py` 的雜湊）稽核程式版本。

## 評估

- `evaluate.py`（或 `cli.py evaluate`）：v2 以後的 CSV 依 `source_label` 分 cohort，列出規則／模型／最終
  三層的分布、規則 → 最終的交叉表、unknown 理由、observed 訊號，拒絕合併不同 `measurement_version`。
- A/A 噪音底線：用「A/A noise floor」config（`PAIR_MODE=human_human`）跑同一份清單，比較 `rule_fired_raw`。
- precision／recall 需要獨立、盲化的人工標註（`annotate.py` → `score_annotations.py`）；不可用
  `source_label` 自動填真值。標註與 holdout 的設計原則見 [docs/research_v2.md](docs/research_v2.md)〈獨立評估方式〉，
  在 v3 仍然適用。

## 測試

```powershell
.venv\Scripts\python.exe -m pytest tests -q
```

測試不連外：`tests/conftest.py` 擋掉所有非 loopback 的 DNS，證據檔與 CSV 寫到暫存目錄，模型實例為 None 或替身。

| 檔案 | 涵蓋 |
|---|---|
| `test_page_mechanisms.py` | φ 本體（自 v1 原樣保留） |
| `test_phishing.py` | 釣魚三層輸出、不完整觀察、模型不可越權、模型只拿證據 |
| `test_static_cloaking.py` | S1–S3 連言規則、S4 |
| `test_cloaking_rules.py` | C1–C5（原樣保留）、結構分歧、閘門規則表 |
| `test_cloaking_labels.py` | v3 閘門與每個替代解釋、訊號表證據、模型不改標籤 |
| `test_pipeline_e2e.py` | 真實 graph 接線、盲標 meta 不洩漏、label 逐列來源、成功／失敗列同欄位、批次 manifest |
| `test_feeds.py` | 快照正規化、不可覆寫、雜湊驗證、離線匯入、舊快照可讀 |
| `test_llm.py` | 嚴格 schema、Ollama 參數與 digest、重試、雲端 provider 停用、降級 |
| `test_observation_local.py` | 真 requests 與 Chromium 對 loopback 伺服器：UA 分流、導向鏈、JS 與延遲載入、寫入／beacon／越界阻擋、前端導向、下載不存檔、passive 範圍擋內網 |
| `test_compat.py` | φ 逐位元組不變、舊入口與函式名稱、client 設定無偽裝、槽位指派、評估與盲標工具自檢 |
