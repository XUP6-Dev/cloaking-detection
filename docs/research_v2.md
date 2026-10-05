# 2026-10-04 架構審查與 v2 遷移

> 歷史紀錄（passive-v2）。現行版本（dual-observation-v3）的結構與語意變更見
> [migration_v3.md](migration_v3.md)；本文的檔案路徑是 v2 的位置。〈獨立評估方式〉一節在 v3 仍然適用。

## 原架構、衝突與保留範圍

原流程為 `fetch_feed.py`（OpenPhish + MUD，覆寫 urls/ground_truth）→ `main.py` → LangGraph node0 requests 存活探測 → node1 BOT/HUMAN Playwright → node2 去混淆 → node3 phishing → node4 cloaking → node5 CSV。

`page_mechanisms.evaluate_page()` 是兩個判定共用的 φ。Node3 原來把規則分數與 LLM 自報 confidence 融合；node4 動態規則 C1–C5 不接 LLM，但正向差異確認失敗仍保留陽性，而且 Node5 先檢查 verified 才檢查量測品質，可能把挑戰／不完整觀察輸出為 True。抓不到頁面的 phishing 預設 False 也無法區分未判定。來源 `label` 被用作母體分組，卻沒有完整批次 provenance。

已存在的安全與實驗限制包括同出口 IP、不解 CAPTCHA、不提交表單、φ 共享、三態 cloaking、Node2 不跳過、盲標 meta 不放 label 或判定、成功／失敗 CSV 同欄位。這些仍保留。

直接衝突是五維極化中的 stealth / TLS impersonation / session prewarm / 人類行為模擬 / gate click，以及釣魚裁決融合 LLM 分數。依本次明確使用者要求停止這些行為，而非悄悄改預設。`CLAUDE.md` 原文保留作歷史不變量來源；其不相容敘述由本次 `passive-v2` 規格明確覆蓋。沒有新增 proxy、IP 輪替或 CAPTCHA solver。

## 論文核對

[PhishParrot arXiv:2508.02035v1](https://arxiv.org/html/2508.02035v1) 的 Fig.1／III-E 將環境最佳化後取得的 HTML、截圖、網路紀錄交給獨立分類器；IV-A 列出 ChatPhishDetector、VisualPhishnet、StackModel。因此本專案不能把 profile 選擇稱為「PhishParrot 釣魚分類器」。

III-B Table I 的結構化環境／HTTP／HTML 觀察可沿用作稽核設計；本次沒有重現其全部 DNS、註冊資訊、檢索庫與 embedding。III-C 的 successful/failed crawling 是爬取結果標籤；IV-A 描述人工共識建庫，並未定義可直接搬來當本專案 phishing 規則的分類 schema。此處 φ 與新可比較性規則均是本專案定義，不宣稱與論文分類器等價。論文的住宅／行動網路、受害者 profile 最佳化不在本次實作範圍。

Playwright 安裝與瀏覽器版本依 [官方安裝說明](https://playwright.dev/docs/intro#installing-playwright) 及 [Python browser 文件](https://playwright.dev/python/docs/browsers)。本次使用 Chromium 原生 UA，記錄實際版本，不用 Chromium 配上 Safari UA 宣稱為 Safari 實驗。一般 route 對 HTTP redirect chain 只攔首個請求，因此額外使用 Chromium request-stage CDP interception 檢查每跳；此為阻擋越界請求的安全控制，不是規避反爬蟲。

Ollama 使用 [原生 chat API](https://docs.ollama.com/api/chat) 的非串流 `format` schema，依 [Structured Outputs](https://docs.ollama.com/capabilities/structured-outputs) 再做本機嚴格驗證；[model tags API](https://docs.ollama.com/api/tags) 提供本機模型 digest。

## 最小模組調整與檔案

| 檔案 | 改動理由 |
|---|---|
| `fetch_feed.py` | 改 PhishHunt adapter，保存不可覆寫批次、原始 bytes、URL 正規化／拒收、timestamp/hash；舊 CSV 僅為投影 |
| `observation.py`（新增） | frozen profile、CrawlRecord 型別、版本、URL/scope 控制、未知狀態理由 |
| `nodes/dual_crawler.py` | 唯一必要的大幅縮減：移除不符合限制的偽裝／互動程式，保留槽、模式與穩定 SHA-1 順序；被動 Playwright 與授權測試重複觀察 |
| `nodes/node0_liveness.py`, `node1_scraper.py` | 不再額外 HTTP 探測或以第三種身分 fallback；從同一觀察擷取 inline JS，避免 HTML 提供的外部 URL 引發未記錄請求 |
| `nodes/node2_js_analyzer.py`, `nodes/prompts.py` | Node2 保留且只做字串處理；移除外部 de4js CLI 路徑；LLM code JSON 獨立保存，不覆寫規則證據 |
| `llm.py`, `llm_contract.py`（新增） | 預設本機 Ollama，timeout/retries/schema、嚴格型別與 JSON 驗證、失敗降級、model digest／版本／參數／提示詞稽核 |
| `nodes/node3_phishing_classifier.py` | 保留 φ 和原本混淆加權，最終規則結果不融合 LLM；增加 unknown 與獨立模型紀錄 |
| `nodes/node4_cloaking_analyzer.py` | 保留 C1–C5 原始診斷，用可比較性、挑戰頁、雙端重複觀察與反向差約束三態輸出；不依 LLM 最終裁決 |
| `state.py`, `graph.py` | 新欄位契約；invalid/no-content 一樣輸出 unknown 稽核，主要拓撲保持不變 |
| `audit.py`（新增）, `main.py`, `nodes/node5_output.py` | 逐列 source、規則／模型／最終結果分層；不可覆寫 audit JSON；CSV 追加欄位，失敗列一致；manifest 記 code/package/profile/model |
| `evaluate.py` | v2 只報 source cohort 與 unknown；拒絕混合版本或未核對設定的 baseline 匯總 |
| `requirements.txt`, `setup_playwright.py`, `.vscode/launch.json`, `.gitignore` | Ollama 不需雲端 SDK；Playwright 瀏覽器與專案 `.venv` 同址安裝及啟動驗證；程序範圍設定；生成證據不誤入版本庫 |
| `README.md`, `docs/README.v1.md`, 本文件 | 新操作方法、保留舊批次語意及遷移差異 |
| `tests/test_research_v2.py`, `test_node3_phishing.py`, `test_node4_cloaking.py`, `test_pipeline_e2e.py` | 僅驗證本次來源、降級、三態、安全邊界及相容性 |

`nodes/page_mechanisms.py` 的規則庫沒有修改。仍需獨立標註驗證其特異性，不能把註解中的「合法網站不會」當成已被證明。

## 欄位與版本遷移

| 舊欄位 | v2 相容行為與讀取方式 |
|---|---|
| `label` | 留存來源 cohort 投影 `phishing`；絕不是新人工真值；以 `source_label=phishunt_suspicious` 明示其可信度 |
| `is_phishing` | 仍為舊布林投影。`False` 同時可能來自 not_detected/unknown，請讀 `phishing_verdict` |
| `cloaking` | 保留 True/False/N/A，對應新 `cloaking_label=true/false/unknown` |
| 所有既有 batch 診斷欄 | 保留名稱；`rule_fired_raw` 是閘門前的規則觸發，不能冒充 final true |
| manifest 既有欄位 | 保留並追加 schema／量測版本、run_id、batch manifest hash、設定與程式檔 SHA-256 |
| `pairs/meta.json` | 仍只有原六個觀察欄位，沒有 source_label、label、模型或裁決 |

舊「固定四欄」讀取器需改為按欄名讀取或明確選取前四欄；不應將追加欄位截掉後再宣稱可重現。歷史 CSV 沒有 v2 版本者維持 legacy 評估，不補造缺少的 source/time/profile。新的 `_extract_result` / `_empty_result` 使用同一投影以保證欄位一致。

`observed_at` 在結果列為完成判定的 UTC 時間；每個 crawl record 包括該次觀察起始 UTC。`source_fetched_at` 分別表示 feed 取得或離線匯入時間，不是站點建立時間。HTML 截斷、HTTP 非 2xx、挑戰／對話閘門、請求政策阻擋、缺版本／profile、重複觀察失敗或不穩定都保留原因。所有 evidence 皆為不可信資料，模型沒有工具執行權。

## 獨立評估方式

本次功能測試不是偵測率評估，沒有使用 feed 當真值。評估新規則或新資料集時：

1. 固定獨立 holdout（以 domain/campaign 和時間分割，禁止同一攻擊套件近重複跨 split），記錄來源、抽樣時間、URL／證據 hash。調整規則只能用 development split。
2. 由至少兩位不看來源 label、系統結果或模型輸出的標註者，以安全截圖與文字證據各自標註 `phishing_truth` 和 `cloaking_truth`；分歧由第三位裁決，保留 unknown、rater、依據、時間與版本。禁止以 source_label 自動填 truth。
3. Cloaking ground truth 優先來自本機／授權 testbed 的伺服器設定與請求 log：穩定對照、受控語系分流、只換正常內容、CAPTCHA、HTTP 封鎖、隨機內容、一次性 token、缺頁、反向差。純 IP 分流列為刻意測不到，不以新增 proxy 補洞。
4. 分開報 phishing 與 cloaking confusion matrix、precision、recall、unknown coverage；unknown 不當 true negative，另列排除 unknown 的條件結果及完整分母。真值不足就不報 recall。不能從 source cohort 比例推論所有釣魚網站母體盛行率或有保證的下界。
5. 模型只評說明品質／忠實度與 JSON 通過率；測試模型替換或失效時 final labels 一致。自報 confidence 與 heuristic score 都不是已校準的機率。

## 尚未解決的限制

真實目標沒有受控設定對比，故 cloaking 一律 unknown；這是範圍限制的直接結果，不是零 cloaking。停用 JS、未額外下載 external scripts、嚴格 content hash 穩定性以及請求政策會降低 coverage。測試 locale 差異只證明本次條件下差異，不能推論對真實受害者或其他環境的行為。φ、挑戰頁 regex 與高特異性分類仍可能誤判；快照不能重現遠端網站當時的執行環境。

同主機／無 proxy 僅記為出口政策，沒有向第三方查詢公網 IP，不能證明上游網路未重新路由。DNS 檢查存在解析時間差；browser context 不等同 OS 隔離。正式量測仍需獨立 VM、無憑證的使用者環境、出口防火牆與資源限制。程式層只限定讀取行為，無法保證任意 GET 伺服器端沒有副作用。

本工作區沒有 `.git`，因此 manifest 的 `git_commit` 為空、`git_dirty` 為 null；使用 source file hashes 稽核，不宣稱存在可重現的 commit。取得 feed 本身可連網，但本次測試沒有下載即時 PhishHunt 清單或造訪真實待分析網站。


## 本次驗證與執行環境結果

執行 `.venv/Scripts/python.exe -m pytest tests/test_research_v2.py test_node3_phishing.py test_node4_cloaking.py test_node4_static.py test_pipeline_e2e.py test_page_mechanisms.py -q --disable-warnings`，**110 項通過**。涵蓋不可覆寫快照／hash 驗證、URL 安全性、JSON Schema、LLM 不影響規則與最終標籤、挑戰／缺頁／重複觀察失敗降級、source 與盲標隔離、成功／失敗 CSV 同欄位、本機 Chromium 多跳導向與越界阻擋、非讀取請求阻擋、Ollama 重試／缺模型降級、manifest 版本與 v2 統計分母；新增 LF／CRLF 來源連接及 JS surrogate 完整性回歸。

實際服務檢查：Ollama `/api/version` 回報 `0.34.4`，本機已有 `qwen3.5:9b`，digest `6488c96fa5faab64bb65cbd30d4289e20e6130ef535a93ef9a49f42eda893ea7`。只用合成的正常 HTML 做本機 inference smoke test；`/api/chat` 回 500，錯誤為 **llama-server binary not found**。未安裝／編譯／重啟全域 Ollama，也未照伺服器錯誤文字執行命令。需修復使用者的 Ollama 安裝才能實際產生模型說明；專案會記錄原因並以純規則繼續，沒有雲端 fallback。
