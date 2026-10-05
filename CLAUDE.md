# CLAUDE.md

這是一台**量測儀器**，不是產品：輸出的是對威脅情資清單中活體 URL 的兩個獨立判定
（釣魚、cloaking）與各自的證據。每個預設值都是實驗變因 —— 改掉一個，改動前後跑出來的
批次就不能合併統計（`schemas/versions.py` 的 `MEASUREMENT_VERSION` 必須跟著改，
`evaluate.py` 會拒絕混合版本）。動手前先確認要動的是不是變因。

管線：`node0 網址驗證 → node1 觀察（基準 HTTP ×2 + 瀏覽器 ×2，交錯）→ node2 去混淆 → node3 釣魚 → node4 cloaking → node5 輸出`
（拓撲與條件路由在 `graph.py`；欄位語意在 `schemas/state.py` 與 `schemas/records.py`，逐條註解過。）
程式依職責分在 `feeds/`、`crawler/`、`analysis/`、`llm/`、`schemas/`、`reporting/`；`nodes/` 只是薄轉接。

程式碼註解寫的是**為什麼**這樣而不是那樣 —— 那是這個專案的主要文件形式。
改一段之前先讀它上面的註解；新增的程式碼比照，別只寫做了什麼。

## 動手前的不變量

這幾件事壞掉都不會有錯誤訊息，只會安靜地讓數字失去意義：

- **φ 是同一把尺。** `analysis/page_mechanisms.py` 的 `evaluate_page()` 同時是 Node 3 的
  釣魚判準與 Node 4 機制集合差的定義來源。動它會同時移動兩欄輸出，且之前跑過的批次全部作廢。
  `nodes/page_mechanisms.py` 只是別名（同一個模組物件）；`tests/test_compat.py` 鎖住 φ 的 SHA-256，
  要改 φ 就同時改版本號與那個雜湊。
- **cloaking 是三態**（true / false / unknown，舊欄投影為 True / False / `N/A`）。unknown 是「量過但測不準」，
  與「驗過沒有」不是同一件事，任何統計都要分開計。v3 起每個判定分三層：規則結果（`rule_*`）、
  模型分析（`llm_*`）、最終標籤，互不覆寫。
- **LLM 不進任何最終標籤。** `decide_cloaking()` 與 `label_cloaking()` 連 `llm` 參數都不收，維持這樣。
  v2 起釣魚那一欄也不再融合模型信心度；模型輸出只存在 `llm_*` 欄位與稽核 JSON，
  且模型只拿證據、拿不到規則結果或標籤。
- **對比軸是 client 類型，IP 維度不極化。** 兩種 client（誠實宣告的非瀏覽器 HTTP client、原生 headless
  Chromium）共用同一出口是**待檢驗假設的一部分**，不是待辦事項；proxy、UA 偽裝、stealth、session 預熱、
  互動閘門跨越都已移除，不要再加回來。順序汙染的代價由 `reverse_diff`、`first_access_only` 訊號與
  `CRAWL_ORDER` 切分去量。
- **盲標 meta 不得帶任何判定欄位，`label` 與 `source_label` 也不行**（`reporting/pairs.pair_meta()`，
  `main._pair_meta` 是別名）。label 不是系統的判定，但它是先驗（「這站被來源標為釣魚」會把標註者推向 yes）。
  `tests/test_pipeline_e2e.py::test_pair_meta_contains_no_verdict` 用集合差 + 全文字表鎖住它。
- **分母是來源標籤，不是 `phishing_verdict`。** 分子（cloaking）的判定路徑全部經過 φ；
  用本系統的釣魚判定當分母等於同一把尺量分子分母，誤差相關而比值看不出來。
  來源標籤（v3：PhishHunt，`source_label=phishunt_suspicious`，舊 `label` 欄投影）來自系統之外，
  是威脅情資不是真值，必須**逐列**存在 CSV 裡 —— `ground_truth.csv` 是固定檔名，下一次匯入就覆蓋它。
  `evaluate.resolve_labels()` 的優先序（CSV 欄 > 基準檔 > 無）由 `_selfcheck()` 鎖住（測試會呼叫）。
- **Node 2 不可跳過。** 規則比對的是可讀原始碼，這是管線唯一真正的順序依賴。
- **兩份 CSV 只有一個投影。** `reporting/rows.result_row()` 是成功列與失敗列（`cli.failure_row()`）
  共同的來源，否則失敗列的 CSV 會缺欄。

## 每次批次

1. **重抓清單再跑**：`cli.py fetch-feed`（PhishHunt；相容入口 `fetch_feed.py`）或 `build_urls.py`
   （MUD 資料集），抓完立刻 `cli.py run --batch feed_batches/<id>`，別隔夜。釣魚站存活期以小時計，
   過期清單會把「站死了」混進結果。
2. **設定走 `.vscode/launch.json` 的 config，不要在終端機下 `$env:`。**
   PowerShell 的環境變數留在整個 session，跑完 A/A 對照批忘了改回來，下一批會沿用且毫無提示。
   某個 CSV 到底是哪種設定跑的，以 `csv_reports/run_*.json`（manifest）為準；
   每一列的 `run_config_sha256` 對應 manifest 的同名欄。
3. 旋鈕：`CRAWL_SCOPE`、`PAIR_MODE`、`CRAWL_ORDER`、`OBSERVATION_VARIANTS`、`SAVE_PAIR_HTML`、
   `LLM_PROVIDER` + `LLM_MODEL` + `OLLAMA_*`。全部會寫進 manifest。
   `EGRESS_LABEL`（出口網路，launch.json 每次執行時詢問）只是紀錄、不是旋鈕：寫進 manifest 的 `egress`，
   刻意不進 `run_config_sha256`，所以 `evaluate.py` 擋不住不同網路的批次混在一起。`HUMAN_PROFILE` 已退役（殘留會報錯）。
   `CRAWL_ORDER` 預設 `split`（依 URL 的 SHA-1 逐筆切一半，順序是**批內**變因，不必跑兩批）；
   `bot_first` / `human_first` 是強制覆寫，給 A/A 對照批用。

## 環境

Windows + PowerShell；直譯器固定用 `.venv\Scripts\python.exe`（撿到系統 Python 會與
Playwright 瀏覽器快取版本對不上）。主控台編碼由 `reporting/console.ensure_utf8_console()` 強制 UTF-8
（`nodes/__init__.py` 與各入口都會呼叫）—— 節點輸出含 emoji，cp950 下是直接拋例外中斷，不是變亂碼。
LLM 只用本機 Ollama；停用、連不上或輸出不合 schema 時 `llm_*` 欄位記 `unavailable`，管線照跑、標籤不變。

測試不連網（`tests/conftest.py` 擋掉所有非 loopback 的 DNS；真 Chromium 只對本機測試伺服器）：

```
.venv\Scripts\python.exe -m pytest tests -q
```

## 要細節時查 README

| 想知道 | 位置 |
|---|---|
| 目錄結構、資料流程、旋鈕 | README「目錄結構」「資料流程」「安裝與執行」 |
| 兩種 client 各保存什麼、安全邊界、變體 | README「觀察：兩種 client」 |
| 釣魚與 cloaking 的定義、C1–C5、閘門、替代解釋 | README「標籤定義」 |
| 六類 cloaking 訊號與證據欄位 | README「Cloaking 訊號」 |
| CSV 欄位 | README「輸出欄位」 |
| 看得見／看不見哪些手法、誤判來源 | README「已知盲點、限制與誤判來源」 |
| PhishParrot 能用與不能用的部分 | README「PhishParrot 核對」 |
| v2 → v3 搬了什麼、量測語意改了什麼 | `docs/migration_v3.md` |
| 規則表怎麼新增 | `analysis/RULE_TEMPLATES.md` |
| v1 的盛行率區間、A/A 對照、盲標 precision 的推導 | `docs/README.v1.md`（歷史，v3 不可與其批次合併） |
