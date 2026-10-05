# v2 → v3 遷移紀錄（2026-10-05）

v3 是**量測版本變更**（`measurement_version=dual-observation-v3`、`schema_version=3.0`），
不是單純搬檔：觀察方式與 cloaking 閘門都變了。v2（`passive-v2`）與 v3 的批次**不可合併統計**，
`evaluate.py` 會拒絕混合版本。舊結果不回填、不轉換，以原版本語意解讀（見
[研究與遷移紀錄 v2](research_v2.md) 與 [歷史 README](README.v1.md)）。

## 1. 模組搬移與相容入口

| v2 位置 | v3 位置 | 相容方式 |
|---|---|---|
| `main.py`（CLI＋批次＋manifest＋CSV＋盲標＋摘要） | `cli.py`（CLI＋批次）、`reporting/rows.py`、`reporting/manifest.py`、`reporting/pairs.py`、`reporting/console.py` | `main.py` 保留為相容入口：`python main.py [--batch] [--limit]` 照常；保留 `_extract_result`、`_empty_result`、`_pair_meta`、`_save_pair`、`select_batch`、`analyze_url`、`analyze_batch` |
| `fetch_feed.py` | `feeds/phishunt.py`、`feeds/snapshot.py` | `fetch_feed.py` 保留：`python fetch_feed.py [LIMIT] [--input] [--snapshot-root]` 照常；保留 `snapshot_feed`、`load_batch`、`fetch_feed`、`FEED_URL` |
| `observation.py` | 版本 → `schemas/versions.py`；`sha256`/`utc_now`/`jsonable` → `schemas/evidence.py`；`normalize_url`/`origin` → `feeds/urls.py`；`CrawlProfile`/`profile_for` → `crawler/profiles.py`；`permitted_url` → `crawler/policy.py`；`observation_issues` → `crawler/records.py` | 已刪除（內部模組），改 import 新位置 |
| `state.py` | `schemas/state.py`（`AnalysisState`）、`schemas/records.py`（`ObservationRecord`） | 已刪除 |
| `audit.py` | `reporting/audit.py`（`AUDIT_ROOT`、`finalize_audit`）、`reporting/rows.py`（`AUDIT_FIELDS`、`audit_columns`） | 已刪除 |
| `llm.py` | `llm/`（套件）：`providers.py`、`contract.py`、`prompts.py` | `import llm`、`llm.llm_code/llm_phish/llm_cloak`、`llm.OllamaLocal` 照常 |
| `llm_contract.py` | `llm/contract.py` | 已刪除 |
| `nodes/page_mechanisms.py`（φ） | `analysis/page_mechanisms.py`（**內容逐位元組相同**，SHA-256 `776d79d1…0721`） | `nodes/page_mechanisms.py` 是別名：`import nodes.page_mechanisms` 拿到同一個模組物件 |
| `nodes/dual_crawler.py` | `crawler/plan.py`（計畫、順序、配對）、`crawler/http_baseline.py`、`crawler/browser.py` | 已刪除；`crawler.plan.dual_crawl(url)` 保留 v2 的回傳形狀 `(bot, human, errors)` |
| `nodes/prompts.py` | `llm/prompts.py` | 已刪除 |
| `nodes/node2_js_analyzer.py` 的 `Deobfuscator` | `analysis/deobfuscation.py`（邏輯未改） | `from nodes.node2_js_analyzer import Deobfuscator` 仍可用 |
| `nodes/node3_phishing_classifier.py` 的判定邏輯 | `analysis/phishing.py` | 節點保留 `classify_phishing_node(state, llm)` |
| `nodes/node4_cloaking_analyzer.py` | `analysis/cloaking.py`（`decide_cloaking` 等 6 個函式 AST 相同）、`analysis/static_cloaking.py`（特徵庫逐項相同）、`analysis/signals.py`（新增） | 節點保留 `analyze_cloaking_node`、`decide_cloaking`、`_detect_gates`、`_static_detect`、`_structural_divergence`、`_similarity_score` |
| `nodes/node5_output.py` 的欄位與 CSV | `reporting/rows.py`（唯一投影）、`reporting/csv_io.py` | 節點保留 `output_node`、`FIELDNAMES`、`SESSION_CSV`、`_cloaking_verdict`、`CLOAKING_UNKNOWN` |
| `nodes/RULE_TEMPLATES.md` | `analysis/RULE_TEMPLATES.md` | — |
| 根目錄 `test_*.py`、`tests/test_research_v2.py` | `tests/`（依主題拆分，見 README「測試」） | `python -m pytest tests` |

刪除且不提供轉接的 v2 內部函式：

- `nodes/node4_cloaking_analyzer.py` 的 `_assess_dynamic_reliability`、`_pair_issues`、`_dynamic_verify`
  → 由 `analysis.cloaking.label_cloaking` 取代。
- `nodes/dual_crawler.py` 的 `_timed_fetch`、`_effective_order`、`_empty_result`
  → `crawler.http_baseline.fetch` / `crawler.browser.fetch`、`crawler.plan.effective_order(url, crawl_order)`、
  `crawler.records.new_record`。模組常數 `CRAWL_ORDER` / `PAIR_MODE` 改成每次執行一份的
  `crawler.plan.ObservationSettings` 快照（寫進每一列與 manifest）。
- `main.py` 的模組全域變數 `_SOURCE_RECORDS` / `_BATCH_MANIFEST` / `_RUN_ID` → `cli.Run` 物件。

## 2. 量測語意變更（為什麼 v3 不能與 v2 合併）

| 項目 | v2（passive-v2） | v3（dual-observation-v3） |
|---|---|---|
| 每個 URL 的觀察 | 2 次 Playwright，兩槽**相同設定**、JS 關閉 | 4 次交錯：基準 HTTP ×2（bot 槽）＋ Playwright JS 開啟 ×2（human 槽） |
| 真實 URL 的 cloaking | 一律 unknown（沒有對比） | 依兩種 client 的伺服器回應比較，可為 true / false / unknown |
| cloaking 比較的內容 | 兩槽 `page.content()` | 兩種 client 收到的**伺服器主文件**（同一層）；JS 渲染後 DOM 另存 |
| 重複觀察 | 只在測試範圍 | 每個 URL 都做，且交錯排序 |
| 內容穩定性 | 主文件雜湊完全相同 | 狀態／主機／機制穩定；雜湊只在同側穩定時才當成系統性差異 |
| 釣魚判定頁面 | JS 關閉的頁面 | 瀏覽器 JS 執行後的 DOM（不可用時退回基準 HTTP 原始文件並標註） |
| 觀察問題 → 釣魚判定 | 任何問題（含 favicon 404）都 → unknown | 分級：沒有文件 → unknown；不完整只讓「未檢出」變 unknown，規則陽性仍為 phishing |
| 子資源失敗 | 一律影響判定 | 只有 document/script/xhr/fetch/websocket/eventsource 類型影響「未檢出」 |
| 截斷上限 | 60,000 字元（10/04 批次 9/50 被截斷） | 分析 2,000,000 字元；本文 5 MB |
| 挑戰頁偵測 | 含 `challenge-platform`、`enable javascript` | 移除這兩個（Cloudflare 一般頁面與 noscript 的常見內容）；alert/confirm/prompt 只在腳本與事件屬性中比對 |
| 請求上限 | 40 | 200 |
| XHR/fetch | 一律擋 | GET/HEAD 允許（視同載入資源）；非 GET 一律擋；websocket/eventsource/beacon 一律擋 |
| locale 對比（測試範圍） | en-US vs zh-TW | 移除；測試範圍改用與真實目標相同的兩種 client |
| 舊 `is_phishing` 欄的 unknown | False（session CSV）或空白（batch CSV），兩份不一致 | `N/A`（兩份 CSV 同一個投影） |
| LLM schema | `{is_phishing, confidence, …}` | `{assessment ∈ enum, key_indicators, explanation}`（無自報信心度） |
| LLM provider | ollama + 5 個雲端／LM Studio 選裝路徑 | 只有 ollama 與 none；其他值停用模型並記錄原因 |
| Ollama 參數 | temperature 0、seed 0、num_predict | 另加 `num_ctx`（預設 8192），避免長提示詞被靜默截斷 |
| φ | — | **未改**（逐位元組相同） |
| C1–C5 規則 | — | **未改**（AST 相同）；v3 新增的是閘門 |

## 3. 新增的輸出欄位（附加在既有欄位之後）

`rule_phishing_verdict`、`llm_phishing_assessment`、`rule_cloaking_label`、`llm_cloaking_assessment`、
`phishing_basis`、`cloaking_basis`、`uncertainty_reasons`、`evidence_sources`、`cloaking_signals`、
`cloaking_signals_not_tested`、`observation_plan`、`run_config_sha256`、`llm_model`、`prompt_version`。
欄位意義見 README「輸出欄位」。讀取請按欄名。

## 4. 舊資料怎麼讀

- `csv_reports/` 下 `schema_version=2.0` 的 CSV：`evaluate.py` 以 cohort 方式報告，不與 v3 合併。
- `audit_records/` 下的 v2 稽核 JSON：`crawl_records` 內含完整 HTML；v3 的稽核 JSON 只存
  證據檔路徑與雜湊（`observations/<record_id>/raw.html`、`dom.html`…），兩者結構不同。
- `feed_batches/` 的 v2 快照：`load_batch` 照常驗證與讀取（v3 只在 manifest 多了 `source_http`）。
