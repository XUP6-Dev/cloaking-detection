"""管線共享狀態 —— 所有節點透過這個 TypedDict 交換資料。

欄位依「誰寫入」分組。釣魚與 cloaking 是兩個獨立屬性、不互為前提：一個釣魚站可以
不做 cloaking，一個做 cloaking 的站也可以不是釣魚站，所以各自判定、各自輸出，
不合成單一風險分數。兩者共用的只有判準 φ（analysis/page_mechanisms.evaluate_page）。
"""
from typing import Any, Dict, List, Literal, TypedDict

from schemas.records import ObservationRecord


class AnalysisState(TypedDict):
    # ── 建立時寫入（graph.create_initial_state）─────────────────
    schema_version: str
    run_id: str
    analysis_id: str
    url: str
    source_record: Dict[str, Any]          # feed 快照的逐列來源；手動輸入時為空
    observation_settings: Dict[str, Any]   # 本列實際使用的觀察設定快照（順序、配對、變體、範圍）
    run_config_sha256: str                 # 觀察設定的雜湊，對應 manifest 的同名欄
    observation_plan: str                  # 本列實際的觀察順序，例如 bot_first:B1,H1,B2,H2;variants=

    # ── Node 0：網址驗證 ─────────────────────────────────────────
    alive: bool | None                     # True=收到 HTTP 回應；False=網址無效；None=無法觀察
    liveness_reason: str

    # ── Node 1：觀察 ─────────────────────────────────────────────
    # 槽名是歷史名稱：bot = 基準 HTTP、human = Playwright 瀏覽器（A/A 模式兩槽同類）。
    # 各槽的第二次觀察放在 record["confirmation"]。
    bot_crawl: ObservationRecord
    human_crawl: ObservationRecord
    variant_observations: Dict[str, ObservationRecord]   # 可選變體：referer / mobile
    # raw_html 是歷史名稱，實際內容是「釣魚判定用的頁面」= 瀏覽器 JS 執行後的 DOM；
    # 瀏覽器不可用時退回基準 HTTP 的原始文件，analysis_source 記錄實際來源。
    raw_html: str
    analysis_source: str                   # 例如 "human#1:dom" / "bot#1:html"
    analysis_profile_id: str
    analysis_final_url: str
    observation_issues: List[str]          # 判定用頁面的觀察問題（分級見 crawler/records.py）
    js_scripts: List[Dict[str, Any]]

    # ── Node 2：去混淆 ───────────────────────────────────────────
    deobfuscated_js: List[Dict[str, Any]]

    # ── Node 3：釣魚 ─────────────────────────────────────────────
    phishing_rule_result: Dict[str, Any]   # φ + 混淆加權的完整結果
    rule_phishing_verdict: Literal["phishing", "not_detected", "not_run"]
    phishing_verdict: Literal["phishing", "not_detected", "unknown"]
    phishing_reason: str
    phishing_basis: str
    phishing_caveats: List[str]
    llm_phishing_assessment: str
    is_phishing: bool                      # 舊布林：只有 phishing_verdict == "phishing" 時為 True
    phishing_confidence: float             # 舊診斷欄：Layer 1 固定 0.95 / Layer 2 上限 0.90（不是機率）
    phishing_indicators: List[str]

    # ── Node 4：cloaking ─────────────────────────────────────────
    static_evidence: Dict[str, Any]        # 前端 JS 特徵（S1–S3 規則與一般性偵測）
    signals: List[Dict[str, Any]]          # 訊號表：每個訊號都附實際觀察值（analysis/signals.py）
    rule_cloaking_label: Literal["true", "false", "unknown"]
    cloaking_label: Literal["true", "false", "unknown"]
    cloaking_reason: str
    cloaking_basis: str
    cloaking_uncertainty: List[str]        # 閘門理由（cloaking_label 為 unknown 的原因）
    llm_cloaking_assessment: str
    cloaking_verified: bool                # 舊欄：cloaking_label == "true"
    cloaking_confidence_tier: str          # 舊診斷欄：CONFIRMED / SUSPECTED / AMBIGUOUS
    dual_crawl_results: Dict[str, Any]     # 舊診斷欄的來源（主配對的 C1–C5 原始結果）

    # ── 全程 ─────────────────────────────────────────────────────
    model_outputs: List[Dict[str, Any]]    # 每次模型呼叫的完整稽核（不影響任何最終標籤）
    evidence: Dict[str, Any]               # Node 5 寫入：稽核 JSON 路徑與 SHA-256
    observed_at: str                       # Node 5 完成判定的 UTC 時間
    report: str
    errors: List[str]
