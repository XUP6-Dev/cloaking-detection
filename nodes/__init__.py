"""管線節點：LangGraph 的六個步驟，每個都只是「讀 state → 呼叫 crawler/analysis/reporting → 寫 state」。

  node0_liveness            網址驗證（不發請求）
  node1_scraper             依觀察計畫觀察、挑判定用頁面、抽 JS
  node2_js_analyzer         JS 去混淆（不可跳過）
  node3_phishing_classifier 釣魚判定
  node4_cloaking_analyzer   cloaking 訊號表、標籤、模型說明
  node5_output              稽核 JSON、summary CSV、文字報告
  page_mechanisms           相容轉接：φ 已搬到 analysis/page_mechanisms.py（同一個模組物件）

這裡也是所有呼叫端必經之處，所以在 import 時固定主控台為 UTF-8（節點輸出含 emoji，
cp950 下會直接拋例外中斷）。
"""
from reporting.console import ensure_utf8_console

ensure_utf8_console()
