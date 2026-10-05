"""判定層：只讀觀察紀錄，不發任何網路請求。

  page_mechanisms.py  φ：單頁惡意機制判準（釣魚判定與 cloaking 機制集合差共用的同一把尺）
                      —— 自 nodes/ 原封搬移，內容逐位元組未變；改它會同時移動兩欄輸出
  deobfuscation.py    JS 去混淆（確定性；模型重建只作參考）
  phishing.py         本專案的釣魚判定（規則結果 → 最終判定；模型分析另存）
  static_cloaking.py  前端 JS cloaking 特徵 S1–S3（不裁決，只擋「未觀察到」）
  cloaking.py         C1–C5 機制集合差 + 觀察品質／替代解釋閘門 → 三態標籤（不收 llm）
  signals.py          cloaking 訊號表：六類觀察訊號，每個都附實際值
"""
