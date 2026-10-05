"""量測版本常數 —— 每一列 CSV、每份稽核 JSON、每份 manifest 都帶這三個值。

版本號變了就代表觀察方式或判定規則變了：不同 MEASUREMENT_VERSION 的批次不是同一把尺
量出來的，evaluate.py 會拒絕合併統計。改動任何預設值（觀察次數、client 設定、閘門條件）
都必須改這裡，否則新舊批次會被安靜地混在一起。
"""
SCHEMA_VERSION = "3.0"

# v3：每個 URL 交錯觀察四次（基準 HTTP ×2、Playwright 瀏覽器 ×2），
# cloaking 比的是兩種 client 收到的伺服器原始文件。v2（passive-v2）是兩次相同設定、
# JS 關閉的瀏覽器觀察，真實 URL 的 cloaking 一律 unknown —— 兩者不可合併。
MEASUREMENT_VERSION = "dual-observation-v3"

# φ（analysis/page_mechanisms.py）內容逐位元組未變；變的是 cloaking 標籤的閘門。
RULE_VERSION = "phi-unchanged+baseline-browser-gates-v3"

# evaluate.py 用來辨識舊批次。舊批次維持舊語意解讀，不回填、不轉換。
LEGACY_MEASUREMENT_VERSIONS = ("passive-v2",)
