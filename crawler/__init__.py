"""觀察層：對一個 URL 做哪些觀察、怎麼觀察、紀錄長什麼樣。判定不在這裡（見 analysis/）。

  profiles.py       兩種 client 的設定（實驗變因）與可選變體
  policy.py         請求邊界：範圍（防內網）、只讀方法、阻擋清單
  records.py        紀錄骨架、共用解碼與摘要、閘門偵測、觀察問題分級、證據檔案
  http_baseline.py  基準 HTTP 觀察（requests，不執行 JS）
  browser.py        Playwright 瀏覽器觀察（執行 JS，不互動）
  plan.py           觀察計畫：交錯順序、A/A 配對、變體；ObservationSettings
"""
