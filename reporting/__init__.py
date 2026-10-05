"""輸出層：CSV、稽核 JSON、執行 manifest、盲標配對、主控台摘要。

  rows.py      欄位定義與唯一的逐列投影（兩份 CSV 共用）
  audit.py     逐列稽核 JSON（不可覆寫；大型內容以證據檔路徑＋雜湊引用）
  manifest.py  執行 manifest（設定、程式碼雜湊、套件、模型、來源批次）
  pairs.py     盲標配對檔（meta 不含任何判定或來源標籤）
  csv_io.py    CSV 讀寫
  console.py   UTF-8 主控台與批次摘要
"""
