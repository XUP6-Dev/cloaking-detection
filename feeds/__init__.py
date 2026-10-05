"""Feed 匯入：URL 正規化、不可變批次快照、PhishHunt 來源介面。

  urls.py      保守正規化（不合併可能不同的樣本）
  snapshot.py  不可變批次目錄 + 雜湊驗證 + 舊工具相容投影
  phishunt.py  下載 https://phishunt.io/feed.txt（只下載清單，不造訪其中 URL）
"""
