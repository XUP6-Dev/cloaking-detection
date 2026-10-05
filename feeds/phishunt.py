"""PhishHunt 威脅情資匯入。匯入只下載清單本身，從不造訪清單中的 URL。

PhishHunt 是第三方威脅情資，不是人工真值：每列 source_label=phishunt_suspicious 明示
這一點。本專案的釣魚判定（phishing_verdict）與它分開輸出，兩者互不覆寫；評估時也不可
拿它自動填真值（見 README「標籤定義」）。
"""
from pathlib import Path

import requests

from feeds.snapshot import MAX_FEED_BYTES, snapshot_feed
from schemas.evidence import utc_now

FEED_URL = "https://phishunt.io/feed.txt"
SOURCE_LABEL = "phishunt_suspicious"
USER_AGENT = "DefensiveMeasurement/3.0 (feed import)"
# 清單伺服器回報的時間點與版本；寫進批次 manifest 的 source_http。
_HTTP_META = ("content-type", "content-length", "last-modified", "etag", "date")


def download():
    """下載清單，回傳 (原始位元組, 回應中繼資料)。

    不跟隨導向、不讀環境 proxy：清單網址若換了位置，要人看過才接受，
    不讓 3xx 默默把來源換成別的東西。
    """
    with requests.Session() as session:
        session.trust_env = False
        with session.get(FEED_URL, timeout=(10, 30), allow_redirects=False, stream=True,
                         headers={"User-Agent": USER_AGENT}) as response:
            response.raise_for_status()
            if response.status_code != 200:
                raise ValueError("feed_redirect_or_unexpected_status")
            chunks, size = [], 0
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > MAX_FEED_BYTES:
                    raise ValueError("feed_too_large")
                chunks.append(chunk)
            meta = {"status": response.status_code, "url": response.url,
                    **{key: response.headers.get(key, "") for key in _HTTP_META}}
            return b"".join(chunks), meta


def fetch_feed():
    """相容介面（v2）：只回傳原始位元組。"""
    return download()[0]


def snapshot(raw, root, *, source=FEED_URL, **kwargs):
    """以 PhishHunt 的來源標記存成不可變快照（參數見 feeds.snapshot.snapshot_feed）。"""
    return snapshot_feed(raw, root, source=source, source_label=SOURCE_LABEL, **kwargs)


def import_feed(root, *, limit=300, input_path=None):
    """下載（或讀取離線存檔）並存成快照，回傳批次目錄。

    離線匯入時 source 記為該檔的 file URI、fetched_at 是匯入時間 ——
    不謊稱是當日從 PhishHunt 取得的清單。
    """
    if input_path:
        path = Path(input_path)
        raw, source, http_meta = path.read_bytes(), path.resolve().as_uri(), {"offline_input": True}
    else:
        (raw, http_meta), source = download(), FEED_URL
    return snapshot(raw, root, source=source, limit=limit, source_http=http_meta,
                    fetched_at=utc_now())
