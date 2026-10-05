"""相容入口（v2）：`python fetch_feed.py [LIMIT] [--input FILE] [--snapshot-root DIR]`
等同 `python cli.py fetch-feed …`。匯入只下載清單本身，從不造訪清單中的 URL。

保留的舊名稱：snapshot_feed（PhishHunt 預設來源）、load_batch、fetch_feed、FEED_URL。
實作在 feeds/。
"""
import sys

from feeds.phishunt import FEED_URL, fetch_feed                        # noqa: F401
from feeds.phishunt import snapshot as snapshot_feed                   # noqa: F401
from feeds.snapshot import MAX_FEED_BYTES, load_batch                  # noqa: F401


def main(argv=None):
    from cli import main as cli_main
    return cli_main(["fetch-feed", *(sys.argv[1:] if argv is None else argv)])


if __name__ == "__main__":
    sys.exit(main())
