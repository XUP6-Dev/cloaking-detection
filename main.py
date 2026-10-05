"""相容入口（v2）：`python main.py [--batch DIR] [--limit N]` 等同 `python cli.py run …`。

保留舊的函式名稱，新程式請改用右側：
  _extract_result(state)       → reporting.rows.result_row
  _empty_result(url, error)    → cli.failure_row(run, url, error)
  _pair_meta / _save_pair      → reporting.pairs.pair_meta / save_pair
  select_batch / analyze_url / analyze_batch → cli.Run + cli.analyze_url / analyze_batch
v2 的模組全域變數（_SOURCE_RECORDS / _BATCH_MANIFEST / _RUN_ID）由 cli.Run 物件取代。
"""
import sys

import cli
from cli import Run, failure_row
from reporting.pairs import pair_meta as _pair_meta, save_pair as _save_pair  # noqa: F401
from reporting.rows import result_row as _extract_result                      # noqa: F401

_RUN = None


def select_batch(path):
    global _RUN
    _RUN = Run()
    return _RUN.select_batch(path)


def analyze_url(url):
    return cli.analyze_url(url, _RUN)


def analyze_batch(urls, **kwargs):
    return cli.analyze_batch(urls, run=_RUN, **kwargs)


def _empty_result(url, error="pipeline_failed", run=None):
    return failure_row(run or _RUN or Run(), url, error)


if __name__ == "__main__":
    sys.exit(cli.main(["run", *sys.argv[1:]]))
