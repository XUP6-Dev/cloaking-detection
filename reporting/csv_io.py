"""CSV 讀寫。所有輸出 CSV 用 utf-8-sig（Excel 開得了中文），讀取一律按欄名，不按位置。"""
import csv
import threading
from pathlib import Path

_APPEND_LOCK = threading.Lock()


def load_csv(path):
    with open(path, encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(rows, path, fieldnames):
    path = Path(path)
    with path.open("x", newline="", encoding="utf-8-sig") as handle:   # 不覆寫既有結果
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return path


def append_row(path, fieldnames, row):
    """逐列附加（批次中斷時已完成的列仍在）。多執行緒共用一把鎖。"""
    path = Path(path)
    with _APPEND_LOCK:
        new = not path.exists()
        with path.open("a", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            if new:
                writer.writeheader()
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return new
