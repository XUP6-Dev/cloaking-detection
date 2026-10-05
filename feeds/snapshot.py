"""不可變批次快照：feed 原始位元組 + 逐列來源 + 雜湊。

每批一個目錄 feed_batches/<batch_id>/，檔案以 "x" 模式建立（已存在就失敗），讀取前
逐檔驗證 SHA-256。這是程式層的 append-only 與完整性檢查，不是檔案系統 WORM 或簽章。

為什麼逐列保存來源而不是事後 join：ground_truth.csv 是固定檔名，下一次匯入就覆蓋。
事後拿它 join 舊批次，對到的是最新那份清單，分母會安靜地換掉。
"""
import csv
import json
import uuid
from pathlib import Path

from feeds.urls import NORMALIZATION_VERSION, normalize_url
from schemas.evidence import sha256, utc_now
from schemas.versions import SCHEMA_VERSION

MAX_FEED_BYTES = 10_000_000
SNAPSHOT_FILES = ("feed.txt", "records.json", "rejected.json", "urls.txt")
_BATCH_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def snapshot_feed(raw, root, *, source, source_label, fetched_at=None, limit=300, batch_id=None,
                  source_http=None):
    """把 feed 原始位元組存成不可變批次，回傳批次目錄。與來源無關；PhishHunt 的預設值在
    feeds/phishunt.py。

    source_label 描述來源的可信度（威脅情資，不是人工真值）；label="phishing" 是舊
    分母欄的投影，代表「第二方來源聲稱這是釣魚」，不是本專案的判定。
    """
    if limit < 1 or len(raw) > MAX_FEED_BYTES:
        raise ValueError("invalid_limit_or_feed_size")
    fetched_at = fetched_at or utc_now()
    batch_id = batch_id or uuid.uuid4().hex
    if not batch_id or set(batch_id) - _BATCH_ID_CHARS:
        raise ValueError("invalid_batch_id")
    records, rejected, seen = [], [], set()
    for line_no, line in enumerate(raw.decode("utf-8-sig", errors="replace").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            url = normalize_url(line)
        except ValueError as exc:
            rejected.append({"line": line_no, "raw_url": line, "reason": str(exc)})
            continue
        if url in seen:
            rejected.append({"line": line_no, "raw_url": line, "reason": "duplicate_normalized_url",
                             "normalized_url": url})
            continue
        seen.add(url)
        records.append({"url": url, "raw_url": line, "normalized_url": url, "line": line_no,
                        "source_label": source_label, "label": "phishing",
                        "source": source, "fetched_at": fetched_at, "batch_id": batch_id,
                        "label_semantics": "unverified_source_intelligence"})
    selected = records[:limit]
    if not selected:
        raise ValueError("feed_has_no_valid_urls")
    directory = Path(root) / batch_id
    directory.mkdir(parents=True, exist_ok=False)
    payloads = {"feed.txt": raw,
                "records.json": json.dumps(selected, ensure_ascii=False, indent=2).encode(),
                "rejected.json": json.dumps(rejected, ensure_ascii=False, indent=2).encode(),
                "urls.txt": ("\n".join(r["url"] for r in selected) + "\n").encode()}
    for name, payload in payloads.items():
        with (directory / name).open("xb") as handle:
            handle.write(payload)
    manifest = {"schema_version": SCHEMA_VERSION, "batch_id": batch_id, "source": source,
                "fetched_at": fetched_at, "source_label": source_label,
                "is_ground_truth": False, "normalization_version": NORMALIZATION_VERSION,
                "valid_unique_count": len(records), "selected_count": len(selected), "limit": limit,
                # feed 伺服器回報的 Last-Modified / ETag 等：說明清單本身的時間點
                "source_http": source_http or {},
                "files_sha256": {name: sha256(data) for name, data in payloads.items()}}
    with (directory / "manifest.json").open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
    return directory


def load_batch(directory):
    """驗證每個快照檔的雜湊後，回傳 (manifest, {url: 來源紀錄})。v2 批次同樣可讀。"""
    directory = Path(directory).resolve()
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    for name in SNAPSHOT_FILES:
        if sha256((directory / name).read_bytes()) != manifest["files_sha256"][name]:
            raise ValueError(f"snapshot_integrity_failed:{name}")
    records = json.loads((directory / "records.json").read_text(encoding="utf-8"))
    return manifest, {row["url"]: row for row in records}


def write_legacy_projections(batch, base):
    """舊工具相容投影：根目錄 urls.txt / ground_truth.csv / active_batch.json。

    新管線一律從批次快照取逐列來源；這三個檔只給舊工具與「直接跑 main.py」的路徑用。
    urls.txt 寫原始 LF 位元組 —— Windows 的 write_text 會換成 CRLF。
    """
    base = Path(base)
    _, records = load_batch(batch)
    (base / "urls.txt").write_bytes((Path(batch) / "urls.txt").read_bytes())
    with (base / "ground_truth.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=["url", "label", "source_label", "source",
                                                    "batch_id", "fetched_at"])
        writer.writeheader()
        writer.writerows({key: row[key] for key in writer.fieldnames} for row in records.values())
    (base / "active_batch.json").write_text(json.dumps({"path": str(Path(batch).resolve())}),
                                            encoding="utf-8")
    return records


def select_active_batch(urls_file, pointer):
    """根目錄 urls.txt 與 active_batch.json 指向的快照一致時回傳該批次路徑，否則 None。

    只容許換行字元差異（LF/CRLF）：URL 文字、順序或內容任何改動都不得沿用舊來源，
    否則手動改過的清單會被貼上舊 batch 的 source_label。
    """
    urls_file, pointer = Path(urls_file), Path(pointer)
    if not pointer.exists() or not urls_file.exists():
        return None
    batch_path = Path(json.loads(pointer.read_text(encoding="utf-8"))["path"])
    if urls_file.read_text(encoding="utf-8") != (batch_path / "urls.txt").read_text(encoding="utf-8"):
        return None
    return batch_path
