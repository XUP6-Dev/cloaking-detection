"""Feed 匯入：正規化、不可變快照、來源標記、離線匯入、舊工具投影。全部離線。"""
import json
from pathlib import Path

import pytest

import cli
from feeds.phishunt import FEED_URL, SOURCE_LABEL, import_feed, snapshot
from feeds.snapshot import load_batch
from feeds.urls import normalize_url

FIXTURE = Path(__file__).parent / "fixtures" / "feed.txt"


def test_feed_snapshot_normalization_integrity_and_no_overwrite(tmp_path):
    raw = (b"HTTPS://EXAMPLE.invalid:443/a?q=1#x\nhttps://example.invalid/a/\njavascript:alert(1)\n"
           b"https://u:p@example.invalid/\nHTTPS://EXAMPLE.invalid:443/a?q=1#x\n")
    p = snapshot(raw, tmp_path, batch_id="batch-one")
    manifest, rows = load_batch(p)
    assert manifest["is_ground_truth"] is False and manifest["source"] == FEED_URL
    assert len(rows) == 2
    assert rows["https://example.invalid/a?q=1#x"]["raw_url"].startswith("HTTPS")
    assert all(r["source_label"] == SOURCE_LABEL == "phishunt_suspicious" for r in rows.values())
    assert all(r["label_semantics"] == "unverified_source_intelligence" for r in rows.values())
    assert len(json.loads((p / "rejected.json").read_text())) == 3
    with pytest.raises(FileExistsError):
        snapshot(raw, tmp_path, batch_id="batch-one")
    (p / "records.json").write_text("[]")
    with pytest.raises(ValueError, match="integrity"):
        load_batch(p)


@pytest.mark.parametrize("url", ["file:///c:/secret", "ftp://example.invalid", "https://x.invalid/\x00",
                                 "https://user@example.invalid", "https://x.invalid\\@y.invalid",
                                 "https://x.invalid:bad/"])
def test_reject_unsafe_url(url):
    with pytest.raises(ValueError):
        normalize_url(url)


def test_normalization_keeps_distinct_samples():
    """不合併 /x 與 /x/、不重排 query、不丟 fragment —— 合併會讓分母安靜縮水。"""
    assert normalize_url("https://a.invalid/x") != normalize_url("https://a.invalid/x/")
    assert normalize_url("https://a.invalid/?b=1&a=2").endswith("?b=1&a=2")
    assert normalize_url("https://a.invalid/#frag").endswith("#frag")


def test_offline_import_records_the_file_not_the_feed(tmp_path):
    """離線匯入不得謊稱是當日從 PhishHunt 取得：source 是檔案 URI。"""
    batch = import_feed(tmp_path, limit=10, input_path=FIXTURE)
    manifest, rows = load_batch(batch)
    assert manifest["source"].startswith("file:") and manifest["source_http"] == {"offline_input": True}
    assert manifest["fetched_at"] and manifest["normalization_version"]
    assert all(r["source"] == manifest["source"] and r["batch_id"] == manifest["batch_id"] for r in rows.values())


def test_v2_snapshots_remain_readable(tmp_path):
    """舊批次（schema 2.0、沒有 source_http）仍可驗證讀取，不需轉換。"""
    batch = snapshot(b"https://fixture.invalid/a\n", tmp_path, batch_id="old")
    manifest_path = batch / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.pop("source_http")
    manifest["schema_version"] = "2.0"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert list(load_batch(batch)[1]) == ["https://fixture.invalid/a"]


def test_fetch_feed_cli_keeps_snapshot_bytes_in_urls_file(tmp_path):
    cli.main(["fetch-feed", "1", "--input", str(FIXTURE), "--snapshot-root", str(tmp_path / "batches"),
              "--project-root", str(tmp_path)])
    batch = Path(json.loads((tmp_path / "active_batch.json").read_text(encoding="utf-8"))["path"])
    assert (tmp_path / "urls.txt").read_bytes() == (batch / "urls.txt").read_bytes()
    assert b"\r\n" not in (tmp_path / "urls.txt").read_bytes()
    assert "source_label" in (tmp_path / "ground_truth.csv").read_text(encoding="utf-8-sig")


def test_selected_batch_is_frozen_in_the_run(tmp_path):
    """之後的匯入不能改變已選定批次的逐列來源。"""
    batch = snapshot(b"https://fixture.invalid/a\n", tmp_path / "feeds", batch_id="frozen")
    run = cli.Run()
    urls = run.select_batch(batch)
    snapshot(b"https://different.invalid/b\n", tmp_path / "feeds", batch_id="later")
    assert run.initial_state(urls[0])["source_record"]["batch_id"] == "frozen"
    assert run.batch_manifest["manifest_sha256"]
