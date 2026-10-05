"""相容入口與研究不變量的鎖。

舊的命令列入口與公開函式名稱照常可用；φ 與 C1–C5 不得被順手修改；client 設定不得出現
偽裝或規避；評估與盲標工具的既有自檢照常通過。
"""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# φ 在 v2 的 nodes/page_mechanisms.py 的 SHA-256。要改 φ：同時改 schemas/versions.py 的
# RULE_VERSION 與 MEASUREMENT_VERSION 和這個值 —— 之前跑過的批次全部不可與之後合併。
PHI_SHA256_V2 = "776d79d1ce33a61a2b32eee3956b588c319fc3d71a944e78457c85a349eb0721"


def test_phi_is_byte_identical_to_v2():
    assert hashlib.sha256((ROOT / "analysis" / "page_mechanisms.py").read_bytes()).hexdigest() == PHI_SHA256_V2


def test_old_phi_import_path_is_the_same_module():
    import analysis.page_mechanisms as new
    import nodes.page_mechanisms as old
    assert old is new, "判準只能有一份：舊路徑必須是同一個模組物件，不是複本"


def test_main_and_fetch_feed_keep_public_names():
    import fetch_feed
    import main
    for name in ("_extract_result", "_empty_result", "_pair_meta", "_save_pair",
                 "select_batch", "analyze_url", "analyze_batch"):
        assert callable(getattr(main, name)), name
    for name in ("snapshot_feed", "load_batch", "fetch_feed", "main"):
        assert callable(getattr(fetch_feed, name)), name
    assert fetch_feed.FEED_URL == "https://phishunt.io/feed.txt"


def _python(*args, cwd=ROOT):
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", "LLM_PROVIDER": "none"}
    return subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", env=env, timeout=120)


def test_fetch_feed_entry_point_runs_offline(tmp_path):
    done = _python("fetch_feed.py", "1", "--input", str(ROOT / "tests" / "fixtures" / "feed.txt"),
                   "--snapshot-root", str(tmp_path / "batches"), "--project-root", str(tmp_path))
    assert done.returncode == 0, done.stderr
    assert (tmp_path / "urls.txt").exists() and (tmp_path / "active_batch.json").exists()


def test_main_and_cli_entry_points_parse():
    for args in (("main.py", "--help"), ("cli.py", "run", "--help"), ("cli.py", "--help")):
        done = _python(*args)
        assert done.returncode == 0, done.stderr
    assert "--batch" in _python("main.py", "--help").stdout


def test_node_level_compat_helpers():
    from nodes.node2_js_analyzer import Deobfuscator  # noqa: F401（舊路徑仍可 import）
    from nodes.node4_cloaking_analyzer import _detect_gates, _static_detect
    from nodes.node5_output import CLOAKING_UNKNOWN, FIELDNAMES, _cloaking_verdict
    click = "<button onclick=\"document.getElementById(1).style.display='block'\">x</button>"
    assert _detect_gates(click, ["click:continue"]) == ["click_gate"], "跨閘門的宣稱不得清除閘門"
    assert _detect_gates('<div class="g-recaptcha"></div>', ["dialog_auto_accept"]) == ["captcha"]
    detected, techniques = _static_detect(
        {"deobfuscated_js": [{"deobfuscated": "if (navigator.webdriver) { location.href = 'http://x'; }"}],
         "raw_html": ""}, None)
    assert detected and techniques["static_rule"]
    assert [_cloaking_verdict({"cloaking_label": v}) for v in ("true", "false", "unknown")] == \
        [True, False, CLOAKING_UNKNOWN]
    assert CLOAKING_UNKNOWN == "N/A" and FIELDNAMES[:4] == ["url", "alive", "is_phishing", "cloaking"]


def test_profiles_are_standard_and_never_disguised(monkeypatch):
    import crawler.browser as browser_module
    from crawler.plan import ObservationSettings
    from crawler.profiles import BASELINE, BROWSER, VARIANT_PROFILES, profile_for
    assert profile_for(False) is BASELINE and profile_for(True) is BROWSER
    for profile in (BROWSER, VARIANT_PROFILES["mobile"]):
        opts = profile.context_options()
        assert not {"user_agent", "extra_http_headers", "proxy", "permissions"} & set(opts)
        assert opts["service_workers"] == "block" and opts["accept_downloads"] is False
        assert opts["ignore_https_errors"] is False and opts["java_script_enabled"] is True
    assert "DefensiveMeasurement" in BASELINE.user_agent and "Referer" not in BASELINE.headers("https://a.invalid/x")
    assert VARIANT_PROFILES["referer"].headers("https://a.invalid/x")["Referer"] == "https://a.invalid/"
    for name in ("_STEALTH_JS", "_BOT_EXPOSE_JS", "_cross_gates", "prewarm"):
        assert not hasattr(browser_module, name), name
    monkeypatch.setenv("HUMAN_PROFILE", "jp-mobile")
    with pytest.raises(ValueError, match="retired"):
        profile_for(True)
    with pytest.raises(ValueError, match="retired"):
        ObservationSettings.from_env()


@pytest.mark.parametrize("pair_mode,expected", [("bot_human", ("http_baseline", "browser")),
                                                ("human_human", ("browser", "browser")),
                                                ("bot_bot", ("http_baseline", "http_baseline"))])
def test_dual_crawl_assigns_by_slot_not_by_order(monkeypatch, pair_mode, expected):
    """依「槽」而非「先後」指派：接錯的話 human − bot 的方向會整個反過來，而且沒有錯誤訊息。"""
    import crawler.plan as plan
    seen = []

    def fake(kind, url, *, profile=None, scope="passive", meta=None):
        seen.append(kind)
        return {"kind": kind, "error": None, **(meta or {})}
    monkeypatch.setattr(plan, "fetch_observation", fake)
    monkeypatch.setenv("CRAWL_ORDER", "human_first")
    monkeypatch.setenv("PAIR_MODE", pair_mode)
    bot, human, errors = plan.dual_crawl("https://fixture.invalid/")
    assert (bot["kind"], human["kind"]) == expected and not errors
    assert seen == [expected[1], expected[0], expected[1], expected[0]]
    assert (human["access_index"], bot["access_index"]) == (1, 2)
    assert bot["confirmation"]["replicate"] == human["confirmation"]["replicate"] == 2


def test_evaluate_reports_cohorts_and_refuses_to_pool(capsys):
    import evaluate
    evaluate._selfcheck()      # label 優先序與三種盛行率的不變式（CLAUDE.md）
    v2 = {"schema_version": "2.0", "measurement_version": "passive-v2", "source_label": "phishunt_suspicious",
          "phishing_verdict": "unknown", "cloaking_label": "unknown"}
    evaluate.report_v2([v2])
    assert "unknown" in capsys.readouterr().out
    with pytest.raises(ValueError):
        evaluate.report_v2([v2, {**v2, "measurement_version": "dual-observation-v3", "schema_version": "3.0"}])
    v3 = {**v2, "schema_version": "3.0", "measurement_version": "dual-observation-v3", "alive": "True",
          "rule_cloaking_label": "true", "cloaking_label": "unknown", "llm_cloaking_assessment": "unavailable",
          "cloaking_signals": "client_type_response_difference",
          "uncertainty_reasons": json.dumps({"phishing": [], "cloaking": ["human#2:crawl_error"]})}
    evaluate.report_cohorts([v3])
    out = capsys.readouterr().out
    assert "crawl_error" in out and "client_type_response_difference" in out and "不是釣魚網站母體盛行率" in out


def test_annotation_tools_selfchecks_still_hold():
    import annotate
    import score_annotations
    annotate._selfcheck()          # 盲標頁不洩漏判定、抽樣可重現、srcdoc 轉義
    score_annotations._selfcheck()  # precision 與 κ 的手算一致
