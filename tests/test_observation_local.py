"""真的跑 requests 與 Playwright Chromium，但只對本機 loopback 的測試伺服器（CRAWL_SCOPE=local_test）。

伺服器依 User-Agent 分流，模擬「對非瀏覽器 client 給誘餌、對瀏覽器給釣魚頁」的 cloaking，
以及延遲載入、前端導向、寫入請求、越界導向、檔案下載等情境。不接觸任何真實網站。
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from analysis.cloaking import label_cloaking
from analysis.signals import compute_signals
from crawler import browser, http_baseline
from crawler.plan import ObservationSettings, observe_url

DECOY = b"<html><head><title>Docs</title></head><body><h1>Docs</h1><p>Nothing here.</p></body></html>"
PHISH = (b'<html><head><title>Docs</title></head><body><p>Sign in</p><form action="/unused">'
         b'<input type="password"></form><script>const e="https://api.telegram.org/never-requested";</script>'
         b"</body></html>")
# 表單只在 JS 執行 300ms 後用 DOM API 建出來：主文件裡沒有任何表單標記
DELAYED = (b"<html><head><title>Docs</title></head><body><p>Loading</p><div id=slot></div><script>"
           b"setTimeout(function(){var f=document.createElement('form');var i=document.createElement('input');"
           b"i.type='pass'+'word';i.name='p';f.appendChild(i);document.getElementById('slot').appendChild(f);}, 300);"
           b"</script></body></html>")
WRITES = (b"<html><body><p>Docs</p><script>fetch('/forbidden',{method:'POST',body:'x'});"
          b"fetch('/read-api');navigator.sendBeacon('/beacon','x');"
          b"try{new WebSocket('ws://127.0.0.1:9/ws')}catch(e){}</script></body></html>")


@pytest.fixture
def server():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, body, ctype="text/html; charset=utf-8", status=200):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            ua = self.headers.get("User-Agent", "")
            calls.append(("GET", self.path, ua))
            if self.path == "/redirect":
                self.send_response(302); self.send_header("Location", "/second-hop"); self.end_headers(); return
            if self.path == "/second-hop":
                self.send_response(307); self.send_header("Location", "/ua-split"); self.end_headers(); return
            if self.path == "/escape":
                self.send_response(302); self.send_header("Location", "http://external.invalid/"); self.end_headers()
                return
            pages = {"/ua-split": DECOY if "DefensiveMeasurement" in ua else PHISH, "/delayed": DELAYED,
                     "/writes": WRITES,
                     "/meta": b'<html><head><meta http-equiv="refresh" content="0;url=/plain"></head><body>x</body></html>',
                     "/plain": DECOY, "/read-api": b"{}",
                     "/popup": b"<html><body><p>Docs</p><script>window.open('/popup-target')</script></body></html>"}
            if self.path == "/download":
                return self._send(b"PK\x03\x04 not a real archive", "application/zip")
            self._send(pages.get(self.path, DECOY))

        def do_POST(self):
            calls.append(("POST", self.path, ""))
            self._send(b"", status=500)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_port}", calls
    srv.shutdown()
    srv.server_close()
    thread.join()


LOCAL = ObservationSettings(scope="local_test", crawl_order="bot_first")


def test_user_agent_cloaking_is_observed_and_labelled(server):
    base, calls = server
    result = observe_url(base + "/redirect", LOCAL)
    bot, human = result["bot"], result["human"]
    assert result["errors"] == [] and result["plan"] == "bot_first:B1,H1,B2,H2;variants="
    assert [r["status"] for r in bot["navigation_responses"]] == [302, 307, 200]
    assert [r["status"] for r in human["navigation_responses"]] == [302, 307, 200]
    assert [r["access_index"] for r in (bot, human, bot["confirmation"], human["confirmation"])] == [1, 2, 3, 4]
    assert "DefensiveMeasurement" in bot["request_headers"]["User-Agent"]
    assert "DefensiveMeasurement" not in human["request_headers"]["user-agent"], "瀏覽器維持原生 UA"
    assert bot["title"] == human["title"] == "Docs" and "never-requested" in human["html"]
    for rec in (bot, human):
        assert Path(rec["artifacts"]["raw.html"]).exists() and Path(rec["artifacts"]["record.json"]).exists()
    assert Path(human["screenshot_path"]).exists() and Path(human["artifacts"]["dom.html"]).exists()
    decision = label_cloaking(bot, human, base + "/redirect")
    assert decision["label"] == "true", decision["reasons"]
    signals = {s["id"]: s for s in compute_signals(bot, human)}
    assert signals["client_type_response_difference"]["status"] == "observed"
    assert signals["multi_hop_redirect"]["status"] == "observed"
    assert all(method == "GET" for method, _, _ in calls)


def test_browser_runs_js_and_records_delayed_content(server):
    base, _ = server
    rec = browser.fetch(base + "/delayed", scope="local_test")
    assert not rec["error"], rec["error"]
    # 主文件是 JS 執行前、DOM 是執行後
    assert BeautifulSoup(rec["html"], "html.parser").find("input") is None
    assert BeautifulSoup(rec["dom_html"], "html.parser").find("input", {"type": "password"}) is not None
    assert rec["dom_snapshots"][0]["sha256"] != rec["dom_snapshots"][1]["sha256"]
    other = http_baseline.fetch(base + "/delayed", scope="local_test")
    bot = {**other, "confirmation": dict(other)}
    human = {**rec, "confirmation": dict(rec)}
    signals = {s["id"]: s for s in compute_signals(bot, human)}
    assert signals["delayed_content"]["status"] == "observed"
    assert signals["js_modified_dom"]["status"] == "observed"
    decision = label_cloaking(bot, human, base + "/delayed")
    assert decision["rule_label"] == "false" and decision["label"] == "unknown"
    assert any("js_rendered_mechanisms_not_compared" in r for r in decision["reasons"])


def test_browser_blocks_writes_beacons_sockets_and_scope_escape(server):
    base, calls = server
    rec = browser.fetch(base + "/writes", scope="local_test")
    assert not rec["error"], rec["error"]
    reasons = {(r["reason"], r["content_affecting"]) for r in rec["blocked_requests"]}
    assert ("non_read_method", True) in reasons, rec["blocked_requests"]          # POST fetch
    assert ("non_read_method", False) in reasons or ("persistent_or_beacon_channel", False) in reasons
    assert not any(method == "POST" for method, _, _ in calls), "寫入請求不得送達伺服器"
    assert any(path == "/read-api" for _, path, _ in calls), "GET 的 fetch 視同載入資源，允許"
    escaped = browser.fetch(base + "/escape", scope="local_test")
    assert any(r["reason"] == "request_outside_scope" for r in escaped["blocked_requests"]) or escaped["error"]
    baseline = http_baseline.fetch(base + "/escape", scope="local_test")
    assert baseline["error"] == "request_outside_scope" and baseline["status_code"] == 0


def test_client_side_redirect_is_recorded(server):
    base, _ = server
    rec = browser.fetch(base + "/meta", scope="local_test")
    assert rec["final_url"].endswith("/meta") and rec["page_url"].endswith("/plain")
    bot = {**rec, "confirmation": dict(rec)}
    signals = {s["id"]: s for s in compute_signals(bot, bot)}
    assert signals["client_side_redirect"]["status"] == "observed"


def test_popups_are_closed_and_never_load(server):
    """新視窗立即關閉，且它的導覽被擋（不能藉新視窗載入任何東西）；觀察本身不懸住。"""
    base, calls = server
    rec = browser.fetch(base + "/popup", scope="local_test")
    assert not rec["error"], rec["error"]
    assert rec["popups"] or any(r["reason"] == "secondary_navigation_blocked" for r in rec["blocked_requests"])
    assert not any(path == "/popup-target" for _, path, _ in calls)
    assert "popup_closed" in rec["observation_issues"] or rec["blocked_requests"]


def test_downloads_are_never_stored(server):
    base, _ = server
    rec = http_baseline.fetch(base + "/download", scope="local_test")
    assert rec["status_code"] == 200 and rec.get("non_html_content")
    assert "raw.html" not in rec["artifacts"] and rec["html"] == ""
    assert "non_html_document" in rec["observation_issues"]
    page = browser.fetch(base + "/download", scope="local_test")
    assert page["error"] or page.get("non_html_content") or page["downloads"]
    assert "raw.html" not in page["artifacts"]


def test_passive_scope_refuses_loopback_targets():
    """真實目標的範圍只允許公網位址：不能被 feed 裡的網址拿來打本機或內網。"""
    rec = http_baseline.fetch("http://127.0.0.1:9/", scope="passive")
    assert rec["error"] == "request_outside_scope"
    page = browser.fetch("http://127.0.0.1:9/", scope="passive")
    assert page["error"] == "request_outside_scope"
