"""所有測試共用的隔離設定。

  * 禁止外部 DNS：只允許 loopback。任何程式路徑意外想連真實網站（包括釣魚網站）
    都會讓測試直接失敗 —— 測試資料只來自合成 HTML 與本機 HTTP server。
  * 證據檔、稽核 JSON、summary CSV 寫到 tmp_path，不汙染專案目錄。
  * 清掉會改變觀察設定的環境變數：開發者 session 殘留的 PAIR_MODE / CRAWL_ORDER 等
    不能讓測試在不同機器上得到不同結果。
  * 圖裡的模型實例一律 None（不呼叫任何真模型）。需要模型行為的測試自己傳替身。
"""
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_KNOBS = ("HUMAN_PROFILE", "PAIR_MODE", "CRAWL_ORDER", "CRAWL_SCOPE", "OBSERVATION_VARIANTS",
          "SAVE_PAIR_HTML", "AUTHORIZED_TEST_ORIGINS", "TEST_AUTHORIZATION", "EGRESS_LABEL")


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    import crawler.records as records
    import graph
    import nodes.node5_output as output
    import reporting.audit as audit
    for knob in _KNOBS:
        monkeypatch.delenv(knob, raising=False)
    monkeypatch.setattr(records, "ARTIFACT_ROOT", tmp_path / "observations")
    monkeypatch.setattr(audit, "AUDIT_ROOT", tmp_path / "audit")
    monkeypatch.setattr(output, "SESSION_CSV", tmp_path / "summary.csv")
    for name in ("llm_code", "llm_phish", "llm_cloak"):
        monkeypatch.setattr(graph, name, None)
    original = socket.getaddrinfo

    def loopback_only(host, *args, **kwargs):
        if host not in ("127.0.0.1", "localhost", "::1", None):
            raise AssertionError(f"test attempted external DNS: {host}")
        return original(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", loopback_only)
    return tmp_path
