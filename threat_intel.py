"""外部信譽查詢（GSB / VirusTotal / urlscan）—— 獨立工具，不在管線內。"""
import sys as _sys
import os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import os
import time
import threading

import requests


# ── VirusTotal 節流 ───────────────────────────────────────────
# 免費版限制 4 requests/min → 兩次呼叫至少間隔 15 秒。
# time.sleep(1) 是不夠的（那是 60 req/min 的節奏），會吃 429。
# 用模組級 lock 保護，批次並行（main.py ThreadPoolExecutor）時也不會超標。
_VT_MIN_INTERVAL = 15.0
_VT_LOCK = threading.Lock()
_VT_LAST = 0.0


def _vt_throttle():
    global _VT_LAST
    with _VT_LOCK:
        wait = _VT_LAST + _VT_MIN_INTERVAL - time.time()
        if wait > 0:
            time.sleep(wait)
        _VT_LAST = time.time()


# ─────────────────────────────────────────────────────────────
#  ① Google Safe Browsing v4
# ─────────────────────────────────────────────────────────────

_GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_google_safe_browsing(url: str) -> dict:
    key = os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "")
    if not key:
        return {"verdict": "skipped", "detail": "未設定 GOOGLE_SAFEBROWSING_API_KEY"}

    body = {
        "client": {"clientId": "phishcloak-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    r = requests.post(_GSB_ENDPOINT, params={"key": key}, json=body, timeout=15)
    r.raise_for_status()
    matches = r.json().get("matches", [])
    if matches:
        types = sorted({m.get("threatType", "?") for m in matches})
        return {"verdict": "malicious", "detail": ",".join(types)}
    return {"verdict": "clean", "detail": ""}


# ─────────────────────────────────────────────────────────────
#  ② VirusTotal（vt-py）
# ─────────────────────────────────────────────────────────────

def check_virustotal(url: str) -> dict:
    key = os.getenv("VT_API_KEY", "")
    if not key:
        return {"verdict": "skipped", "detail": "未設定 VT_API_KEY"}
    try:
        import vt
    except ImportError:
        return {"verdict": "error",
                "detail": "vt-py 未安裝：pip install ./vt-py-0.22.0 或 pip install vt-py"}

    _vt_throttle()
    with vt.Client(key) as client:
        try:
            obj = client.get_object("/urls/{}", vt.url_id(url))
        except vt.APIError as e:
            if e.code == "NotFoundError":
                # ponytail: 只查不提交。URLhaus feed 的 URL 幾乎都已在 VT 資料庫；
                # 需要主動送掃時再加 client.scan_url(url, wait_for_completion=True)
                return {"verdict": "unknown", "detail": "VT 無此 URL 紀錄"}
            raise

    stats = obj.last_analysis_stats  # {'malicious': n, 'suspicious': n, 'harmless': n, ...}
    mal, susp = stats.get("malicious", 0), stats.get("suspicious", 0)
    detail = f"{mal} malicious / {susp} suspicious"
    if mal >= 2:                       # 單一引擎誤報常見，2 家以上才視為確定
        return {"verdict": "malicious", "detail": detail}
    if mal + susp >= 1:
        return {"verdict": "suspicious", "detail": detail}
    return {"verdict": "clean", "detail": detail}


# ─────────────────────────────────────────────────────────────
#  ③ urlscan.io
# ─────────────────────────────────────────────────────────────

def check_urlscan(url: str) -> dict:
    key = os.getenv("URLSCAN_API_KEY", "")
    headers = {"API-Key": key} if key else {}

    # 先搜既有掃描（免費、即回），沒有才提交新掃描（需 key，約 10-30 秒）
    r = requests.get(
        "https://urlscan.io/api/v1/search/",
        params={"q": f'page.url:"{url}" OR task.url:"{url}"', "size": 1},
        headers=headers, timeout=15,
    )
    r.raise_for_status()
    results = r.json().get("results", [])

    if results:
        # 既有掃描：結果一次就能拿到，拿不到代表已被 urlscan 清除（過期）
        rr = requests.get(f"https://urlscan.io/api/v1/result/{results[0]['_id']}/",
                          headers=headers, timeout=15)
        if rr.status_code != 200:
            return {"verdict": "unknown", "detail": "既有掃描結果已過期"}
        return _urlscan_verdict(rr.json())

    if not key:
        return {"verdict": "unknown",
                "detail": "無既有掃描；設定 URLSCAN_API_KEY 可提交新掃描"}
    sub = requests.post(
        "https://urlscan.io/api/v1/scan/",
        headers={**headers, "Content-Type": "application/json"},
        json={"url": url, "visibility": "unlisted"}, timeout=15,
    )
    if sub.status_code == 400:
        # urlscan 拒掃（黑名單網域 / 無法解析等）
        return {"verdict": "error",
                "detail": sub.json().get("message", "scan rejected")[:120]}
    sub.raise_for_status()
    uuid = sub.json()["uuid"]

    # 新掃描約需 10-30 秒才有結果，輪詢至多 90 秒
    deadline = time.time() + 90
    while time.time() < deadline:
        time.sleep(10)
        rr = requests.get(f"https://urlscan.io/api/v1/result/{uuid}/",
                          headers=headers, timeout=15)
        if rr.status_code == 200:
            return _urlscan_verdict(rr.json())
    return {"verdict": "unknown", "detail": "掃描結果逾時未就緒"}


def _urlscan_verdict(data: dict) -> dict:
    overall = data.get("verdicts", {}).get("overall", {})
    score = overall.get("score", 0)
    if overall.get("malicious"):
        cats = ",".join(overall.get("categories", [])) or f"score={score}"
        return {"verdict": "malicious", "detail": cats}
    if score and score > 0:
        return {"verdict": "suspicious", "detail": f"score={score}"}
    return {"verdict": "clean", "detail": f"score={score}"}


# ─────────────────────────────────────────────────────────────
#  Node 0
# ─────────────────────────────────────────────────────────────

_VENDORS = [
    ("google_safe_browsing", check_google_safe_browsing),
    ("virustotal",           check_virustotal),
    ("urlscan",              check_urlscan),
]


def check_url(url: str) -> dict:
    """查詢三個外部信譽來源，彙整成 {"vendors", "overall", "hits"}。

    這**不是管線的一部分**。外部情資是在回答「是不是釣魚站」，而本系統量的是
    cloaking，所以它已從 graph 移除。留著這個檔案是因為它有另一個用途：
    驗證清單的標籤是否還成立。PhiUSIIL 的標記是 2024 年的狀態，
    「當年是釣魚站」不等於「現在還是釣魚站」；要主張某批 URL 現在仍是釣魚站，
    就需要一個獨立於受測系統之外的來源來背書。

    絕不可把這個結果餵回管線當判定 —— 那會讓量測對象與量測工具混在一起。
    """
    vendors = {}
    for name, fn in _VENDORS:
        try:
            vendors[name] = fn(url)
        except Exception as e:
            vendors[name] = {"verdict": "error", "detail": str(e)[:200]}

    hits = [f"{n}: {v['detail'] or 'malicious'}"
            for n, v in vendors.items() if v["verdict"] == "malicious"]
    verdicts = {v["verdict"] for v in vendors.values()}

    # 「clean」必須由真的掃過的來源背書，不能由黑名單的「查無此筆」冒充。
    #
    # 三個來源的 clean 不等值：
    #   GSB 是黑名單 —— 沒收錄只代表「還沒被列入」，clean 不代表掃過。
    #   VirusTotal / urlscan 有實際掃描結果（0/90 引擎命中、score=0），
    #     這才是「檢查過而且沒發現問題」。
    #
    # 舊寫法只要任何一家回 clean 就標 clean，於是「GSB 尚未列入 + 其餘兩家
    # 沒資料」會輸出 clean，讀起來像三家都背書過。剛上線的釣魚站正是這個樣子。
    _SCANNERS = ("virustotal", "urlscan")
    scanned_clean = any(vendors.get(n, {}).get("verdict") == "clean" for n in _SCANNERS)
    overall = ("malicious" if hits
               else "suspicious" if "suspicious" in verdicts
               else "clean" if scanned_clean
               else "unknown")

    return {"vendors": vendors, "overall": overall, "hits": hits}


if __name__ == "__main__":
    import llm  # noqa: F401  import 的副作用是 load_dotenv，讀出三把 API key
    import sys

    if len(sys.argv) > 1:
        for u in sys.argv[1:]:
            r = check_url(u)
            print(f"{r['overall']:10} {u}")
            for name, v in r["vendors"].items():
                print(f"    {name:22} {v['verdict']:10} {v['detail'][:60]}")
    else:
        # 自我檢查：GSB 官方測試 URL 必須被判 malicious（需已設定 API key）
        res = check_google_safe_browsing(
            "http://testsafebrowsing.appspot.com/s/phishing.html")
        print(f"GSB self-check: {res}")
        assert res["verdict"] in ("malicious", "skipped"), res
        print("OK — 帶 URL 參數可查詢：python threat_intel.py <url> [<url> ...]")
