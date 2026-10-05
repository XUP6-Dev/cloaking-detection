"""Node 0：驗證網址。不發任何請求 —— 可不可達由 Node 1 的實際觀察決定。"""
from feeds.urls import normalize_url


def liveness_node(state):
    try:
        normalize_url(state["url"])
        state["alive"] = True
        state["liveness_reason"] = "pending_observation"
    except ValueError as exc:
        state["alive"] = False
        state["errors"] = state.get("errors", []) + [str(exc)]
        state["phishing_reason"] = state["cloaking_reason"] = str(exc)
    return state


def is_alive(url):
    """相容介面（build_urls.py）：一次基準 HTTP 觀察是否收到任何 HTTP 回應。"""
    from crawler.http_baseline import fetch
    return bool(fetch(url, save_artifacts=False).get("status_code"))
