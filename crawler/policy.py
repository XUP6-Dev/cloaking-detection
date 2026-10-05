"""請求邊界：哪些網址、方法、資源類型可以送出。

這是安全控制，不是規避手段：目的是讓觀察只「讀取」，且不被頁面拿來打內網。
政策只由啟動程序的設定決定 —— feed、頁面內容、LLM 輸出都不能改它。

範圍（CRAWL_SCOPE）：
  passive          真實目標。只允許解析結果全為公網位址的主機（擋 loopback／私有網段）。
  local_test       只允許 loopback 上、與起始網址同 origin 的請求（本機 testbed）。
  authorized_test  只允許 AUTHORIZED_TEST_ORIGINS 內、與起始網址同 origin 的請求，
                   且必須有非空的 TEST_AUTHORIZATION（授權紀錄或工單參照）。

已知限制：DNS 檢查與實際連線之間有時間差（rebinding），程式層無法消除；正式量測應在
獨立 VM 並以出口防火牆阻擋私有網段。GET 端點也可能有伺服器端副作用 —— 本工具只能
約束自己送出的請求種類，不能保證任意伺服器是純讀取。
"""
import ipaddress
import json
import os
import socket
from urllib.parse import urlsplit

from feeds.urls import normalize_url, origin

SCOPES = ("passive", "local_test", "authorized_test")
READ_METHODS = ("GET", "HEAD")
# JS 開啟後頁面會自己發請求。GET/HEAD 的 xhr/fetch 視同載入資源；下列類型是持續的
# 雙向通道或純送出（beacon），不論方法一律阻擋 —— 它們只會把資料往外送。
ALWAYS_BLOCKED_TYPES = ("websocket", "eventsource", "ping")
# 這些類型被擋或失敗時，判定用頁面可能少了內容，「未檢出」就不能成立；
# 圖片、字型、樣式、子框架失敗只記錄 —— φ 讀的是 HTML/JS 文字，不受它們影響。
CONTENT_AFFECTING_TYPES = ("document", "script", "xhr", "fetch", "websocket", "eventsource")


def permitted_url(url, scope, initial_url, cache=None):
    """這個網址在此範圍內可否請求。cache（dict）只在單次觀察內重用 DNS 結果。"""
    try:
        normalized = normalize_url(url)
        host = urlsplit(normalized).hostname
        if scope == "local_test":
            return (host in ("127.0.0.1", "::1", "localhost")
                    and origin(normalized) == origin(initial_url))
        if scope == "authorized_test":
            allowed = json.loads(os.environ.get("AUTHORIZED_TEST_ORIGINS", "[]"))
            return (isinstance(allowed, list) and bool(os.environ.get("TEST_AUTHORIZATION"))
                    and origin(initial_url) in allowed and origin(normalized) == origin(initial_url))
        if scope != "passive":
            return False
        if cache is not None and host in cache:
            return cache[host]
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ok = bool(addresses) and all(ipaddress.ip_address(a[4][0]).is_global for a in addresses)
        if cache is not None:
            cache[host] = ok
        return ok
    except (ValueError, OSError, TypeError):
        return False


def block_reason(*, url, method, resource_type, initial_url, scope,
                 subframe_navigation=False, request_count=0, max_requests=None, cache=None):
    """回傳阻擋理由；空字串 = 放行。Playwright route 與 CDP 逐跳攔截共用這一個判斷。"""
    if method not in READ_METHODS:
        return "non_read_method"
    if resource_type in ALWAYS_BLOCKED_TYPES:
        return "persistent_or_beacon_channel"
    if subframe_navigation:
        return "secondary_navigation_blocked"
    if max_requests is not None and request_count > max_requests:
        return "request_budget_exceeded"
    if not permitted_url(url, scope, initial_url, cache):
        return "request_outside_scope"
    return ""


def content_affecting(resource_type, *, reason="", subframe=False):
    """被擋／失敗的請求是否可能讓判定用頁面缺內容。

    看資源類型而不看方法：POST 的 beacon（ping）不回傳內容，不算；POST 的 xhr/fetch
    可能正是取回表單的那一支，算。子框架內容不在主框架 DOM 裡，不算。
    """
    if subframe or reason == "secondary_navigation_blocked":
        return False
    return reason == "request_budget_exceeded" or resource_type in CONTENT_AFFECTING_TYPES
