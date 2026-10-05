"""基準 HTTP 觀察：requests 直接 GET，不執行 JavaScript。

取得 HTTP 狀態、每一跳的請求／回應標頭、導向鏈、主文件 HTML、內嵌 JavaScript 與外部
腳本網址。外部腳本**不另外下載**：那會讓不可信 HTML 決定額外請求哪些網址；瀏覽器端
本來就會載入它們，內容由瀏覽器觀察取得。

導向逐跳手動跟隨，每一跳送出前都經過 crawler/policy 的範圍檢查（擋內網位址）。
"""
import time
from importlib.metadata import version
from urllib.parse import urljoin

import requests

from crawler import policy
from crawler.profiles import BASELINE
from crawler.records import (fill_document, is_document_type, new_record, observation_issues,
                             save_record_json, write_artifact)
from schemas.evidence import utc_now

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def classify_error(exc):
    """把 requests 例外歸成可統計的類別；原始訊息另存在 error 欄。"""
    text = repr(exc)
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        if "NameResolutionError" in text or "getaddrinfo" in text or "Name or service not known" in text:
            return "dns"
        if any(s in text for s in ("RemoteDisconnected", "ConnectionResetError", "Connection aborted")):
            return "connection_reset"
        return "connection"
    if isinstance(exc, (requests.exceptions.InvalidURL, requests.exceptions.MissingSchema,
                        requests.exceptions.InvalidSchema)):
        return "invalid_url"
    return "other"


def _read_body(response, limit):
    chunks, size, truncated = [], 0, False
    for chunk in response.iter_content(65536):   # 已依 Content-Encoding 解壓
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            truncated = True
            break
    return b"".join(chunks)[:limit], truncated


def fetch(url, *, profile=None, scope="passive", meta=None, save_artifacts=True):
    profile = profile or BASELINE
    record = new_record("http_baseline", url, profile)
    record.update(meta or {})
    record["client"] = {"name": "requests", "version": version("requests"),
                        "urllib3": version("urllib3")}
    start, current, dns_cache, body = time.monotonic(), url, {}, None
    headers = profile.headers(url)
    try:
        with requests.Session() as session:
            session.trust_env = False           # 不讀環境 proxy／netrc：出口與瀏覽器相同
            for hop in range(profile.max_redirects + 1):
                if not policy.permitted_url(current, scope, url, dns_cache):
                    record["error"], record["error_kind"] = "request_outside_scope", "request_outside_scope"
                    break
                response = session.get(current, headers=headers, allow_redirects=False, stream=True,
                                       timeout=(profile.connect_timeout_s, profile.read_timeout_s),
                                       verify=profile.verify_tls)
                with response:
                    entry = {"url": current, "status": response.status_code,
                             "headers": dict(response.headers), "observed_at": utc_now(),
                             "request": {"method": "GET", "headers": dict(response.request.headers)}}
                    record["navigation_responses"].append(entry)
                    if hop == 0:
                        record["request_headers"] = dict(response.request.headers)
                    location = response.headers.get("Location")
                    if response.status_code in _REDIRECT_STATUSES and location:
                        current = urljoin(current, location)
                        continue
                    record.update(status_code=response.status_code, final_url=current,
                                  response_headers=dict(response.headers))
                    content_type = response.headers.get("Content-Type", "")   # 不分大小寫
                    if is_document_type(content_type):
                        body, record["truncated"] = _read_body(response, profile.max_body_bytes)
                    else:
                        # 檔案下載（壓縮檔、執行檔…）：不讀內容、不存檔，只記錄類型
                        body, record["non_html_content"] = None, True
                        record["content_type"] = content_type
                    break
            else:
                record["error"], record["error_kind"] = "too_many_redirects", "too_many_redirects"
        record["redirect_chain"] = [entry["url"] for entry in record["navigation_responses"]]
        if record["status_code"] and body is not None:
            fill_document(record, body, content_type, profile.max_analysis_chars)
            if save_artifacts:
                write_artifact(record, "raw.html", body)
    except requests.RequestException as exc:
        record["error"], record["error_kind"] = f"{type(exc).__name__}: {exc}"[:500], classify_error(exc)
        record["redirect_chain"] = [entry["url"] for entry in record["navigation_responses"]]
    record["finished_at"] = utc_now()
    record["fetch_time_sec"] = round(time.monotonic() - start, 3)
    record["observation_issues"] = observation_issues(record)
    if save_artifacts:
        save_record_json(record)
    return record
