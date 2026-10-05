"""Playwright 瀏覽器觀察：原生 headless Chromium，執行 JavaScript，不做任何互動。

保存兩層內容：
  html      主文件回應（JS 執行前）—— 與基準 HTTP 的 html 同一層，cloaking 比較用
  dom_html  load + settle 之後的 DOM —— 釣魚判定與 JS 行為訊號用
另外保存 DOMContentLoaded 時的 DOM 快照（量延遲載入）、HTTP 導向鏈與之後的前端導向、
子資源、同主機外部腳本內容、主控台錯誤、頁面例外、失敗與被擋的請求、對話框、下載、新視窗。

以下是安全控制而非規避手段：只放行 GET/HEAD；websocket/eventsource/beacon 一律擋；
子框架導覽擋；每一跳（含 HTTP 導向）送出前檢查範圍；請求數上限；拒絕下載；新視窗立即
關閉；對話框自動關閉；不授予任何權限；不點擊、不輸入、不捲動、不提交。
"""
import asyncio
import os
import time
from importlib.metadata import version

from crawler import policy
from crawler.profiles import BROWSER
from crawler.records import (decode_body, fill_document, is_document_type, new_record,
                             observation_issues, save_record_json, summarize_html, write_artifact)
from feeds.urls import host_of
from schemas.evidence import sha256, utc_now

# Playwright 官方的 "0" 模式：瀏覽器放在 .venv 的套件旁，IDE 與命令列看見同一份。
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "0")
LAUNCH_ARGS = ["--no-proxy-server"]
HARD_TIMEOUT_S = 90
MAX_EVENTS = 200


def classify_error(message):
    text = message or ""
    if "Timeout" in text or "timeout" in text:
        return "timeout"
    if "ERR_NAME_NOT_RESOLVED" in text:
        return "dns"
    if "ERR_CERT" in text or "SSL" in text:
        return "tls"
    if "ERR_HTTP2_PROTOCOL_ERROR" in text:
        return "protocol_error"
    if "ERR_BLOCKED_BY_CLIENT" in text or "request_outside_scope" in text:
        return "blocked_by_policy"
    if "Download is starting" in text:
        return "download"
    if "ERR_CONNECTION" in text or "ERR_EMPTY_RESPONSE" in text:
        return "connection"
    return "other"


def _subframe_navigation(request, page):
    """非主框架的導覽。frame 尚未建立的導覽（例如新視窗的第一個請求）Playwright 會拋例外，
    那種一律當成非主框架 —— route 回呼裡拋例外會讓請求懸著不放行也不中止。"""
    if not request.is_navigation_request():
        return False
    try:
        return request.frame != page.main_frame
    except Exception:
        return True


async def _settled_content(page, attempts=3):
    """前端導向進行中時 content() 會失敗；稍等重試，仍失敗就拋出。"""
    for attempt in range(attempts):
        try:
            return await page.content()
        except Exception:
            if attempt == attempts - 1:
                raise
            await page.wait_for_timeout(500)


async def _observe(url, profile, scope, record, payloads):
    from playwright.async_api import TimeoutError as PlaywrightTimeout, async_playwright
    if not policy.permitted_url(url, scope, url):
        record["error"] = record["error_kind"] = "request_outside_scope"
        return
    dns_cache, seen_blocks, blocked_urls, counter = {}, set(), set(), {"requests": 0}
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True, chromium_sandbox=True,
                                           args=LAUNCH_ARGS, timeout=30000)
        record["browser_version"] = browser.version
        record["client"] = {"name": "chromium", "version": browser.version,
                            "playwright_version": record["playwright_version"]}
        try:
            context = await browser.new_context(**profile.context_options())
            page = await context.new_page()

            def note_block(target, method, kind, reason, subframe=False):
                if (target, method, reason) in seen_blocks:
                    return
                seen_blocks.add((target, method, reason))
                blocked_urls.add(target)
                if len(record["blocked_requests"]) < MAX_EVENTS:
                    record["blocked_requests"].append({
                        "url": target, "method": method, "type": kind, "reason": reason,
                        "content_affecting": policy.content_affecting(kind, reason=reason, subframe=subframe)})

            async def guard(route):
                request = route.request
                subframe = _subframe_navigation(request, page)
                reason = policy.block_reason(url=request.url, method=request.method,
                                             resource_type=request.resource_type, initial_url=url,
                                             scope=scope, subframe_navigation=subframe, cache=dns_cache)
                if reason:
                    note_block(request.url, request.method, request.resource_type, reason, subframe)
                    await route.abort("blockedbyclient")
                else:
                    await route.continue_()

            async def close_socket(websocket_route):
                note_block(websocket_route.url, "GET", "websocket", "persistent_or_beacon_channel")
                await websocket_route.close()

            await context.route("**/*", guard)
            await context.route_web_socket("**/*", close_socket)
            # Playwright 的 route 只看得到導向鏈的第一個請求；Chromium 的 request-stage
            # 攔截在每一跳送出前都檢查一次（不替換瀏覽器的傳輸層或標頭）。
            cdp = await context.new_cdp_session(page)

            async def guard_every_hop(event):
                counter["requests"] += 1
                request, kind = event["request"], event.get("resourceType", "").lower()
                reason = policy.block_reason(url=request["url"], method=request["method"],
                                             resource_type=kind, initial_url=url, scope=scope,
                                             request_count=counter["requests"],
                                             max_requests=profile.max_requests, cache=dns_cache)
                try:
                    if reason:
                        note_block(request["url"], request["method"], kind, reason)
                        await cdp.send("Fetch.failRequest", {"requestId": event["requestId"],
                                                             "errorReason": "BlockedByClient"})
                    else:
                        await cdp.send("Fetch.continueRequest", {"requestId": event["requestId"]})
                except Exception:
                    record.setdefault("observation_notes", []).append("interception_error")

            cdp.on("Fetch.requestPaused", guard_every_hop)
            await cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})

            async def on_dialog(dialog):
                record["dialogs"].append({"type": dialog.type, "message": dialog.message[:200]})
                await dialog.dismiss()

            async def on_popup(popup):
                record["popups"].append(popup.url)
                await popup.close()

            def on_console(message):
                if message.type == "error" and len(record["console_errors"]) < 50:
                    record["console_errors"].append(message.text[:500])

            def on_page_error(error):
                if len(record["page_errors"]) < 50:
                    record["page_errors"].append(str(error)[:500])

            def on_failed(request):
                if request.url in blocked_urls:      # 自己擋的，已記在 blocked_requests
                    return
                subframe = _subframe_navigation(request, page)
                if len(record["failed_requests"]) < MAX_EVENTS:
                    record["failed_requests"].append({
                        "url": request.url, "type": request.resource_type, "method": request.method,
                        "failure": request.failure or "",
                        "content_affecting": policy.content_affecting(request.resource_type, subframe=subframe)})

            navigations, script_responses = [], []

            def on_response(response):
                request = response.request
                if len(record["subresources"]) < MAX_EVENTS:
                    record["subresources"].append({"url": response.url, "type": request.resource_type,
                                                   "method": request.method, "status": response.status})
                if request.resource_type == "script" and response.ok and len(script_responses) < 50:
                    script_responses.append(response)
                if request.is_navigation_request() and not _subframe_navigation(request, page):
                    navigations.append({"url": response.url, "status": response.status,
                                        "observed_at": utc_now()})

            page.on("dialog", on_dialog)
            page.on("popup", on_popup)
            page.on("console", on_console)
            page.on("pageerror", on_page_error)
            page.on("requestfailed", on_failed)
            page.on("download", lambda download: record["downloads"].append(download.url))
            page.on("response", on_response)

            # ── 主文件：commit 時就取回應，JS 還沒機會改寫或導走 ──────
            response = await page.goto(url, timeout=profile.navigation_timeout_ms, wait_until="commit")
            if response is None:
                raise RuntimeError("no_navigation_response")
            chain, request = [], response.request
            while request is not None:
                chain.append(request)
                request = request.redirected_from
            chain.reverse()
            for hop in chain:
                hop_response = await hop.response()
                record["navigation_responses"].append({
                    "url": hop.url, "status": hop_response.status if hop_response else 0,
                    "headers": await hop_response.all_headers() if hop_response else {},
                    "observed_at": utc_now(),
                    "request": {"method": hop.method, "headers": await hop.all_headers()}})
            record["request_headers"] = record["navigation_responses"][0]["request"]["headers"]
            record["redirect_chain"] = [hop.url for hop in chain]
            record.update(status_code=response.status, final_url=response.url,
                          response_headers=await response.all_headers())
            content_type = record["response_headers"].get("content-type", "")
            if not is_document_type(content_type):
                record["non_html_content"], record["content_type"] = True, content_type
            else:
                try:
                    payloads["raw.html"] = await response.body()
                except Exception as exc:
                    record["document_body_error"] = f"{type(exc).__name__}: {exc}"[:300]

            # ── JS 執行後：DOMContentLoaded 快照 → load（上限內）→ settle 快照 ──
            await page.wait_for_load_state("domcontentloaded", timeout=profile.navigation_timeout_ms)
            dcl_html = await _settled_content(page)
            try:
                await page.wait_for_load_state("load", timeout=profile.load_timeout_ms)
            except PlaywrightTimeout:
                record["load_event"] = "timeout"     # 不算失敗：有些頁面的資源永遠載不完
            await page.wait_for_timeout(profile.settle_ms)
            dom_html = await _settled_content(page)
            record["page_url"] = page.url
            record["dom_title"] = await page.title()

            if "raw.html" in payloads:
                fill_document(record, payloads["raw.html"], content_type, profile.max_analysis_chars)
            limit = profile.max_analysis_chars
            record.update(dom_length=len(dom_html), dom_truncated=len(dom_html) > limit,
                          dom_html=dom_html[:limit], dom_domcontentloaded_html=dcl_html[:limit])
            record["dom_sha256"] = sha256(record["dom_html"])
            record["dom_text"] = summarize_html(record["dom_html"], record["page_url"])["text"]
            dcl_text = summarize_html(record["dom_domcontentloaded_html"])["text"]
            record["dom_snapshots"] = [
                {"at": "domcontentloaded", "sha256": sha256(record["dom_domcontentloaded_html"]),
                 "html_length": len(dcl_html), "text_length": len(dcl_text)},
                {"at": "settled", "sha256": record["dom_sha256"],
                 "html_length": len(dom_html), "text_length": len(record["dom_text"])}]
            payloads["dom.html"] = record["dom_html"]
            payloads["dom_domcontentloaded.html"] = record["dom_domcontentloaded_html"]
            # 主文件之後的主框架導覽 = 前端導向（meta refresh / JS）
            initial = len(chain) if [n["url"] for n in navigations[:len(chain)]] == record["redirect_chain"] else 0
            record["client_navigations"] = navigations[initial:] if initial else [
                n for n in navigations if n["url"] not in set(record["redirect_chain"])]

            # ── 同主機外部腳本：讀內容供去混淆與規則分析；第三方只記網址 ──
            page_host = host_of(record["page_url"]) or host_of(record["final_url"])
            fetched = 0
            for script in script_responses:
                entry = {"url": script.url, "status": script.status,
                         "first_party": host_of(script.url) == page_host}
                if entry["first_party"] and fetched < profile.max_external_scripts:
                    fetched += 1
                    try:
                        data = await script.body()
                    except Exception as exc:
                        entry["error"] = f"{type(exc).__name__}"
                    else:
                        entry.update(sha256=sha256(data), length=len(data))
                        if len(data) <= profile.max_script_bytes:
                            entry["content"] = decode_body(data, script.headers.get("content-type", ""))[0]
                record["external_scripts"].append(entry)

            try:   # 既有的截圖保存（供人工檢視；本版未新增影像分析）
                payloads["screenshot.png"] = await page.screenshot(timeout=5000, full_page=False)
            except Exception as exc:
                record["screenshot_error"] = f"{type(exc).__name__}: {exc}"[:300]
        finally:
            await asyncio.wait_for(browser.close(), timeout=8)


def fetch(url, *, profile=None, scope="passive", meta=None, save_artifacts=True):
    profile = profile or BROWSER
    record = new_record("browser", url, profile)
    record.update(meta or {})
    record["playwright_version"] = version("playwright")
    payloads, start = {}, time.monotonic()
    try:
        asyncio.run(asyncio.wait_for(_observe(url, profile, scope, record, payloads),
                                     timeout=HARD_TIMEOUT_S))
    except (Exception, asyncio.CancelledError) as exc:   # 逾時（TimeoutError）也記成觀察失敗
        if not record.get("error"):
            record["error"] = f"{type(exc).__name__}: {exc}"[:500]
            record["error_kind"] = classify_error(record["error"])
    record["finished_at"] = utc_now()
    record["fetch_time_sec"] = round(time.monotonic() - start, 3)
    record["observation_issues"] = observation_issues(record)
    if save_artifacts:
        for name, data in payloads.items():
            path = write_artifact(record, name, data)
            if name == "screenshot.png":
                record["screenshot_path"], record["screenshot_sha256"] = str(path), sha256(data)
        save_record_json(record)
    return record


def preflight():
    """整批開跑前確認 Chromium 能啟動；失敗就拋出含安裝指令的 RuntimeError。"""
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, chromium_sandbox=True,
                                                 args=LAUNCH_ARGS, timeout=30000)
            browser.close()
    except Exception as exc:
        detail = str(exc).splitlines()[0] if str(exc) else ""
        raise RuntimeError("Playwright Chromium 無法啟動；請在本專案執行 "
                           ".venv\\Scripts\\python.exe setup_playwright.py。"
                           f"原因：{type(exc).__name__}: {detail}") from exc
