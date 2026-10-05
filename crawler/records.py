"""觀察紀錄：建立、解碼、摘要、品質分級、證據檔案。

兩種 client（基準 HTTP、瀏覽器）都經過這裡的同一組函式解碼與摘要 —— 比較的前提是
兩邊用同一把尺切出文字、標題與腳本清單。欄位定義見 schemas/records.py。
"""
import json
import re
import uuid
from pathlib import Path
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from schemas.evidence import sha256, utc_now
from schemas.versions import MEASUREMENT_VERSION

ARTIFACT_ROOT = Path(__file__).resolve().parents[1] / "observations"
MAX_INLINE_SCRIPTS = 30
MAX_INLINE_SCRIPT_CHARS = 60000

# ── 品質分級 ─────────────────────────────────────────────────────
# 阻斷：根本沒有可判讀的文件 → 任何判定都是 unknown。
BLOCKING_ISSUES = frozenset({"missing_observation", "crawl_error", "empty_document", "non_html_document"})
# 完整性：文件存在但可能不完整或被遮住。正向證據仍成立（看到了就是看到了），
# 但「未檢出／未觀察到」不能成立 —— 沒看到的部分可能正是答案。
COMPLETENESS_ISSUES = frozenset({
    "http_error_status", "challenge_or_block_page", "interaction_gate", "content_truncated",
    "document_body_unavailable", "content_requests_blocked", "content_requests_failed",
    "blank_visible_text", "dialog_dismissed", "download_blocked", "popup_closed",
    "analysis_without_js_execution",
})


def new_record(kind, url, profile):
    """空紀錄骨架：失敗的觀察與成功的觀察欄位完全相同，CSV 投影才不會缺欄。"""
    record = {
        "record_version": MEASUREMENT_VERSION, "record_id": uuid.uuid4().hex, "kind": kind,
        "role": "", "replicate": 0, "access_index": 0, "crawl_order": "", "pair_mode": "",
        "variant": "", "profile_id": profile.profile_id, "profile": profile.record(), "client": {},
        "observed_at": utc_now(), "finished_at": "", "fetch_time_sec": 0.0,
        "request_headers": {}, "status_code": 0, "final_url": url, "redirect_chain": [],
        "navigation_responses": [], "response_headers": {}, "content_type": "", "charset": "",
        "html": "", "html_length": 0, "html_sha256": "", "body_sha256": "", "truncated": False,
        "text_content": "", "title": "", "scripts": {"inline": [], "external": []},
        "error": None, "error_kind": "", "observation_issues": [], "artifacts": {},
    }
    if kind == "browser":
        record.update({
            "dom_html": "", "dom_text": "", "dom_title": "", "dom_sha256": "", "dom_length": 0,
            "dom_truncated": False, "dom_snapshots": [], "dom_domcontentloaded_html": "",
            "page_url": url, "client_navigations": [], "subresources": [], "external_scripts": [],
            "console_errors": [], "page_errors": [], "failed_requests": [], "blocked_requests": [],
            "dialogs": [], "downloads": [], "popups": [], "document_body_error": "",
            "browser_version": "unavailable", "playwright_version": "unavailable",
        })
    return record


# ── 解碼與摘要 ───────────────────────────────────────────────────
_HEADER_CHARSET = re.compile(r"charset\s*=\s*\"?([A-Za-z0-9_\-:.]+)", re.I)
_META_CHARSET = re.compile(rb"""<meta[^>]+charset\s*=\s*["']?\s*([A-Za-z0-9_\-:.]+)""", re.I)


def decode_body(body, content_type=""):
    """位元組 → 文字，回傳 (文字, 字元集與來源)。

    順序：BOM → Content-Type 的 charset → <meta charset> → UTF-8（壞位元組以 U+FFFD 取代）。
    不用 requests 的 .text：它對沒宣告 charset 的 text/html 套 ISO-8859-1，UTF-8 頁面會變亂碼，
    兩種 client 的文字就因解碼器不同而「不同」—— 那不是伺服器的差異。
    """
    if body.startswith(b"\xef\xbb\xbf"):
        return body[3:].decode("utf-8", "replace"), "utf-8:bom"
    if body.startswith((b"\xff\xfe", b"\xfe\xff")):
        return body.decode("utf-16", "replace"), "utf-16:bom"
    candidates = []
    header = _HEADER_CHARSET.search(content_type or "")
    if header:
        candidates.append((header.group(1), "header"))
    meta = _META_CHARSET.search(body[:4096])
    if meta:
        candidates.append((meta.group(1).decode("ascii", "ignore"), "meta"))
    for name, source in candidates:
        try:
            return body.decode(name, "replace"), f"{name.lower()}:{source}"
        except LookupError:
            continue
    return body.decode("utf-8", "replace"), "utf-8:default"


def is_document_type(content_type):
    """可當成頁面分析的內容類型。其餘（壓縮檔、執行檔、PDF…）不讀內容、不存檔 ——
    本工具不收集惡意檔案樣本，只記錄類型與狀態。"""
    kind = (content_type or "").split(";")[0].strip().lower()
    return kind == "" or kind.startswith("text/") or kind in (
        "application/xhtml+xml", "application/xml", "application/json", "application/javascript")


def summarize_html(html, base_url=""):
    """可見文字、標題、內嵌腳本、外部腳本網址。v2 的文字切法（去 script/style/meta/link/noscript）。"""
    soup = BeautifulSoup(html or "", "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    inline, external = [], []
    for tag in soup.find_all("script"):
        if tag.get("src"):
            external.append(urljoin(base_url, tag["src"]))
        elif tag.string and len(inline) < MAX_INLINE_SCRIPTS:
            inline.append(tag.string[:MAX_INLINE_SCRIPT_CHARS])
    for tag in soup(["script", "style", "meta", "link", "noscript"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ")).strip()
    return {"text": text, "title": title, "inline_scripts": inline, "external_scripts": external}


def script_inventory(summary):
    return {"inline": [{"sha256": sha256(s), "length": len(s)} for s in summary["inline_scripts"]],
            "external": summary["external_scripts"]}


def fill_document(record, body, content_type, max_chars):
    """把主文件位元組寫進紀錄：解碼、截斷旗標、雜湊、文字、標題、腳本清單。"""
    html, charset = decode_body(body, content_type)
    record.update(content_type=content_type or "", charset=charset, body_sha256=sha256(body),
                  html_length=len(html))
    record["truncated"] = record.get("truncated", False) or len(html) > max_chars
    record["html"] = html[:max_chars]
    record["html_sha256"] = sha256(record["html"])
    summary = summarize_html(record["html"], record.get("final_url", ""))
    record.update(text_content=summary["text"], title=summary["title"],
                  scripts=script_inventory(summary))
    return summary


# ── 閘門與挑戰頁：唯一一份規則表（v2 有兩份不一致的 regex）──────────
# 每條規則只在適合的範圍比對，避免把正常內容誤當閘門：
#   markup  整份 HTML          script  內嵌腳本與 on* 事件屬性
#   handler 只看 on* 事件屬性  text    可見文字（已去掉 noscript）
# 刻意不收的兩個 v2 條件：Cloudflare 一般頁面都會載入的 /cdn-cgi/challenge-platform/ 腳本，
# 以及 noscript 裡常見的「enable JavaScript」—— 兩者都不代表內容被擋住。
GATE_RULES = (
    ("captcha", "markup", r"g-recaptcha|recaptcha/(?:api|enterprise)\.js|h-captcha|hcaptcha\.com/1/api"
                          r"|cf-turnstile|challenges\.cloudflare\.com/turnstile"),
    ("challenge", "markup", r"_cf_chl_opt|cf-chl-|<title>\s*just a moment"),
    ("challenge", "text", r"checking your browser|verify(?:ing)? (?:that )?you are (?:a )?human"
                          r"|access denied|attention required|please enable cookies"),
    ("notification", "script", r"Notification\s*\.\s*requestPermission"),
    ("alert_gate", "script", r"\b(?:alert|confirm|prompt)\s*\("),
    ("click_gate", "handler", r"display\s*=\s*['\"]block|removeAttribute\(\s*['\"]hidden"),
    ("click_gate", "text", r"click (?:here )?to continue"),
)
_GATE_RE = tuple((name, scope, re.compile(pattern, re.I)) for name, scope, pattern in GATE_RULES)
CHALLENGE_GATES = frozenset({"captcha", "challenge"})
INTERACTION_GATES = frozenset({"notification", "alert_gate", "click_gate"})
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>(.*?)</script>", re.I | re.S)
_HANDLER_ATTR = re.compile(r"""\bon[a-z]+\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.I)
_TAG = re.compile(r"<[^>]+>")


def detect_gates(html, text=None):
    """回傳頁面上出現的閘門／挑戰名稱（排序）。不跨越任何閘門，只記錄它存在。"""
    if not html:
        return []
    handlers = " ".join(a or b for a, b in _HANDLER_ATTR.findall(html))
    contexts = {"markup": html, "handler": handlers,
                "script": " ".join(_SCRIPT_BLOCK.findall(html)) + " " + handlers,
                "text": text if text is not None else _TAG.sub(" ", html)}
    return sorted({name for name, scope, regex in _GATE_RE if regex.search(contexts[scope])})


def observation_issues(record, view=None):
    """把一次觀察的問題分級成代碼（排序）。

    view="html" 看伺服器送來的主文件（cloaking 比較用）；view="dom" 看 JS 執行後的頁面
    （釣魚判定用）。預設：瀏覽器紀錄看 dom，其餘看 html。
    """
    if not record:
        return ["missing_observation"]
    view = view or ("dom" if record.get("dom_html") else "html")
    issues = set()
    status = record.get("status_code") or 0
    if record.get("error") or not status:
        issues.add("crawl_error")
    if status and not 200 <= status < 300:
        issues.add("http_error_status")
    if view == "dom":
        body, text, truncated = record.get("dom_html", ""), record.get("dom_text", ""), record.get("dom_truncated")
    else:
        body, text, truncated = record.get("html", ""), record.get("text_content", ""), record.get("truncated")
    if record.get("non_html_content"):
        issues.add("non_html_document")
    elif status and not body:
        issues.add("document_body_unavailable" if view == "html" and record.get("document_body_error")
                   else "empty_document")
    if truncated:
        issues.add("content_truncated")
    if body and not (text or "").strip():
        issues.add("blank_visible_text")
    gates = set(detect_gates(body, text))
    if gates & CHALLENGE_GATES:
        issues.add("challenge_or_block_page")
    if gates & INTERACTION_GATES:
        issues.add("interaction_gate")
    if view == "dom":
        # 缺 content_affecting 的舊紀錄一律視為會影響內容（保守）
        if any(r.get("content_affecting", True) for r in record.get("blocked_requests", [])):
            issues.add("content_requests_blocked")
        if any(r.get("content_affecting", True) for r in record.get("failed_requests", [])):
            issues.add("content_requests_failed")
        for key, issue in (("dialogs", "dialog_dismissed"), ("downloads", "download_blocked"),
                           ("popups", "popup_closed")):
            if record.get(key):
                issues.add(issue)
    return sorted(issues)


def blocking(issues):
    return sorted(set(issues) & BLOCKING_ISSUES)


def caveats(issues):
    return sorted(set(issues) & COMPLETENESS_ISSUES)


# ── 證據檔案 ─────────────────────────────────────────────────────
_BODY_FIELDS = ("html", "dom_html", "dom_domcontentloaded_html", "text_content", "dom_text")


def write_artifact(record, name, data):
    """observations/<record_id>/<name>，"x" 模式建立：同一筆證據不會被覆寫。"""
    folder = ARTIFACT_ROOT / record["record_id"]
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    with path.open("xb") as handle:
        handle.write(data if isinstance(data, bytes) else data.encode("utf-8", errors="surrogatepass"))
    record.setdefault("artifacts", {})[name] = str(path)
    return path


def audit_view(record):
    """稽核用的紀錄：大型內容換成檔案路徑＋雜湊，保留文字摘錄供人工快速檢視。"""
    if not record:
        return {}
    view = {k: v for k, v in record.items() if k not in _BODY_FIELDS and k != "confirmation"}
    view["text_excerpt"] = (record.get("text_content") or "")[:500]
    if "dom_text" in record:
        view["dom_text_excerpt"] = (record.get("dom_text") or "")[:500]
    if record.get("external_scripts"):
        view["external_scripts"] = [{k: v for k, v in s.items() if k != "content"}
                                    for s in record["external_scripts"]]
    if record.get("confirmation"):
        view["confirmation"] = audit_view(record["confirmation"])
    return view


def save_record_json(record):
    return write_artifact(record, "record.json",
                          json.dumps(audit_view(record), ensure_ascii=True, indent=2))
