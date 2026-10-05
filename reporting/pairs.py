"""盲標用的配對檔：pairs/<sha1(url)[:12]>/{bot.html, human.html, human_dom.html, meta.json}。

bot.html 與 human.html 都是「伺服器送來的主文件」（同一層，與 cloaking 標籤的比較方式一致）；
human_dom.html 是瀏覽器 JS 執行後的 DOM，供標註者參考。

meta.json **絕對不可包含任何判定結果，label 也不行**：label 不是系統的判定，但它是先驗
（「這站被來源標為釣魚」會把標註者推向 yes），κ 與 precision 都會虛高。
tests/test_pipeline_e2e.py::test_pair_meta_contains_no_verdict 用集合差＋全文字表鎖住這件事。
"""
import hashlib
import json
from pathlib import Path

PAIR_DIR = Path(__file__).resolve().parents[1] / "pairs"


def pair_meta(state):
    bot = state.get("bot_crawl") or {}
    human = state.get("human_crawl") or {}
    settings = state.get("observation_settings") or {}
    return {
        "url": state.get("url", ""),
        "bot_status": bot.get("status_code", 0),
        "human_status": human.get("status_code", 0),
        "fetch_time": {"bot": bot.get("fetch_time_sec", 0), "human": human.get("fetch_time_sec", 0)},
        # 逐列的實際順序是來源資訊，不是判定結果，可以給標註者看
        "crawl_order": human.get("crawl_order") or settings.get("crawl_order", ""),
        "pair_mode": settings.get("pair_mode") or human.get("pair_mode", ""),
    }


def save_pair(state, pair_dir=None):
    url = state.get("url", "")
    if not url:
        return None
    folder = Path(pair_dir or PAIR_DIR) / hashlib.sha1(url.encode()).hexdigest()[:12]
    folder.mkdir(parents=True, exist_ok=True)
    bot, human = state.get("bot_crawl") or {}, state.get("human_crawl") or {}
    (folder / "bot.html").write_text(bot.get("html", "") or "", encoding="utf-8", errors="surrogatepass")
    (folder / "human.html").write_text(human.get("html", "") or "", encoding="utf-8", errors="surrogatepass")
    (folder / "human_dom.html").write_text(human.get("dom_html", "") or "", encoding="utf-8",
                                           errors="surrogatepass")
    (folder / "meta.json").write_text(json.dumps(pair_meta(state), ensure_ascii=False, indent=2),
                                      encoding="utf-8")
    return folder
