"""Node 1：依觀察計畫做所有觀察（crawler/plan.py），挑出判定用頁面，抽出 JavaScript。

判定用頁面的優先序：瀏覽器 JS 執行後的 DOM（human#1 → human#2），都不可用才退回基準
HTTP 的原始文件（bot#1 → bot#2），並標註 analysis_without_js_execution —— 那份頁面沒有
執行過 JS，「未檢出」不能成立。實際來源寫在 analysis_source。
"""
from crawler.plan import ObservationSettings, observe_url
from crawler.records import blocking, observation_issues, summarize_html


def _candidates(bot, human):
    for slot, record in (("human", human), ("bot", bot)):
        for replicate, candidate in ((1, record), (2, (record or {}).get("confirmation"))):
            if candidate:
                yield f"{slot}#{replicate}", candidate


def choose_analysis_page(bot, human):
    """回傳 (名稱, view, 紀錄, 觀察問題)；全部不可用時紀錄為空 dict。"""
    first_issues = []
    for name, record in _candidates(bot, human):
        view = "dom" if record.get("dom_html") else "html"
        issues = observation_issues(record, view)
        if not blocking(issues):
            if view == "html":
                issues = sorted(set(issues) | {"analysis_without_js_execution"})
            return name, view, record, issues
        first_issues = first_issues or issues
    return "", "", {}, first_issues or ["missing_observation"]


def extract_scripts(html, record, source):
    """判定用頁面的內嵌腳本 + 瀏覽器載入的同主機外部腳本（內容已由 crawler 取得，這裡不發請求）。"""
    summary = summarize_html(html)
    scripts = [{"type": "inline", "src": None, "content": text, "source": source}
               for text in summary["inline_scripts"]]
    scripts += [{"type": "external", "src": item["url"], "content": item["content"], "source": source}
                for item in record.get("external_scripts", []) if item.get("content")]
    return scripts


def scrape_js_node(state):
    settings = ObservationSettings.from_record(state["observation_settings"])
    result = observe_url(state["url"], settings)
    bot, human = result["bot"], result["human"]
    state.update(bot_crawl=bot, human_crawl=human, variant_observations=result["variants"],
                 observation_plan=result["plan"])
    state["errors"] = state.get("errors", []) + result["errors"]
    records = [bot, bot.get("confirmation"), human, human.get("confirmation"), *result["variants"].values()]
    # 沒收到任何回應是「觀察失敗」，不是「網站已失效」
    state["alive"] = True if any(r and r.get("status_code") for r in records) else None
    name, view, record, issues = choose_analysis_page(bot, human)
    state["observation_issues"] = issues
    if not record:
        state["raw_html"], state["js_scripts"] = "", []
        state["phishing_reason"] = state["cloaking_reason"] = ";".join(issues)
        return state
    state["raw_html"] = record["dom_html"] if view == "dom" else record.get("html", "")
    state["analysis_source"] = f"{name}:{view}"
    state["analysis_profile_id"] = record.get("profile_id", "unknown")
    state["analysis_final_url"] = ((record.get("page_url") if view == "dom" else None)
                                   or record.get("final_url") or state["url"])
    state["js_scripts"] = extract_scripts(state["raw_html"], record, state["analysis_source"])
    return state
