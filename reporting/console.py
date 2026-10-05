"""主控台：UTF-8 輸出與批次摘要表。

Windows 主控台預設 cp950/cp936，印出 emoji 或 ①②③ 會直接 UnicodeEncodeError 讓程式
中斷 —— 不是變亂碼，是拋例外。每個進入點都呼叫 ensure_utf8_console()。
"""
import sys


def ensure_utf8_console():
    for stream in (sys.stdout, sys.stderr):
        if stream and stream.encoding and stream.encoding.lower() != "utf-8":
            stream.reconfigure(encoding="utf-8")


def observation_status(row):
    return "✅ 已取得回應" if row.get("alive") is True else "⚠️ 無法觀察"


_PHISH_ZH = {"phishing": "命中", "not_detected": "未檢出", "unknown": "無法判定"}
_CLOAK_ZH = {"true": "是", "false": "否", "unknown": "無法判定"}
_ALIVE_ZH = {True: "是", False: "網址無效"}


def print_summary(results):
    """批次彙整表與三態計數。unknown 獨立計數，不併入任何一邊。"""
    total = len(results)
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        Console = None
    if Console:
        table = Table(title=f"\n📊 批次分析彙整 ({total} 個網站)", show_header=True, header_style="bold magenta")
        for name, width, justify in (("#", 4, "right"), ("URL", 50, "left"), ("存活", 6, "center"),
                                     ("釣魚", 8, "center"), ("Cloaking", 9, "center"), ("狀態", 12, "left")):
            table.add_column(name, width=width, justify=justify, no_wrap=(name == "URL"))
        for i, r in enumerate(results, 1):
            url = r["url"][:50] + "…" if len(r["url"]) > 50 else r["url"]
            table.add_row(str(i), url, {True: "✅", False: "❌"}.get(r.get("alive"), "－"),
                          _PHISH_ZH.get(r.get("phishing_verdict"), "無法判定"),
                          _CLOAK_ZH.get(r.get("cloaking_label"), "無法判定"), r.get("status", "")[:12])
        Console().print(table)
    else:
        print(f"\n{'=' * 80}\n{'#':<4} {'URL':<55} {'存活':<6} {'釣魚':<6} {'Cloaking':<10}\n{'-' * 80}")
        for i, r in enumerate(results, 1):
            print(f"{i:<4} {r['url'][:54]:<55} {_ALIVE_ZH.get(r.get('alive'), '無法判定'):<6} "
                  f"{_PHISH_ZH.get(r.get('phishing_verdict'), '無法判定'):<6} "
                  f"{_CLOAK_ZH.get(r.get('cloaking_label'), '無法判定'):<10}")
        print("=" * 80)

    def count(key, value):
        return sum(1 for r in results if r.get(key) == value)
    print(f"\n統計：收到 HTTP 回應 {sum(1 for r in results if r.get('alive') is True)}/{total} | "
          f"無法觀察 {sum(1 for r in results if r.get('alive') is None)}/{total}")
    print(f"  釣魚     phishing {count('phishing_verdict', 'phishing')} | "
          f"not_detected {count('phishing_verdict', 'not_detected')} | "
          f"unknown {count('phishing_verdict', 'unknown')}")
    print(f"  cloaking true {count('cloaking_label', 'true')} | false {count('cloaking_label', 'false')} | "
          f"unknown {count('cloaking_label', 'unknown')}（規則原始 true {count('rule_cloaking_label', 'true')}）")
