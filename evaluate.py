"""
evaluate.py - 以 ground_truth.csv 為基準統計 cloaking 觀測結果

用法:
    python evaluate.py                          # 自動取 csv_reports/ 最新的 batch_results_*.csv
    python evaluate.py csv_reports/batch_results_20260820_104527.csv
    python evaluate.py --baseline csv_reports/batch_results_<A/A那批>.csv

統計 cloaking 三態的分布，以及釣魚判定的陽性率。

釣魚這邊仍然只有陽性率、沒有 recall / 精確度：那需要每個 URL 的真實標記，
ground_truth.csv 目前不存在。有基準檔時本程式會自動分組比較（見 main()）。

評估原則：
    「無法取得內容」與「驗過沒有 cloaking」不是同一件事。
    死站沒有東西可比，N/A 是「未經可信測量」，兩者都不可併入 False。

    有 N/A 的時候，盛行率不是一個數，是一個區間，所以報三個：
      ① 下界 = True / N          「至少這麼多」，N/A 全當非 cloaking ← 主結果引用這個
      ② 上界 = (True + N/A) / N  「至多這麼多」，N/A 全當 cloaking
      ③ 條件 = True / (True+False)  排除 N/A，假設 N/A 的 cloaking 率與可判定
                                    子集相同 —— 這個假設很可能不成立，N/A 富集了
                                    掛閘門與結構分歧的站，那些正是更可能 cloak 的。
    ① ≤ ③ ≤ ② 是這三個定義的不變式（_selfcheck 隨機驗證）。
"""
import json
import math
import sys
from collections import Counter
from pathlib import Path

from reporting.console import ensure_utf8_console
from reporting.csv_io import load_csv  # noqa: F401（score_annotations 等工具沿用這個名稱）

BASE = Path(__file__).parent

# Windows 主控台預設 cp950 印不出 ①②③ κ ← 這些字元，會直接 UnicodeEncodeError
ensure_utf8_console()


def wilson(k, n, z=1.96):
    """Wilson 分數區間；n=0 時回傳 (0, 0) 而非除零。"""
    if not n:
        return 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - m) / d, (c + m) / d


def two_proportion_p(k1, n1, k2, n2):
    """兩比例 z 檢定的雙尾 p 值（合併比例估計標準誤）。n=0 時回傳 nan。"""
    if not n1 or not n2:
        return float("nan")
    p = (k1 + k2) / (n1 + n2)
    se = math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2))
    if se == 0:
        return 1.0
    z = (k1 / n1 - k2 / n2) / se
    return math.erfc(abs(z) / math.sqrt(2))


def prevalences(t, f, na):
    """三種盛行率。分母是「有裁決的存活樣本」= t+f+na，不含裁決欄位空白的列 ——
    混進去會讓 ① ≤ ③ ≤ ② 這條不變式失效（那些列既不是 N/A 也不是 False）。"""
    n = t + f + na
    if not n:
        return None
    return {
        "n":     n,
        "lower": (t, n),                    # ① N/A 全當非 cloaking
        "upper": (t + na, n),               # ② N/A 全當 cloaking
        "cond":  (t, t + f) if t + f else (0, 0),   # ③ 排除 N/A
    }


def _rate_line(label, k, n, note=""):
    if not n:
        print(f"   {label} 無樣本")
        return
    lo, hi = wilson(k, n)
    print(f"   {label} {k:>4}/{n:<5} = {k/n:6.1%}  [{lo:.1%}, {hi:.1%}]  {note}")


def resolve_labels(rows, gt_path):
    """決定每一列的清單標籤，回傳 (labels: {url: label}, 來源說明: str)。

    優先序：CSV 自帶的 `label` 欄 > ground_truth.csv > 沒有。

    自帶欄位才是對的那一個。ground_truth.csv 是單一固定檔名，每跑一次
    fetch_feed.py 就被覆蓋 —— 事後拿它去 join，對到的是**最新那份清單**，
    不是這批當初跑的那份。兩者對不上時 join 會安靜地少掉一堆列，
    對得上但內容已換時更糟：分組看起來正常，分母卻是錯的。

    檔案 join 這條路只留給沒有 label 欄的舊 CSV。
    """
    if rows and "label" in rows[0]:
        labels = {r["url"]: r["label"] for r in rows if r.get("label")}
        if labels:
            return labels, "CSV 的 label 欄"
        # 有欄位但全空 = build_urls.py 的純釣魚清單（沒有第二方標籤）。
        # 這是正常情形，不是缺資料，所以直接走整批統計，不去碰 ground_truth.csv ——
        # 那個檔可能留著上一批的清單，join 上去等於憑空生出一個分母。
        return {}, "無（label 欄全空 —— 純釣魚清單，無第二方標籤）"
    if gt_path.exists():
        gt = {r["url"]: r["label"] for r in load_csv(gt_path)}
        if any(r["url"] in gt for r in rows):
            return gt, f"{gt_path.name}（舊格式 CSV，事後 join）"
        return {}, f"{gt_path.name} 與這批沒有交集 —— 基準檔是舊清單，改以整批統計"
    return {}, "無 ground_truth.csv"


def report_phi_blindspot(rows, labels):
    """φ 對活體釣魚站的盲區 —— 這是 cloaking 判定的 recall 上界，不是誤差。

    node4_cloaking_analyzer 的降級邏輯裡已經寫死這句話：判定路徑全部經過 φ，
    所以 φ 的 recall 就是 cloaking 判定的 recall 上界。分母獨立出來之後
    （feed 標籤，不再是 Node 3 的 is_phishing），那句註解變成可以量的數字：

      feed 說是釣魚、站還活著、但 φ 在真人端一個惡意機制都沒認出來的比例。

    落在這個比例裡的站，本系統無論 C1–C5 怎麼調都判不出 cloaking。
    主結果報的下界要配著這個數一起讀 —— 它說明下界為什麼比看起來更保守。
    """
    phish = [r for r in rows
             if labels.get(r["url"]) == "phishing" and r.get("alive") == "True"]
    if not phish or "human_mechanisms" not in phish[0]:
        return
    blind = sum(1 for r in phish if not (r.get("human_mechanisms") or "").strip())
    print("\n── φ 的盲區（存活且標記為釣魚的子集）")
    _rate_line("真人端零機制", blind, len(phish),
               "φ 認不出 → cloaking 判定的 recall 上界")
    # 同一子集裡 Node 3 判為釣魚的比例：φ + 混淆加權 + LLM 融合之後的 recall。
    # 和上面那個數的差距，就是「有機制但不足以判釣魚」那一段。
    if "is_phishing" in phish[0]:
        k = sum(1 for r in phish if r.get("is_phishing") == "True")
        _rate_line("Node 3 判為釣魚", k, len(phish), "φ+LLM 對活體釣魚站的 recall")


def _by_label(rows, labels):
    """(benign 存活列, phishing 存活列)。兩組都空就回 (None, None)。"""
    alive = [r for r in rows if r.get("alive") == "True"]
    b = [r for r in alive if labels.get(r["url"]) == "benign"]
    p = [r for r in alive if labels.get(r["url"]) == "phishing"]
    return (b, p) if b and p else (None, None)


def _compare(title, kb, nb, kp, np_, note=""):
    """同一個量在兩組之間的對照。方向錯（合法組較高）會標出來 ——
    那是這個專案反覆踩到的坑，不該讓讀者自己去比兩行數字。"""
    if not nb or not np_:
        return
    rb, rp = kb / nb, kp / np_
    p = two_proportion_p(kp, np_, kb, nb)
    flag = ("✔ 方向正確" if rp > rb else "✘ 方向反轉") + (f"  p={p:.4g}")
    print(f"   {title}")
    print(f"      benign   {kb:>4}/{nb:<5} = {rb:6.1%}  [{wilson(kb,nb)[0]:.1%}, {wilson(kb,nb)[1]:.1%}]")
    print(f"      phishing {kp:>4}/{np_:<5} = {rp:6.1%}  [{wilson(kp,np_)[0]:.1%}, {wilson(kp,np_)[1]:.1%}]   {flag}")
    if note:
        print(f"      {note}")


def report_channel_differential(rows, labels):
    """可行性判準 F1（觸發性）的直接證據：BOT 被擋而真人拿到完整內容。

    為什麼要單獨看這個而不是看 cloaking 那一欄：F1 問的是「極端暴露的身分是否
    真的讓伺服器走上不同分支」。通道層的差別待遇（403 / 協議中斷 / 空白頁）是
    **第一方伺服器層級的事實** —— 空白回應與完整回應之間不存在連續光譜，
    所以它不受 C1 那個第三方元件混淆的影響。C2–C4 在這之上還加了「真人端須含
    高特異性機制」的閘門（為了壓掉合法站掛 WAF 造成的誤判），那個閘門是
    cloaking 裁決要的，不是 F1 要的。

    關鍵區分：「BOT 被送空白頁」與「HUMAN 端爬取失敗」在只看 content_similarity
    時同形（都是一端空一端滿）。要分開必須同時看 error 欄 —— 這正是先前
    CSV 缺這幾欄時分不出來的東西。
    """
    b, p = _by_label(rows, labels)
    if not b or "bot_channel_blocked" not in rows[0]:
        return
    print("\n── F1 觸發性：通道層差別待遇（不參與裁決）")

    def blocked(g):
        return sum(1 for r in g if r.get("bot_channel_blocked") == "True")
    _compare("BOT 被擋 ＋ 真人正常（bot_channel_blocked）",
             blocked(b), len(b), blocked(p), len(p))

    def bot_blank(g):
        """BOT 空頁且**無錯誤**，真人有內容 —— C4 的形狀，F1 最乾淨的證據。"""
        n = 0
        for r in g:
            try:
                bl, hl = int(r.get("bot_html_length") or 0), int(r.get("human_html_length") or 0)
            except ValueError:
                continue
            if hl > 0 and bl == 0 and not (r.get("bot_error") or "").strip():
                n += 1
        return n
    _compare("BOT 空頁無錯誤 ＋ 真人有內容（C4 形狀）",
             bot_blank(b), len(b), bot_blank(p), len(p),
             "空白 vs 完整之間無連續光譜 → 無法以頁面自身變異解釋")

    def human_failed(g):
        """對照組：反過來是真人端失敗。這是站死了，不是 cloaking ——
        兩者先前在 CSV 上分不出來，數字要並列才不會被誤讀。"""
        return sum(1 for r in g if (r.get("human_error") or "").strip())
    _compare("（對照）HUMAN 端爬取失敗 —— 站死了，不是訊號",
             human_failed(b), len(b), human_failed(p), len(p))


def report_single_end_ablation(rows, labels):
    """單端消融：配對差分相對於單一身分的增益。

    對 BOT / HUMAN 兩份 HTML 各跑一次 φ 的**絕對**判定（不是集合差），
    所以這個量測完全不受 C1 的第三方元件混淆影響 —— 比的是兩端各自看到什麼，
    不是兩端差在哪裡。

    這是 F1 最直接的逐列檢定：若極端身分沒有讓伺服器走上不同分支，
    兩端的絕對判定率應該相同，`只有真人端判為釣魚` 與其反向應該對稱。
    不對稱且偏向真人端，才代表極化真的換到了不同的內容。
    """
    b, p = _by_label(rows, labels)
    if not b or "bot_is_phishing" not in rows[0]:
        return
    print("\n── 單端消融：φ 對兩端各自的判定")

    # ── 主要基底：機制集合 ────────────────────────────────────────
    # 用機制而不是 is_phishing。evaluate_page() 的分數含 URL 詞彙／結構特徵，
    # 而 BOT 與 HUMAN 拿的是**同一個 URL** —— 那部分是兩端共有的常數項，
    # 會把兩端同時推過閾值，掩蓋掉內容上的差異。
    # MALICIOUS_MECHANISM_FLAGS 純粹由內容衍生（HTML 結構與 JS 行為），
    # 不含任何 URL 旗標，所以機制集合才是「兩端看到的東西不同」的乾淨量測。
    def nonempty(g, col):
        return sum(1 for r in g if (r.get(col) or "").strip())
    _compare("BOT 端有惡意機制", nonempty(b, "bot_mechanisms"), len(b),
             nonempty(p, "bot_mechanisms"), len(p))
    _compare("HUMAN 端有惡意機制", nonempty(b, "human_mechanisms"), len(b),
             nonempty(p, "human_mechanisms"), len(p))

    # ── F1 的逐列檢定：不對稱性 ──────────────────────────────────
    # 若極端身分沒有讓伺服器走上不同分支，兩個方向的差集應該**對稱**
    # （純擷取雜訊沒有方向）。偏向真人端才代表極化真的換到了內容。
    print("\n   機制集合差的方向性（F1 的逐列檢定）")
    for name, g in (("benign", b), ("phishing", p)):
        fwd = nonempty(g, "hidden_from_bot")   # 真人有、BOT 沒有
        rev = nonempty(g, "reverse_diff")      # BOT 有、真人沒有
        tot = fwd + rev
        skew = (fwd / tot) if tot else 0.0
        print(f"      {name:9} 只給真人 {fwd:>4} | 只給 BOT {rev:>4} | "
              f"偏向真人端 {skew:5.1%}" + ("  ← 對稱＝雜訊" if tot and 0.4 < skew < 0.6 else ""))
    print("      顯著偏向真人端、且釣魚組偏得比合法組多 → 支持 F1")
    print("      兩組都接近 50% → 差集是擷取雜訊，沒有方向，不支持 F1")

    # ── 次要：單端的完整判定 ──────────────────────────────────────
    # 論文第 8 章指定的形式（「以 BOT 單端與 HUMAN 單端各自的判定作為基線」）。
    # 保留但標註：這兩個數含共同的 URL 項，兩端差距因此被系統性低估。
    print("\n   單端完整判定（含兩端共有的 URL 項，差距被低估）")
    for name, g in (("benign", b), ("phishing", p)):
        kb_ = sum(1 for r in g if r.get("bot_is_phishing") == "True")
        kh_ = sum(1 for r in g if r.get("human_is_phishing") == "True")
        print(f"      {name:9} BOT {kb_:>4}/{len(g)} = {kb_/len(g):5.1%} | "
              f"HUMAN {kh_:>4}/{len(g)} = {kh_/len(g):5.1%}")


def _raw_fired(rows):
    """C1–C5 的原始觸發率（未經 dynamic_reliability 閘門）。

    A/A 對照批唯一可比的欄位：bot_bot 模式 prewarm_ok 恆為 False，
    整批會落在 LOW → N/A，用 cloaking 那一欄比等於沒跑。
    """
    have = [r for r in rows if r.get("rule_fired_raw") not in (None, "")]
    return sum(1 for r in have if r["rule_fired_raw"] == "True"), len(have)


def report_group(rows, title):
    """對一組結果印出存活率與 cloaking 三態分布 + 三種盛行率。"""
    n = len(rows)
    if not n:
        print(f"\n── {title}：無樣本")
        return
    alive = [r for r in rows if r.get("alive") == "True"]
    counts = Counter(r.get("cloaking", "") for r in alive)
    t, f, na = counts.get("True", 0), counts.get("False", 0), counts.get("N/A", 0)

    lo_a, hi_a = wilson(len(alive), n)
    print(f"\n── {title}（N = {n}）")
    print(f"   存活          {len(alive):>4}/{n}  = {len(alive)/n:6.1%}  "
          f"[{lo_a:.1%}, {hi_a:.1%}]")
    if not alive:
        return
    print(f"   cloaking=True  {t:>4}   False {f:>4}   N/A {na:>4}"
          f"  （N/A 佔存活 {na/len(alive):.1%}）")
    pv = prevalences(t, f, na)
    if not pv:
        print("   盛行率: 無可裁決的樣本")
    else:
        if pv["n"] != len(alive):
            print(f"   （{len(alive) - pv['n']} 筆存活樣本沒有裁決值，未計入盛行率分母）")
        _rate_line("① 下界盛行率", *pv["lower"], "N/A 全當非 cloaking ← 主結果引用這個")
        _rate_line("③ 條件盛行率", *pv["cond"],  "排除 N/A（假設 N/A 與可判定子集同率）")
        _rate_line("② 上界盛行率", *pv["upper"], "N/A 全當 cloaking")
    k_raw, n_raw = _raw_fired(alive)
    if n_raw:
        _rate_line("規則原始觸發率", k_raw, n_raw, "rule_fired_raw，繞過可信度閘門")

    # 釣魚是與 cloaking 各自獨立的判定，不共用分母 —— 分母是存活數，
    # 不排除 N/A：釣魚沒有第三態，抓不到內容的頁面就是「沒有證據」→ False。
    if "is_phishing" in alive[0]:
        p = sum(1 for r in alive if r.get("is_phishing") == "True")
        lo_p, hi_p = wilson(p, len(alive))
        print(f"   釣魚陽性率     {p:>4}/{len(alive)} = {p/len(alive):6.1%}  "
              f"[{lo_p:.1%}, {hi_p:.1%}]")
        both = sum(1 for r in alive
                   if r.get("is_phishing") == "True" and r.get("cloaking") == "True")
        print(f"   兩者皆陽性     {both:>4}   （釣魚 ∩ cloaking）")


def report_baseline(rows, baseline_rows, baseline_name):
    """A/A 對照：主批 vs 同一份清單跑 human_human / bot_bot 的噪音底線。

    量的是「頁面自身變異造成的假陽性地板」—— 主結果必須顯著高過這條線，
    否則觀察到的差異可以用頁面自身變異解釋掉。
    """
    alive   = [r for r in rows if r.get("alive") == "True"]
    base_al = [r for r in baseline_rows if r.get("alive") == "True"]
    k1, n1 = _raw_fired(alive)
    k2, n2 = _raw_fired(base_al)
    if not n1 or not n2:
        print("\n── A/A 比對：其中一批沒有 rule_fired_raw 欄位（舊版 CSV）")
        return
    modes = {r.get("pair_mode", "?") for r in base_al}
    print("\n── 規則原始觸發率（rule_fired_raw，繞過可信度閘門）")
    _rate_line(f"主批  {list({r.get('pair_mode','?') for r in alive})}", k1, n1)
    _rate_line(f"A/A   {sorted(modes)}", k2, n2, f"← {baseline_name}")
    print(f"   兩比例檢定 p = {two_proportion_p(k1, n1, k2, n2):.4g}")


def report_crawl_order(rows):
    """爬取順序是未被檢定的實驗變因：若順序影響陽性率，那一部分就不是 cloaking。

    有顯著差異不是壞消息，是可寫的發現（順序汙染 / one-shot kit），
    但主結果就必須只用 human_first 那一半（HUMAN 先到，沒被 BOT 燒過）。
    """
    alive = [r for r in rows if r.get("alive") == "True"]
    orders = sorted({r.get("crawl_order", "") for r in alive} - {""})
    if len(orders) < 2:
        return
    print("\n── 爬取順序分組（rule_fired_raw）")
    stats = {}
    for o in orders:
        stats[o] = _raw_fired([r for r in alive if r.get("crawl_order") == o])
        _rate_line(f"{o:<12}", *stats[o])
    if len(orders) == 2:
        (k1, n1), (k2, n2) = stats[orders[0]], stats[orders[1]]
        print(f"   兩比例檢定 p = {two_proportion_p(k1, n1, k2, n2):.4g}")


def report_reverse_diff(rows):
    """反向差非空率 = 順序汙染是否成立的直接量測（BOT 端獨有惡意機制）。"""
    alive = [r for r in rows if r.get("alive") == "True"]
    if not alive or "reverse_diff" not in alive[0]:
        return
    k = sum(1 for r in alive if r.get("reverse_diff"))
    print("\n── 反向差（BOT 端獨有機制，不參與裁決）")
    _rate_line("非空率      ", k, len(alive),
               "比例偏高（>3%）代表順序汙染 / burn-after-read 值得單獨一節")
    if k:
        for mech, cnt in Counter(
                m for r in alive for m in (r.get("reverse_diff") or "").split("|") if m
        ).most_common(5):
            print(f"      {mech:<28} {cnt}")


_COHORT_FIELDS = ("phishing_verdict", "rule_phishing_verdict", "llm_phishing_assessment",
                  "cloaking_label", "rule_cloaking_label", "llm_cloaking_assessment")


def _reason_codes(row):
    """uncertainty_reasons 欄的 cloaking 理由，去掉觀察名稱前綴（human#1:… → …）。"""
    try:
        reasons = json.loads(row.get("uncertainty_reasons") or "{}").get("cloaking", [])
    except ValueError:
        return []
    return [r.split(":", 1)[1] if r.split(":", 1)[0].endswith(("#1", "#2")) else r.split(":", 1)[0]
            for r in reasons if r]


def report_cohorts(rows):
    """v2 起的批次：來源 cohort 是威脅情資，不是獨立真值 —— 只報各欄分布，unknown 留在分母。

    同一份 CSV 只能有一個 measurement_version：不同版本的觀察方式或判定規則不同，
    合併等於把兩把尺量出來的數字加在一起。
    """
    versions = {r.get("measurement_version") for r in rows}
    schemas = {r.get("schema_version") for r in rows}
    if len(versions) != 1 or len(schemas) != 1 or versions & {None, ""}:
        raise ValueError("Do not pool legacy or mixed measurement versions")
    version = next(iter(versions))
    print(f"{version} source-cohort observations; feed labels are not ground truth or population prevalence.")
    for label in sorted({r.get("source_label", "unlabeled") for r in rows}):
        cohort = [r for r in rows if r.get("source_label", "unlabeled") == label]
        print(f"source_label={label}; N={len(cohort)}")
        for field in _COHORT_FIELDS:
            if field in cohort[0]:
                counts = Counter(r.get(field, "unknown") for r in cohort)
                print(f"  {field}: {dict(counts)}; unknown retained in denominator")
        alive = [r for r in cohort if r.get("alive") == "True"]
        if alive and "cloaking_label" in alive[0]:
            c = Counter(r.get("cloaking_label") for r in alive)
            pv = prevalences(c.get("true", 0), c.get("false", 0), c.get("unknown", 0))
            if pv:
                print("  cloaking 在此 cohort、此 client 組合下的比例（不是釣魚網站母體盛行率）：")
                _rate_line("① 下界", *pv["lower"], "unknown 全當 false")
                _rate_line("③ 條件", *pv["cond"], "排除 unknown（假設 unknown 與可判定子集同率）")
                _rate_line("② 上界", *pv["upper"], "unknown 全當 true")
        if "rule_cloaking_label" not in cohort[0]:
            continue
        cross = Counter((r.get("rule_cloaking_label"), r.get("cloaking_label")) for r in cohort)
        print(f"  規則 → 最終 cloaking: {dict(sorted(cross.items()))}")
        reasons = Counter(code for r in cohort for code in _reason_codes(r))
        if reasons:
            print(f"  unknown 理由（前 10）: {dict(reasons.most_common(10))}")
        signals = Counter(s for r in cohort for s in (r.get("cloaking_signals") or "").split("|") if s)
        if signals:
            print(f"  observed 訊號: {dict(signals.most_common())}")
        agreement = Counter((r.get("rule_cloaking_label"), r.get("llm_cloaking_assessment")) for r in cohort)
        print(f"  規則 × 模型（只供複核排序，不是準確率）: {dict(sorted(agreement.items()))}")
    print("Precision/recall require independent blinded annotations; see README「評估」.")


report_v2 = report_cohorts   # v2 相容名稱


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    baseline_path = None
    if "--baseline" in argv:
        i = argv.index("--baseline")
        if i + 1 >= len(argv):
            sys.exit("[!] --baseline 後面要接一個 CSV 路徑")
        baseline_path = Path(argv[i + 1])
        del argv[i:i + 2]

    if argv:
        batch_path = Path(argv[0])
    else:
        candidates = sorted((BASE / "csv_reports").glob("batch_results_*.csv"))
        if not candidates:
            sys.exit("[!] csv_reports/ 下沒有 batch_results_*.csv —— "
                     "batch_results 在整批跑完才由 cli.py run 寫出，批次中斷就不會有這個檔"
                     "（已完成的列在 cloaking_report_*.csv）")
        batch_path = candidates[-1]

    rows = load_csv(batch_path)
    print(f"批次檔案: {batch_path.name}")

    if any(r.get("schema_version") in ("2.0", "3.0") for r in rows):
        if baseline_path:
            raise ValueError("v2+ baseline pooling requires matching settings; compare run_config_sha256 "
                             "and inspect separate cohort reports")
        report_cohorts(rows)
        return 0

    if "cloaking" not in (rows[0] if rows else {}):
        sys.exit(f"[!] {batch_path.name} 沒有 cloaking 欄位，格式不符")

    labels, src = resolve_labels(rows, BASE / "ground_truth.csv")
    print(f"標籤來源: {src}")

    matched = [r for r in rows if r["url"] in labels]
    if matched:
        print(f"對上標籤: {len(matched)}/{len(rows)} 筆")
        kinds = {labels[r["url"]] for r in matched}
        if len(kinds) > 1:
            # 混合清單（fetch_feed.py 產生的）→ 分組比較才有意義：
            # 合法組的 cloaking 率是特異性地板，釣魚組的才是主結果。
            for lab in sorted(kinds):
                report_group([r for r in matched if labels[r["url"]] == lab],
                             f"標記 = {lab}")
        else:
            report_group(matched, f"全部標記為 {kinds.pop()}")
    else:
        report_group(rows, "全部（無標籤，分母不是釣魚站）")

    report_phi_blindspot(rows, labels)
    # F1 與消融放在盛行率之後：主結果是可行性判準，盛行率是次要結果，
    # 但分組統計要先印出來這兩節才有分母可對照。
    report_channel_differential(rows, labels)
    report_single_end_ablation(rows, labels)

    # ── 觸發了哪幾條規則 ──────────────────────────────────────
    if "cloaking_fired" in rows[0]:
        fired = Counter(r["cloaking_fired"] for r in rows if r.get("cloaking") == "True")
        if fired:
            print("\n── cloaking 陽性的規則觸發分布")
            for k, v in fired.most_common():
                print(f"   {k or '(空)':<12} {v}")
        rel = Counter(r["dynamic_reliability"] for r in rows if r.get("alive") == "True")
        print("\n── 動態可信度分布（存活子集）")
        for k, v in rel.most_common():
            print(f"   {k or '(空)':<8} {v}")

    report_crawl_order(rows)
    report_reverse_diff(rows)
    if baseline_path:
        if not baseline_path.exists():
            sys.exit(f"[!] 找不到基準批次: {baseline_path}")
        report_baseline(rows, load_csv(baseline_path), baseline_path.name)


def _selfcheck():
    assert wilson(0, 0) == (0.0, 0.0)
    lo, hi = wilson(5, 100)
    assert lo < 0.05 < hi, (lo, hi)
    # ① ≤ ③ ≤ ② 是這三個定義的不變式，不是巧合 —— 隨機三態向量驗證
    import random
    for _ in range(2000):
        t, f, na = (random.randint(0, 40) for _ in range(3))
        pv = prevalences(t, f, na)
        if not pv or not pv["cond"][1]:
            continue
        lower = pv["lower"][0] / pv["lower"][1]
        cond  = pv["cond"][0]  / pv["cond"][1]
        upper = pv["upper"][0] / pv["upper"][1]
        assert lower <= cond <= upper + 1e-12, (t, f, na, lower, cond, upper)
    # 兩比例檢定：完全相同的比例 p≈1，天差地別的比例 p 極小
    assert two_proportion_p(50, 100, 50, 100) > 0.99
    assert two_proportion_p(90, 100, 5, 100) < 1e-6

    # 標籤來源的優先序。這四條全部是「安靜地換掉分母」型的錯誤：
    # 分組照印、CI 照算，只有數字是錯的。
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        gt = Path(td) / "ground_truth.csv"
        gt.write_text("url,label\nhttps://a/,phishing\n", encoding="utf-8")
        # ① 自帶欄位優先於檔案（檔案可能已被下一次 fetch_feed.py 覆蓋）
        assert resolve_labels([{"url": "https://a/", "label": "benign"}], gt)[0] \
            == {"https://a/": "benign"}
        # ② label 欄全空 = 純釣魚清單，沒有第二方標籤 —— 不得回頭 join 舊基準檔，
        #    那等於憑空生出一個分母
        assert resolve_labels([{"url": "https://a/", "label": ""}], gt)[0] == {}
        # ③ 沒有 label 欄的舊 CSV 才走檔案 join
        assert resolve_labels([{"url": "https://a/"}], gt)[0] == {"https://a/": "phishing"}
        # ④ 舊 CSV 但基準檔換過清單 → 沒交集就當沒有，不硬湊
        assert resolve_labels([{"url": "https://z/"}], gt)[0] == {}


if __name__ == "__main__":
    _selfcheck()
    main()
