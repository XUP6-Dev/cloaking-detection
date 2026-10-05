"""
score_annotations.py — 把盲標結果接回批次結果，算 precision

用法:
    python score_annotations.py
    python score_annotations.py --annotations annotations.csv --batch csv_reports/batch_results_*.csv

annotations.csv 由 annotate.py 產生的檢視頁匯出，欄位:
    url_hash,label,annotator,seconds,note        label ∈ yes / no / unsure

輸出:
    陽性標註 n=·   判為「是」·  「不是」·  「看不出來」·
    precision（看不出來計為錯，保守）= · % [Wilson CI]
    precision（看不出來排除）        = · % [Wilson CI]
    依 cloaking_fired 分規則的 precision
    陰性樣本裡被標為「是」的比例（不是 recall，但是有用的下界資訊）
    兩位標註者重疊樣本的 Cohen's κ

分規則的 precision 是這份工作最有價值的產出：若 C1 的 precision 遠低於
C2–C4，就有實證理由把 C1 收緊（例如改用 HIGH_SPECIFICITY_MECHANISMS），
而那會是一個有資料支持的設計決策，不是又一次調門檻。
"""
import argparse
import hashlib
import sys
from collections import Counter, defaultdict
from pathlib import Path

from evaluate import wilson
from reporting.console import ensure_utf8_console
from reporting.csv_io import load_csv

BASE = Path(__file__).parent

# Windows 主控台預設 cp950 印不出 ①②③ κ ← 這些字元，會直接 UnicodeEncodeError
ensure_utf8_console()


def url_hash(url: str) -> str:
    """必須與 reporting.pairs.save_pair 的目錄名同一個算法，否則 join 全空。"""
    return hashlib.sha1(url.encode()).hexdigest()[:12]


def _pct(label, k, n, note=""):
    if not n:
        print(f"   {label} 無樣本")
        return
    lo, hi = wilson(k, n)
    print(f"   {label} {k:>3}/{n:<4} = {k/n:6.1%}  [{lo:.1%}, {hi:.1%}]  {note}")


def cohens_kappa(pairs):
    """pairs = [(標註者A的標籤, 標註者B的標籤), ...]；類別數不限。"""
    n = len(pairs)
    if not n:
        return None
    po = sum(1 for a, b in pairs if a == b) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def score(annotations, batch_rows):
    by_hash = {url_hash(r["url"]): r for r in batch_rows}
    # 同一筆被兩人標過時，precision 只取第一位（κ 另外算）—— 否則重疊樣本
    # 會被重複計入分母，把 CI 灌得比實際窄。
    seen, joined = set(), []
    for a in annotations:
        h = a.get("url_hash", "")
        if h in seen or h not in by_hash:
            continue
        seen.add(h)
        joined.append((a, by_hash[h]))
    missing = len({a.get("url_hash") for a in annotations}) - len(seen)
    if missing:
        print(f"[!] {missing} 筆標註在批次結果中找不到對應 URL（換過批次？）")

    pos = [(a, r) for a, r in joined if r.get("cloaking") == "True"]
    neg = [(a, r) for a, r in joined if r.get("cloaking") == "False"]
    c = Counter(a["label"] for a, _ in pos)
    yes, no, unsure = c["yes"], c["no"], c["unsure"]

    print(f"\n── 陽性標註 n={len(pos)}   "
          f"判為「是」{yes}   「不是」{no}   「看不出來」{unsure}")
    _pct("precision（看不出來計為錯，保守）", yes, len(pos))
    _pct("precision（看不出來排除）      ", yes, yes + no)

    if neg:
        nk = sum(1 for a, _ in neg if a["label"] == "yes")
        print(f"\n── 陰性樣本 n={len(neg)}（混進去打散用，順便看漏報）")
        _pct("被標為「是差別遞送」          ", nk, len(neg),
             "不是 recall，是漏報的下界資訊")

    # ── 分規則 precision ────────────────────────────────────────
    per = defaultdict(Counter)
    for a, r in pos:
        for rule in (r.get("cloaking_fired") or "").split("|"):
            if rule:
                per[rule][a["label"]] += 1
    if per:
        print("\n── 依觸發規則分（同一筆觸發多條時各計一次）")
        for rule in sorted(per):
            cc = per[rule]
            tot = sum(cc.values())
            _pct(f"{rule:<4}", cc["yes"], tot,
                 f"（不是 {cc['no']} / 看不出來 {cc['unsure']}）")

    # ── 標註者一致性 ────────────────────────────────────────────
    by_annot = defaultdict(dict)
    for a in annotations:
        by_annot[a.get("annotator", "?")][a.get("url_hash", "")] = a["label"]
    names = sorted(by_annot)
    if len(names) >= 2:
        print("\n── 標註者一致性")
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                x, y = by_annot[names[i]], by_annot[names[j]]
                overlap = [(x[h], y[h]) for h in set(x) & set(y)]
                k = cohens_kappa(overlap)
                if k is None:
                    continue
                flag = "  ← κ<0.6，先把標註準則寫清楚再重標" if k < 0.6 else ""
                print(f"   {names[i]} × {names[j]}  n={len(overlap):<4} "
                      f"κ = {k:.3f}{flag}")
    else:
        print("\n[!] 只有一位標註者 —— 沒有 κ 值就擋不掉「你自己標自己的系統」這個質疑")
    return {"yes": yes, "no": no, "unsure": unsure, "n_pos": len(pos)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--annotations", default=str(BASE / "annotations.csv"))
    ap.add_argument("--batch", default="")
    a = ap.parse_args()

    ann_path = Path(a.annotations)
    if not ann_path.exists():
        sys.exit(f"[!] 找不到 {ann_path} —— 先用 annotate.py 產生檢視頁並標註匯出")
    if a.batch:
        batch = Path(a.batch)
    else:
        cands = sorted((BASE / "csv_reports").glob("batch_results_*.csv"))
        if not cands:
            sys.exit("[!] csv_reports/ 下沒有 batch_results_*.csv")
        batch = cands[-1]
    print(f"標註: {ann_path.name} | 批次: {batch.name}")
    score(load_csv(ann_path), load_csv(batch))


def _selfcheck():
    """合成資料上的 precision 必須與手算一致。"""
    urls = [f"https://s{i}.example/" for i in range(10)]
    batch = [{"url": u, "cloaking": "True" if i < 6 else "False",
              "cloaking_fired": "C1" if i % 2 else "C2"}
             for i, u in enumerate(urls)]
    # 陽性 6 筆：4 yes / 1 no / 1 unsure → 保守 4/6，排除 unsure 4/5
    labels = ["yes", "yes", "yes", "yes", "no", "unsure"] + ["no"] * 4
    ann = [{"url_hash": url_hash(u), "label": l, "annotator": "a",
            "seconds": "5", "note": ""} for u, l in zip(urls, labels)]
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):   # 自檢不該吵
        r = score(ann, batch)
    assert (r["n_pos"], r["yes"], r["no"], r["unsure"]) == (6, 4, 1, 1), r
    assert cohens_kappa([("yes", "yes"), ("no", "no")]) == 1.0
    assert cohens_kappa([("yes", "no"), ("no", "yes")]) < 0
    assert abs(cohens_kappa([("yes", "yes"), ("yes", "no"),
                             ("no", "no"), ("no", "yes")])) < 1e-9


if __name__ == "__main__":
    _selfcheck()
    main()
