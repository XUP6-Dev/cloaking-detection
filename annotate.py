"""
annotate.py — 產生盲標用的並排檢視頁（單一 HTML，離線可用）

用法:
    python annotate.py --n-positive 90 --n-negative 50 --seed 20260821
    python annotate.py --batch csv_reports/batch_results_*.csv --pairs pairs/ -o annotate.html

為什麼需要這個：目前沒有任何獨立於系統之外的東西確認過一個陽性是對的。
`_confirm_c1` 只是拿同一把尺再量一次 —— 它確認「可重現」，不確認「正確」。
量測研究需要的是 precision：「我報的 X% 裡有多少是真的」。

（明確排除的兩條路：自建 testbed 只證明抓得到自己寫的東西，對盛行率無幫助；
 GSB / VirusTotal / urlscan 回答的是「是不是釣魚」不是「有沒有差別遞送」。）

盲標的三個要求，這支程式都用程式碼保證，不是靠自律：
  ① 畫面上不出現系統結論（meta.json 本來就不含，這裡也不從 CSV 帶任何裁決欄位進 HTML）
  ② 陽性與陰性混在一起打散，標註者不知道自己在標哪一種
  ③ 順序由固定種子決定，不得依判定結果排序

輸出的 annotations.csv 欄位: url_hash,label,annotator,seconds,note
（label ∈ yes / no / unsure，對應「是差別遞送」/「不是」/「看不出來」）
"""
import argparse
import hashlib
import html
import json
import random
import re
import sys
from pathlib import Path

from reporting.console import ensure_utf8_console
from reporting.csv_io import load_csv

BASE = Path(__file__).parent

# Windows 主控台預設 cp950 印不出 ①②③ κ ← 這些字元，會直接 UnicodeEncodeError
ensure_utf8_console()


# ── 標註準則（標註者要先讀）────────────────────────────────────────
# 刻意寫死在這裡而不是口頭交代：兩位標註者的 κ 值只有在準則相同時才有意義。
GUIDELINE = """
「是差別遞送」= 兩份頁面在<b>功能意圖</b>上不同（一份要你輸入憑證／下載檔案，
另一份不要；一份是品牌仿冒頁，另一份是空白／錯誤／無關內容）。
「不是」= 兩份意圖相同，差異僅在語言、版面、廣告、個人化推薦、時間戳。
「看不出來」= 任一份無法判讀（空白、純錯誤頁、全圖無文字且無法辨識）。
"""

_TAG_RE = re.compile(r"<[^>]+>")


def _text(html_str: str, limit: int = 6000) -> list:
    """粗略取純文字供並排 diff 用。bs4 在這裡不划算 —— 這份文字只給人看。"""
    s = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html_str or "")
    s = _TAG_RE.sub(" ", s)
    s = html.unescape(s)
    return [ln.strip() for ln in re.sub(r"[ \t]+", " ", s).splitlines()
            if ln.strip()][:limit]


def load_pairs(pairs_dir: Path) -> dict:
    """回傳 {url: 目錄}；meta.json 讀不到就跳過（那一筆沒得標）。"""
    out = {}
    for d in sorted(pairs_dir.iterdir() if pairs_dir.exists() else []):
        meta = d / "meta.json"
        if not (d.is_dir() and meta.exists()):
            continue
        try:
            url = json.loads(meta.read_text(encoding="utf-8")).get("url", "")
        except Exception:
            continue
        if url:
            out[url] = d
    return out


def sample(batch_rows, pairs, n_pos, n_neg, seed):
    """從陽性抽 n_pos、陰性抽 n_neg，混在一起用固定種子打散。

    陰性樣本不只是干擾項：它同時能粗估「False 裡有多少其實是漏報」——
    那不是 recall，但是有用的下界資訊。
    """
    pos = [r["url"] for r in batch_rows
           if r.get("cloaking") == "True" and r["url"] in pairs]
    neg = [r["url"] for r in batch_rows
           if r.get("cloaking") == "False" and r["url"] in pairs]
    rnd = random.Random(seed)
    rnd.shuffle(pos)
    rnd.shuffle(neg)
    picked = pos[:n_pos] + neg[:n_neg]
    rnd.shuffle(picked)          # 打散後就再也看不出哪個是哪個
    return picked, len(pos), len(neg)


def _panel(title, raw):
    # sandbox 只給 allow-same-origin：我們在渲染釣魚頁，絕不給 allow-scripts /
    # allow-forms / allow-top-navigation。srcdoc 內容一律轉義。
    return (f'<div class="pane"><h4>{title}</h4>'
            f'<iframe sandbox="allow-same-origin" srcdoc="{html.escape(raw, quote=True)}">'
            f'</iframe></div>')


def _diff_block(a_lines, b_lines):
    import difflib
    rows = []
    for ln in difflib.unified_diff(a_lines, b_lines, "A", "B", n=1, lineterm=""):
        cls = "add" if ln.startswith("+") else ("del" if ln.startswith("-") else "")
        rows.append(f'<div class="{cls}">{html.escape(ln[:400])}</div>')
    return "".join(rows[:400]) or "<div>（兩份純文字相同）</div>"


_PAGE_HEAD = """<!doctype html><meta charset="utf-8"><title>並排標註</title>
<style>
body{font-family:system-ui,"Noto Sans TC",sans-serif;margin:0;background:#f4f4f6}
header{position:sticky;top:0;background:#222;color:#eee;padding:10px 16px;z-index:9}
header input{padding:4px 8px} header button{padding:6px 12px;margin-left:8px}
.item{background:#fff;margin:16px;padding:12px;border-radius:8px;box-shadow:0 1px 4px #0002}
.panes{display:flex;gap:12px} .pane{flex:1;min-width:0}
iframe{width:100%;height:420px;border:1px solid #ccc;background:#fff}
.diff{max-height:220px;overflow:auto;font:12px/1.4 ui-monospace,monospace;
      background:#fafafa;border:1px solid #eee;padding:6px;margin-top:8px;white-space:pre}
.diff .add{background:#e6ffed} .diff .del{background:#ffeef0}
.btns{margin-top:8px} .btns button{padding:8px 16px;margin-right:8px;font-size:15px}
.btns button.on{outline:3px solid #06c} textarea{width:100%;margin-top:6px}
.done{opacity:.55}
</style>
<header>
  標註者 <input id="who" placeholder="你的名字">
  <button onclick="dump()">匯出 annotations.csv</button>
  <span id="prog"></span>
</header>
<div class="item"><b>標註準則</b>__GUIDELINE__</div>
"""

_PAGE_TAIL = """
<script>
const KEY='annot-'+location.pathname, store=JSON.parse(localStorage.getItem(KEY)||'{}');
const shown={};
document.querySelectorAll('.item[data-h]').forEach(el=>{
  const h=el.dataset.h; shown[h]=Date.now();
  if(store[h]){el.classList.add('done');mark(el,store[h].label);}
});
function mark(el,l){el.querySelectorAll('.btns button')
  .forEach(b=>b.classList.toggle('on',b.dataset.l===l));}
function pick(h,l,btn){
  const el=btn.closest('.item');
  store[h]={label:l,seconds:Math.round((Date.now()-shown[h])/1000),
            note:el.querySelector('textarea').value};
  localStorage.setItem(KEY,JSON.stringify(store));
  el.classList.add('done'); mark(el,l); prog();
}
function prog(){document.getElementById('prog').textContent=
  ' 已標 '+Object.keys(store).length+' / '+Object.keys(shown).length;}
function dump(){
  const who=(document.getElementById('who').value||'anon').replace(/[",\\n]/g,'');
  let out='url_hash,label,annotator,seconds,note\\n';
  for(const [h,v] of Object.entries(store))
    out+=[h,v.label,who,v.seconds,'"'+(v.note||'').replace(/"/g,'""')+'"'].join(',')+'\\n';
  const a=document.createElement('a');
  a.href=URL.createObjectURL(new Blob([out],{type:'text/csv'}));
  a.download='annotations.csv'; a.click();
}
prog();
</script>
"""


def build_html(urls, pairs) -> str:
    parts = [_PAGE_HEAD.replace("__GUIDELINE__", GUIDELINE)]
    for url in urls:
        d = pairs[url]
        h = hashlib.sha1(url.encode()).hexdigest()[:12]
        bot   = (d / "bot.html").read_text(encoding="utf-8", errors="replace")
        human = (d / "human.html").read_text(encoding="utf-8", errors="replace")
        # A/B 而不是 BOT/HUMAN：標註者不必知道哪一邊是爬蟲視角
        parts.append(
            f'<div class="item" data-h="{h}"><b>#{h}</b>'
            f'<div class="panes">{_panel("A", bot)}{_panel("B", human)}</div>'
            f'<div class="diff">{_diff_block(_text(bot), _text(human))}</div>'
            f'<textarea rows="2" placeholder="備註（選填）"></textarea>'
            f'<div class="btns">'
            f'<button data-l="yes" onclick="pick(\'{h}\',\'yes\',this)">是差別遞送</button>'
            f'<button data-l="no" onclick="pick(\'{h}\',\'no\',this)">不是</button>'
            f'<button data-l="unsure" onclick="pick(\'{h}\',\'unsure\',this)">看不出來</button>'
            f'</div></div>')
    parts.append(_PAGE_TAIL)
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", default="")
    ap.add_argument("--pairs", default=str(BASE / "pairs"))
    ap.add_argument("--n-positive", type=int, default=90)
    ap.add_argument("--n-negative", type=int, default=50)
    ap.add_argument("--seed", type=int, default=20260821)
    ap.add_argument("-o", "--out", default=str(BASE / "annotate.html"))
    a = ap.parse_args()

    if a.batch:
        batch = Path(a.batch)
    else:
        cands = sorted((BASE / "csv_reports").glob("batch_results_*.csv"))
        if not cands:
            sys.exit("[!] csv_reports/ 下沒有 batch_results_*.csv")
        batch = cands[-1]
    rows = load_csv(batch)

    pairs = load_pairs(Path(a.pairs))
    if not pairs:
        sys.exit(f"[!] {a.pairs} 下沒有配對 HTML —— 主批要用 SAVE_PAIR_HTML=1 跑")

    urls, n_pos, n_neg = sample(rows, pairs, a.n_positive, a.n_negative, a.seed)
    if not urls:
        sys.exit("[!] 沒有可標註的樣本（CSV 與 pairs/ 對不上？）")
    out = Path(a.out)
    out.write_text(build_html(urls, pairs), encoding="utf-8")

    # 陽性數 < 目標時要講出來：precision 的 CI 寬度直接由這個數決定
    print(f"批次: {batch.name} | 配對: {len(pairs)} 筆")
    print(f"抽樣: 陽性 {min(a.n_positive, n_pos)}/{n_pos}  "
          f"陰性 {min(a.n_negative, n_neg)}/{n_neg}  seed={a.seed}")
    if n_pos < a.n_positive:
        print(f"[!] 陽性只有 {n_pos} 筆（目標 {a.n_positive}）—— 全部納入，"
              f"precision 的 95% CI 會比 ±10% 寬")
    print(f"→ {out}（瀏覽器開啟，標完按「匯出 annotations.csv」）")


def _selfcheck():
    """盲標的三個要求用可執行的檢查鎖住，不是靠自律。"""
    page = _PAGE_HEAD.replace("__GUIDELINE__", GUIDELINE) + _PAGE_TAIL
    for word in ("cloak", "C1", "fired", "verified", "reliability"):
        assert word.lower() not in page.lower(), f"標註頁洩漏了系統結論：{word}"

    # 掃「實際產出」而不只是靜態模板。
    #
    # 上面那一關只看 _PAGE_HEAD + _PAGE_TAIL，但洩題的風險在 build_html ——
    # 它拿得到整列 batch_results，而那一列現在多了 label 欄（feed 的 phishing /
    # benign）。label 不是系統的判定，卻是**先驗**：標註者知道「這站被標為釣魚」
    # 就會往 yes 靠，κ 與 precision 一起虛高。目前 build_html 只放
    # sha1(url)[:12] 與兩份原始 HTML，這一關是為了讓它保持這樣。
    #
    # 字表刻意不含 "C1"：hash 是十六進位，"c1" 會自然出現在雜湊裡。
    # 也不含 "label"：那是標註者自己的輸出欄（annotations.csv 的表頭）。
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        d = Path(td) / "pair"
        d.mkdir()
        (d / "bot.html").write_text("<p>A side</p>", encoding="utf-8")
        (d / "human.html").write_text("<p>B side</p>", encoding="utf-8")
        built = build_html(["https://x.example/login"],
                           {"https://x.example/login": d}).lower()
    for word in ("cloak", "phishing", "benign", "fired", "verified",
                 "reliability", "mechanism", "x.example"):
        assert word not in built, f"標註頁洩漏了非盲資訊：{word}"
    # 抽樣不得依判定結果排序：同一批不同 seed 要給出不同順序
    rows = [{"url": f"u{i}", "cloaking": "True" if i < 10 else "False"} for i in range(40)]
    pairs = {f"u{i}": None for i in range(40)}
    s1, _, _ = sample(rows, pairs, 5, 5, 1)
    s2, _, _ = sample(rows, pairs, 5, 5, 2)
    assert len(s1) == 10 and s1 != s2, (s1, s2)
    assert sample(rows, pairs, 5, 5, 1)[0] == s1, "同一個 seed 必須可重現"
    # 轉義：srcdoc 內的引號與標籤不得逸出成真的 DOM（我們在渲染釣魚頁）
    panel = _panel("A", '<script>alert(1)</script>')
    assert "<script>" not in panel and "allow-scripts" not in panel, panel[:200]


if __name__ == "__main__":
    _selfcheck()
    main()
