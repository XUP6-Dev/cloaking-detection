"""從 dataset/ 的 MUD 資料集挑出存活的釣魚 URL，寫進 dataset/alive_phishing_<日期>.txt。

輸出刻意不是 urls.txt：urls.txt 是 main.py 的收件匣，下一批會覆蓋掉，篩一輪的成果
不該住在會被覆寫的位置。檔名帶日期是為了讓過期看得見 —— 釣魚站存活期以小時計，
隔天再拿同一份清單去跑，「站死了」會被混進「沒有 cloaking」。

用法:
  python build_urls.py 1000              # 湊滿 1000 個存活的釣魚站
  python build_urls.py 1000 --no-scan    # 只挑不探測（快，但約一成是死站）
  python build_urls.py 1000 --workers 24

跑完要進管線時自己複製一次:
  cp dataset/alive_phishing_20260821.txt urls.txt
"""
import csv
import io
import sys
import threading
import time
from contextlib import redirect_stdout
from datetime import date
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_BASE = Path(__file__).resolve().parent
_CSV = _BASE / "dataset" / "MUD_malicious_urls_2026_V2.csv"

# 資料集自帶的 reachability_class 依「我們的存活定義」重新分級。
# 實測各抽 40 筆：active 90% 存活、unavailable 90%、unreachable_or_unscanned 18%。
# unavailable 之所以也有九成，是因為 Node 0 把任何 HTTP 回應（含 403/404/5xx）
# 都算存活 —— 伺服器端 cloaking 站常對非瀏覽器流量回錯誤碼，狀態碼不能當死活依據。
# 先取高良率的桶，可把後續探測的浪費從八成降到一成。
_PREFERRED = ("active", "unavailable", "restricted", "other", "redirected")

csv.field_size_limit(10 ** 7)


def candidates(limit: int):
    """依 reachability_class 良率排序取出釣魚 URL，每個 host 只留一筆。

    去重做在 host 而非 URL 層級：cloaking 是站台／kit 層級的行為，pastehtml.com
    底下那 943 個 URL 共用同一套伺服器行為，算 1 個樣本而不是 943 個。不設限的話
    光它就吃掉候選池的一成，盛行率的分母等於被單一主機灌爆。

    順帶壓掉託管平台的假存活：docs.google.com（264 筆）、storage.googleapis.com、
    firebasestorage、forms.office.com 這類 host 永遠回得了 HTTP，存活探測必過，
    但上面的釣魚檔案早就被清掉了。每 host 一筆讓它們各自縮成一筆。
    """
    pools = {b: [] for b in _PREFERRED}
    seen_host = set()
    with open(_CSV, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if row["class_label"] != "phishing":
                continue
            bucket = row["reachability_class"]
            if bucket not in pools:
                continue
            # url_normalized 才帶 scheme；url 欄是去掉 scheme 的正規化形式
            u = row["url_normalized"].strip()
            host = row["host"]
            if u.startswith("http") and host and host not in seen_host:
                seen_host.add(host)
                pools[bucket].append(u)
    out = []
    for b in _PREFERRED:
        out.extend(pools[b])
        if len(out) >= limit:
            break
    return out[:limit], {b: len(pools[b]) for b in _PREFERRED}


def probe_all(urls, target, workers):
    """用 Node 0 的判準探測存活；判死的以低併發重探一次。

    重探是必要的：Node 0 用裸 requests.get，每次都開新 socket 不重用，持續數千筆
    之後 Windows 暫時埠耗盡，本來活著的站會開始連不上而被記成死的。實測 48 併發
    跑 4,716 筆時存活率在第 800 筆附近由 50% 崩到 3%，同一批低併發重測仍有四成以上。
    """
    from nodes.node0_liveness import is_alive

    alive, probed = [], 0
    lock, stop = threading.Lock(), threading.Event()

    def probe(u):
        if stop.is_set():
            return u, None
        try:
            return u, is_alive(u)
        except Exception:
            return u, False

    def run(batch, w, tag):
        nonlocal probed
        got, missed = [], []
        # Node 0 每筆都會 print，多執行緒下逐筆重導向不安全 → 整段共用一次，
        # 進度改寫 stderr
        with redirect_stdout(io.StringIO()):
            with ThreadPoolExecutor(max_workers=w) as ex:
                for fut in as_completed([ex.submit(probe, u) for u in batch]):
                    u, ok = fut.result()
                    with lock:
                        if ok is None:
                            continue
                        probed += 1
                        (got if ok else missed).append(u)
                        if probed % 25 == 0:
                            print(f"  {tag} 已探測 {probed}　存活 {len(alive)+len(got)}/{target}",
                                  end="\r", file=sys.stderr, flush=True)
                        if len(alive) + len(got) >= target:
                            stop.set()
        print(file=sys.stderr)
        return got, missed

    got, dead = run(urls, workers, "第一輪")
    alive += got
    if dead and len(alive) < target:
        print(f"  第一輪判死 {len(dead)} 筆，低併發重探", file=sys.stderr)
        stop.clear()
        time.sleep(5)                       # 讓 TIME_WAIT 消化一部分
        recovered, _ = run(dead, max(4, workers // 4), "第二輪")
        print(f"  重探救回 {len(recovered)} 筆", file=sys.stderr)
        alive += recovered
    return alive, probed


def main(target=1000, scan=True, workers=16):
    pool, sizes = candidates(target * 4 if scan else target)
    print(f"釣魚候選各桶大小: {sizes}")
    if not pool:
        sys.exit(f"[!] {_CSV.name} 裡找不到釣魚 URL —— 確認檔案與欄位名稱")

    if scan:
        urls, probed = probe_all(pool, target, workers)
        note = f"探測 {probed} 筆，存活 {len(urls)} 筆 = {len(urls)/probed:.1%}"
    else:
        urls, note = pool[:target], "未探測存活"

    urls = urls[:target]
    stamp = date.today().strftime("%Y%m%d")
    out = _BASE / "dataset" / f"alive_phishing_{stamp}.txt"
    out.write_text(
        f"# MUD_malicious_urls_2026_V2 標為 phishing 的 URL {len(urls)} 筆"
        f"（每 host 一筆；{note}；掃描日 {stamp}）\n"
        + "\n".join(urls) + "\n", encoding="utf-8")
    print(f"{note}")
    print(f"已寫入 {len(urls)} 筆 → {out}")
    if scan:
        print(f"[!] 釣魚站壽命以小時計，要跑就今天跑："
              f"cp {out.relative_to(_BASE)} urls.txt && python main.py")


if __name__ == "__main__":
    pos = [a for a in sys.argv[1:] if not a.startswith("--")]
    w = int(sys.argv[sys.argv.index("--workers") + 1]) if "--workers" in sys.argv else 16
    main(int(pos[0]) if pos else 1000,
         scan="--no-scan" not in sys.argv, workers=w)
