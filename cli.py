"""命令列入口與批次流程。

    python cli.py fetch-feed [LIMIT] [--input FILE]     匯入 PhishHunt 清單（只下載清單，不造訪 URL）
    python cli.py run [--batch DIR] [--limit N] [--url URL]
    python cli.py evaluate [CSV] [--baseline CSV]
    python cli.py check                                 本機 Chromium 與 Ollama 狀態（不連外）

舊入口 `python main.py …`、`python fetch_feed.py …` 照常可用，轉接到這裡。

設定一律走 .vscode/launch.json 的 config，不要在 PowerShell 下 $env:（變數留在整個
session，跑完 A/A 對照批忘了改回來，下一批會沿用且毫無提示）。某個 CSV 是哪種設定跑的，
以 csv_reports/run_*.json（manifest）為準。
"""
import argparse
import json
import os
import re
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from reporting.console import ensure_utf8_console

ensure_utf8_console()

BASE_DIR = Path(__file__).resolve().parent
CSV_DIR = BASE_DIR / "csv_reports"


class Run:
    """一次執行的上下文：run_id、觀察設定快照、來源批次。

    取代 v2 main.py 的模組全域變數：設定在開跑時讀一次環境變數，之後整批共用同一份
    快照（寫進 manifest 與每一列），中途改環境變數不會讓同一批混入兩種設定。
    """

    def __init__(self, settings=None, run_id=None):
        from crawler.plan import ObservationSettings
        self.run_id = run_id or uuid.uuid4().hex
        self.settings = settings or ObservationSettings.from_env()
        self.batch_manifest, self.source_records = {}, {}
        self.save_pairs = os.environ.get("SAVE_PAIR_HTML") == "1"

    def select_batch(self, path):
        """改用不可變快照的逐列來源（讀取前驗證雜湊）。回傳快照的 URL 順序。"""
        from feeds.snapshot import load_batch
        from schemas.evidence import sha256
        manifest, records = load_batch(path)
        self.batch_manifest = {**manifest, "snapshot_path": str(Path(path).resolve()),
                               "manifest_sha256": sha256((Path(path) / "manifest.json").read_bytes())}
        self.source_records = records
        return list(records)

    def initial_state(self, url):
        from graph import create_initial_state
        return create_initial_state(url, self.source_records.get(url), self.run_id, self.settings)

    def write_manifest(self, urls, csv_dir, started_at):
        from reporting.manifest import write_manifest
        return write_manifest(run_id=self.run_id, urls=urls, csv_dir=csv_dir, started_at=started_at,
                              settings=self.settings, batch_manifest=self.batch_manifest,
                              n_labels=sum(1 for r in self.source_records.values() if r.get("label")),
                              outputs={"save_pair_html": self.save_pairs})


def failure_row(run, url, error):
    """管線例外時的一列：與成功列同一個投影（欄位必然相同）、帶來源、照樣寫稽核。"""
    from nodes.node5_output import output_node
    from reporting.rows import result_row
    state = run.initial_state(url)
    state.update(alive=None, errors=[error], phishing_reason=error, cloaking_reason=error)
    output_node(state)
    return result_row(state)


def _save_report(row, output_dir, idx):
    safe = row["url"].replace("://", "_").replace("/", "_")
    safe = re.sub(r'[\\?%*:|"<>]', "_", safe).strip(". ")[:60]   # Windows 保留字元
    (Path(output_dir) / f"{idx + 1:03d}_{safe}.md").write_text(row["report"], encoding="utf-8")


def _timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def analyze_url(url, run=None):
    """單一 URL：寫 manifest、跑整條管線，回傳最終 state。"""
    from graph import get_graph
    run = run or Run()
    CSV_DIR.mkdir(exist_ok=True)
    run.write_manifest([url], CSV_DIR, _timestamp())
    return get_graph().invoke(run.initial_state(url))


def analyze_batch(urls, run=None, output_dir=BASE_DIR / "results", save_csv=True,
                  save_individual_reports=True, max_concurrent=1):
    """批次分析。max_concurrent 預設 1：降低目標負載與本機 Ollama 的並行負荷。"""
    from graph import get_graph
    from reporting.console import observation_status, print_summary
    from reporting.csv_io import write_csv
    from reporting.manifest import git_state
    from reporting.pairs import save_pair
    from reporting.rows import BATCH_FIELDS, result_row

    run = run or Run()
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    manifest = run.write_manifest(urls, CSV_DIR, _timestamp())
    print(f"[run manifest] {manifest.name} | pair={run.settings.pair_mode} | "
          f"order={run.settings.crawl_order} | variants={','.join(run.settings.variants) or '-'}")
    egress = json.loads(manifest.read_text(encoding="utf-8"))["egress"]
    # 標籤與 SSID 印在一起：選錯網路不會有任何錯誤訊息，開跑時肉眼對一次是唯一的檢查點
    print(f"[egress] label={egress['label'] or '(未設定)'} | wifi_ssid={','.join(egress['wifi_ssid']) or '-'}")
    if not egress["label"]:
        print("[!] EGRESS_LABEL 未設定 —— 這批走哪個出口網路不會留下紀錄；請用 launch.json 的 config 執行。",
              flush=True)
    git = git_state()
    if git.get("git_dirty"):
        # 在批次開頭就吵：跑完五小時才發現 manifest 指著錯的 commit 就來不及了
        print(f"[!] 工作區有 {git['git_dirty_files']} 個未提交/未追蹤的檔案 —— manifest 的 commit "
              f"{git['git_commit'][:8]} 不是這批實際跑的程式碼；以 code_sha256 為準。", flush=True)
    app, total = get_graph(), len(urls)
    results = [None] * total

    def process(idx, url):
        try:
            state = app.invoke(run.initial_state(url))
            row = result_row(state)
            row["status"] = observation_status(row)
            if run.save_pairs:
                save_pair(state)
        except Exception as exc:
            row = failure_row(run, url, f"{type(exc).__name__}: {exc}")
            row["status"] = f"❌ 失敗: {exc}"
        if save_individual_reports and row.get("report"):
            _save_report(row, output_dir, idx)
        return idx, row

    lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
        futures = [executor.submit(process, idx, url) for idx, url in enumerate(urls)]
        for future in as_completed(futures):
            idx, row = future.result()
            with lock:
                results[idx] = row
                done = sum(r is not None for r in results)
            print(f"[{done}/{total}] {row['status']} {row['url'][:80]}", flush=True)
    print_summary(results)
    if save_csv:
        path = write_csv(results, CSV_DIR / f"batch_results_{_timestamp()}.csv", BATCH_FIELDS)
        print(f"\n✅ CSV 已儲存: {path}")
    return results


def resolve_urls(args, run):
    """--url > --batch > 根目錄 urls.txt（若與 active_batch.json 指向的快照一致，沿用其來源）。"""
    from feeds.snapshot import select_active_batch
    if args.url:
        urls = [args.url]
    elif args.batch:
        batch = Path(args.batch).resolve()
        run.select_batch(batch)
        urls = [u.strip() for u in (batch / "urls.txt").read_text(encoding="utf-8").splitlines() if u.strip()]
    else:
        urls_file = BASE_DIR / "urls.txt"
        batch = select_active_batch(urls_file, BASE_DIR / "active_batch.json")
        if batch:
            run.select_batch(batch)
        if not urls_file.exists():
            urls_file.write_text("# 每行填入一個網址，# 開頭為註解\nhttps://example.com\n", encoding="utf-8")
            print(f"[提示] 已建立 {urls_file}，請填入要分析的網址後再執行。")
            return []
        urls = [line.strip() for line in urls_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.startswith("#")]
    if args.limit:
        # 冒煙測試用：不必為了跑 15 筆去改 urls.txt（改了就得記得改回來）
        urls = urls[:args.limit]
        print(f"[--limit] 只取前 {len(urls)} 筆")
    return urls


def cmd_run(args):
    from crawler.browser import preflight
    from reporting.rows import result_row
    run = Run()
    urls = resolve_urls(args, run)
    if not urls:
        print("[提示] 沒有網址可分析。")
        return 0
    if "browser" in run.settings.record()["slots"].values() or "mobile" in run.settings.variants:
        try:
            preflight()
        except RuntimeError as exc:
            print(f"[啟動檢查失敗] {exc}", file=sys.stderr)
            return 2
    if len(urls) == 1:
        state = analyze_url(urls[0], run)
        print(state["report"])
        out = result_row(state)
        out.pop("report", None)
        CSV_DIR.mkdir(exist_ok=True)
        (CSV_DIR / "result.json").write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    else:
        analyze_batch(urls, run)
    return 0


def cmd_fetch_feed(args):
    from feeds.phishunt import import_feed
    from feeds.snapshot import write_legacy_projections
    batch = import_feed(args.snapshot_root, limit=args.limit, input_path=args.input)
    records = write_legacy_projections(batch, args.project_root)
    print(f"Saved {len(records)} suspicious source records (not ground truth): {batch}")
    print(f'Analyze exact snapshot: .venv\\Scripts\\python.exe cli.py run --batch "{batch}"')
    return 0


def cmd_evaluate(args):
    import evaluate
    return evaluate.main(([args.csv] if args.csv else []) + (["--baseline", args.baseline] if args.baseline else []))


def cmd_check(_args):
    """只檢查本機：Chromium 能否啟動、Ollama 服務與模型是否存在（不送任何頁面內容）。"""
    import requests
    import llm
    from crawler.browser import preflight
    try:
        preflight()
        print("Playwright Chromium：可啟動")
    except RuntimeError as exc:
        print(f"Playwright Chromium：{exc}")
    if llm.providers.DISABLED_REASON:
        print(f"LLM：停用（{llm.providers.DISABLED_REASON}）—— llm_* 欄位會是 unavailable，規則判定不受影響")
        return 0
    base = llm.CONFIG["base_url"].rstrip("/")
    try:
        with requests.Session() as session:
            session.trust_env = False
            version = session.get(base + "/api/version", timeout=5, allow_redirects=False).json()
            models = session.get(base + "/api/tags", timeout=5, allow_redirects=False).json().get("models", [])
        names = {llm.MODEL_NAME, llm.MODEL_NAME + ":latest"}
        found = next((m for m in models if m.get("name") in names or m.get("model") in names), None)
        print(f"Ollama：{base} 版本 {version.get('version', '?')}；模型 {llm.MODEL_NAME} "
              + (f"已安裝（digest {found.get('digest', '?')[:12]}）" if found else "未安裝（不會自動下載）"))
    except (requests.RequestException, ValueError) as exc:
        print(f"Ollama：無法連線 {base}（{type(exc).__name__}）—— 執行時模型欄位記為 unavailable")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(description="Defensive phishing / cloaking measurement (v3)")
    sub = parser.add_subparsers(dest="command", required=True)
    feed = sub.add_parser("fetch-feed", help="import https://phishunt.io/feed.txt into an immutable snapshot")
    feed.add_argument("limit", nargs="?", type=int, default=300)
    feed.add_argument("--input", type=Path, help="offline saved feed; no network")
    feed.add_argument("--snapshot-root", type=Path, default=BASE_DIR / "feed_batches")
    feed.add_argument("--project-root", type=Path, default=BASE_DIR, help=argparse.SUPPRESS)
    feed.set_defaults(func=cmd_fetch_feed)
    run = sub.add_parser("run", help="observe and label URLs")
    run.add_argument("--batch", help="feed_batches/<batch_id> snapshot directory")
    run.add_argument("--limit", type=int, default=0)
    run.add_argument("--url", help="analyze a single URL (unlabeled source)")
    run.set_defaults(func=cmd_run)
    ev = sub.add_parser("evaluate", help="summarize a batch_results CSV")
    ev.add_argument("csv", nargs="?")
    ev.add_argument("--baseline")
    ev.set_defaults(func=cmd_evaluate)
    check = sub.add_parser("check", help="check local Chromium and Ollama (no external network)")
    check.set_defaults(func=cmd_check)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
