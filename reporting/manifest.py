"""執行 manifest：csv_reports/run_<started_at>_<run_id>.json —— 某個 CSV 到底是哪種設定、
哪份程式碼、哪個模型跑出來的，以這個檔為準（不是以 launch.json 或記憶為準）。

沒有它，半年後沒人說得出某個 CSV 是哪種設定跑出來的；而改了任何一個預設值之後跑出來的
批次不能合併統計，沒有任何東西會提醒你。
"""
import hashlib
import json
import locale
import os
import re
import subprocess
import sys
from importlib.metadata import distributions
from pathlib import Path

from schemas.evidence import sha256, utc_now
from schemas.versions import MEASUREMENT_VERSION, RULE_VERSION, SCHEMA_VERSION

BASE_DIR = Path(__file__).resolve().parents[1]
CODE_DIRS = ("", "feeds", "crawler", "analysis", "llm", "schemas", "reporting", "nodes")


def git_state():
    """HEAD 的 commit ＋ 工作區是否乾淨。只記 commit 不夠：有未提交變更時，那個 hash 指向的
    不是實際在跑的程式碼。沒有 .git 時兩欄留空，改以 code_sha256 稽核。"""
    def run(*args):
        return subprocess.check_output(args, cwd=BASE_DIR, stderr=subprocess.DEVNULL).decode().strip()
    try:
        commit = run("git", "rev-parse", "HEAD")
    except Exception:
        return {"git_commit": "", "git_dirty": None}
    try:
        porcelain = run("git", "status", "--porcelain")
        return {"git_commit": commit, "git_dirty": bool(porcelain),
                "git_dirty_files": len(porcelain.splitlines()) if porcelain else 0}
    except Exception:
        return {"git_commit": commit, "git_dirty": None}


def code_hashes():
    hashes = {}
    for folder in CODE_DIRS:
        for path in sorted((BASE_DIR / folder).glob("*.py")):
            hashes[str(path.relative_to(BASE_DIR))] = sha256(path.read_bytes())
    return hashes


def wifi_ssids():
    """本機目前連上的 Wi-Fi SSID（`netsh wlan show interfaces`），給 EGRESS_LABEL 當旁證。

    只讀本機網卡狀態、不連外 —— 查公網 IP / ASN 要把本機出口送給第三方服務，而且那才是
    真正的出口量測，不該偷偷塞在 manifest 裡做。有線網路、非 Windows、或系統沒給定位權限
    （新版 Windows 讀 SSID 需要）時回傳空清單，不讓批次因此失敗。"""
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=5)
    except Exception:
        return []
    # netsh 用 OEM code page 輸出（zh-TW 是 cp950），不是 UTF-8
    text = out.stdout.decode(locale.getpreferredencoding(False), errors="replace")
    return [m.group(1).strip() for m in re.finditer(r"^\s*SSID\s*:\s*(.+)$", text, re.M)]


def egress_record(env=None):
    """出口網路：自報標籤 ＋ 本機旁證。

    兩種 client 共用同一出口（profile 的 egress_policy），所以出口不是批內變因，而是批間的；
    但 egress_verification 是 not_measured，沒有這一欄的話，哪批走哪個網路只存在記憶裡。
    標籤刻意不進 run_config_sha256：它不改變儀器怎麼量，改了雜湊反而讓同設定的舊批對不上。
    代價是 evaluate 的合併檢查擋不住「不同網路的批次混在一起」，比較時要自己看這一欄。
    標籤是自報的 —— 選錯不會有錯誤訊息，所以旁邊放 SSID，讀的人可以自己對照。"""
    env = os.environ if env is None else env
    return {"label": env.get("EGRESS_LABEL", "").strip(), "label_source": "EGRESS_LABEL (self-reported)",
            "wifi_ssid": wifi_ssids(), "verification": "not_measured", "recorded": "at_run_start"}


def write_manifest(*, run_id, urls, csv_dir, started_at, settings, batch_manifest, n_labels, outputs=None):
    import llm
    record = settings.record()
    manifest = {
        "schema_version": SCHEMA_VERSION, "measurement_version": MEASUREMENT_VERSION,
        "rule_version": RULE_VERSION,
        "rule_sha256": sha256((BASE_DIR / "analysis" / "page_mechanisms.py").read_bytes()),
        "run_id": run_id, "observed_at": utc_now(), "started_at": started_at,
        "source_batch": batch_manifest,
        "observation_settings": record, "run_config_sha256": settings.config_sha256(),
        "profiles": record["profiles"],
        "egress": egress_record(),
        "llm_provider": llm.LLM_PROVIDER, "llm_model": llm.MODEL_NAME, "llm_config": llm.audit_config(),
        "authorized_test_origins": os.environ.get("AUTHORIZED_TEST_ORIGINS", "[]"),
        "test_authorization": os.environ.get("TEST_AUTHORIZATION", ""),
        "python_version": sys.version,
        "packages": {d.metadata["Name"]: d.version for d in distributions()},
        "code_sha256": code_hashes(), **git_state(),
        "url_list": (str(Path(batch_manifest["snapshot_path"]) / "urls.txt")
                     if batch_manifest.get("snapshot_path") else "urls.txt"),
        # 取自實際送進管線的清單，不是檔案 —— 檔案可能在跑的途中被改
        "url_list_sha256": hashlib.sha256("\n".join(urls).encode()).hexdigest(),
        "n_urls": len(urls), "n_labels": n_labels,
        "outputs": outputs or {},          # 例如 SAVE_PAIR_HTML
        # v2 相容鍵
        "human_profile": record["profiles"]["human"]["profile_id"],
        "pair_mode": settings.pair_mode, "crawl_order": settings.crawl_order,
        "observation_variants": list(settings.variants), "curl_cffi": False,
    }
    path = Path(csv_dir) / f"run_{started_at}_{run_id}.json"
    with path.open("x", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
    return path
