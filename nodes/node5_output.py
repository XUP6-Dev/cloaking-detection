"""Node 5：寫稽核 JSON、附加一列到本次的 summary CSV、產生文字報告。不呼叫模型。

為什麼沒有風險分數：判定已經在 Node 3 / Node 4 做完。再把兩個結論乘上權重合成一個
0~1 的數字，只是把明確的結論變回需要解釋的數字，而且那些權重沒有任何資料依據。
"""
from datetime import datetime
from pathlib import Path

from reporting.audit import finalize_audit
from reporting.csv_io import append_row
from reporting.rows import SUMMARY_FIELDS, summary_row
from schemas.labels import CLOAKING_UNKNOWN, cloaking_projection  # noqa: F401（相容匯出）

OUTPUT_DIR = Path(__file__).resolve().parents[1] / "csv_reports"
SESSION_CSV = OUTPUT_DIR / f"cloaking_report_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.csv"
FIELDNAMES = SUMMARY_FIELDS        # 前四欄固定為 url, alive, is_phishing, cloaking


def _cloaking_verdict(state):
    """相容介面（v2）：cloaking_label → True / False / "N/A"。"""
    return cloaking_projection(state.get("cloaking_label", "unknown"))


def report_text(state, row):
    cloak = {"true": "是", "false": "本次設定未觀察到"}.get(state.get("cloaking_label"), "無法判定")
    alive = {True: "是", False: "未檢查（網址無效）"}.get(row["alive"], "無法判定")
    return "\n".join([
        f"URL：{row['url']}",
        f"網站是否存活：{alive}",
        f"來源標籤：{row['source_label']}（威脅情資，非人工真值）",
        f"釣魚判定：{row['phishing_verdict']}（規則結果：{row['rule_phishing_verdict']}；"
        f"依據：{row['phishing_basis'] or '—'}）",
        f"是否有 Cloaking：{cloak}（規則結果：{row['rule_cloaking_label']}；依據：{row['cloaking_basis'] or '—'}）",
        f"模型分析（不影響標籤）：釣魚={row['llm_phishing_assessment']}／cloaking={row['llm_cloaking_assessment']}",
        f"不確定原因：{row['uncertainty_reasons']}",
        f"觀察訊號：{row['cloaking_signals'] or '—'}（本次未測：{row['cloaking_signals_not_tested'] or '—'}）",
        f"觀察順序：{row['observation_plan'] or '—'}",
        f"稽核紀錄：{row['evidence']}",
    ])


def output_node(state):
    print("\n[Node 5] 輸出報告...")
    finalize_audit(state)
    row = summary_row(state)
    SESSION_CSV.parent.mkdir(parents=True, exist_ok=True)
    if append_row(SESSION_CSV, FIELDNAMES, row):
        print(f"  → 建立新 CSV：{SESSION_CSV.name}")
    state["report"] = report_text(state, row)
    print(f"  → {row['url']} | 存活={row['alive']} | 釣魚={row['phishing_verdict']} | "
          f"Cloaking={row['cloaking_label']}")
    return state
