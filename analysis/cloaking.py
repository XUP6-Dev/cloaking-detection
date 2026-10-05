"""Cloaking 判定：兩種 client 收到的伺服器原始文件 → 機制集合差（C1–C5）→ 觀察品質與
替代解釋閘門 → 三態標籤。全布林、無加權、無閾值，而且**不收 llm 參數** ——
換模型或停用模型，這裡的輸出一模一樣。

本專案的 cloaking 定義（v3）：同一個 URL、同一個出口、同一段時間內，伺服器（或頁面）依
client 類型（非瀏覽器 HTTP client ↔ 執行 JS 的瀏覽器）遞送不同內容，且差異涉及 φ 認得的
惡意機制，並在兩組交錯觀察中重現。

三層輸出：
  rule_label  只看主配對（bot#1 ↔ human#1）的 C1–C5，閘門之前
  label       rule_label 經過下列閘門；任何一條不成立就是 unknown，附上全部理由
  reasons     閘門理由（代碼）—— unknown 的「為什麼」
"""
import copy
import difflib
import functools
import hashlib
import re

from analysis.page_mechanisms import HIGH_SPECIFICITY_MECHANISMS
from analysis.page_mechanisms import evaluate_page as _evaluate_page_uncached
from crawler.records import observation_issues
from feeds.urls import host_of
from schemas.evidence import sha256


# ── φ 的記憶化包裝 ───────────────────────────────────────────────
# 一個 URL 的分析會對同一份 HTML 評估多次（主文件、DOM、兩次重複、訊號表）。φ 是純函式，
# 快取不改變結果；回傳深複本，呼叫端改動回傳值不會汙染快取。
@functools.lru_cache(maxsize=24)
def _phi(html, url, extra_js):
    return _evaluate_page_uncached(html, url, extra_js=extra_js)


def evaluate_page(html, url="", extra_js=""):
    return copy.deepcopy(_phi(html or "", url or "", extra_js or ""))


# ── 動態規則 C1–C5（v1/v2 原樣搬移，邏輯未改）──────────────────────
def _simhash(text: str, bits: int = 64) -> int:
    if not text:
        return 0
    tokens = [text[i:i+4] for i in range(len(text) - 3)]
    v = [0] * bits
    for t in tokens:
        h = int(hashlib.md5(t.encode("utf-8", errors="ignore")).hexdigest(), 16)
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    return sum(1 << i for i in range(bits) if v[i] > 0)


def _similarity_score(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    sh_sim  = 1.0 - bin(_simhash(a) ^ _simhash(b)).count("1") / 64.0
    seq_sim = difflib.SequenceMatcher(None, a[:5000], b[:5000]).ratio()
    return sh_sim * 0.6 + seq_sim * 0.4


def _redirect_forked(chain_a: list, chain_b: list) -> bool:
    def domain(url):
        m = re.search(r"https?://([^/]+)", url)
        return m.group(1) if m else url
    return bool(chain_a and chain_b and domain(chain_a[-1]) != domain(chain_b[-1]))


_FORM_ACTION_RE = re.compile(r'<form[^>]+action\s*=\s*["\']([^"\']+)', re.I)
_SCRIPT_SRC_RE  = re.compile(r'<script[^>]+src\s*=\s*["\']([^"\']+)', re.I)


def _hosts(pattern, html: str) -> set:
    out = set()
    for u in pattern.findall(html or ""):
        m = re.match(r"https?://([^/]+)", u)
        if m:
            out.add(m.group(1).lower())
    return out


def _structural_divergence(bot_html: str, human_html: str) -> list:
    """兩端結構是否分歧到「不能宣稱看到的是同一個頁面」。純描述，不裁決。

    刻意不用 content_similarity：相似度低的最大宗是多語言／個人化／輪播，那是文字層差異，
    不代表遞送了不同的東西。這裡看的是結構性證據 —— 表單送去哪、腳本從哪來。
    """
    reasons = []
    bf, hf = _hosts(_FORM_ACTION_RE, bot_html), _hosts(_FORM_ACTION_RE, human_html)
    if bf and hf and not (bf & hf):
        reasons.append(f"form_action_hosts_disjoint({sorted(bf)}≠{sorted(hf)})")
    if bool(hf) != bool(bf):
        reasons.append("form_presence_differs")
    bs, hs = _hosts(_SCRIPT_SRC_RE, bot_html), _hosts(_SCRIPT_SRC_RE, human_html)
    if bs and hs:
        jac = len(bs & hs) / len(bs | hs)
        if jac < 0.34:
            reasons.append(f"script_hosts_jaccard={jac:.2f}")
    return reasons


def decide_cloaking(bot_result: dict, human_result: dict, url: str) -> dict:
    """
    純函式：比對 BOT 與 HUMAN 兩份頁面，判定是否為 Cloaking。全布林，無加權無閾值。

    v3：bot = 基準 HTTP、human = 瀏覽器，兩邊傳入的 html 都是「伺服器送來的主文件」
    （同一層）。拿原始文件去比渲染後 DOM，會把 JS 渲染誤讀成差別遞送。

    判準沿用釣魚偵測（evaluate_page），對兩份 HTML 各跑一次，比的是「惡意機制的有無」，
    不是文字長得像不像。相似度低 ≠ cloaking（多語言、A/B test、個人化）；相似度高 ≠ 沒有
    cloaking（只換表單 action 或塞一支外洩腳本可以到 0.98）。相似度只作描述性數據。
    """
    bot_text   = bot_result.get("text_content", "")
    human_text = human_result.get("text_content", "")

    bot_eval   = evaluate_page(bot_result.get("html", ""), bot_result.get("final_url") or url)
    human_eval = evaluate_page(human_result.get("html", ""), human_result.get("final_url") or url)
    bot_mech   = bot_eval["mechanisms"]
    human_mech = human_eval["mechanisms"]
    hidden_from_bot = sorted(human_mech - bot_mech)   # 只給瀏覽器看的惡意機制
    shown_to_both   = sorted(human_mech & bot_mech)
    # 反向差：BOT 看到而 HUMAN 沒看到的機制。不參與 C1–C5，而是**實驗設定失效**的證據：
    # per-IP burn-after-read 的 kit 會把真內容燒在先到的那一次（兩端同出口，IP 刻意不極化），
    # 這個效應無法從設計上排除，只能量它 —— 閘門把它當成 unknown 的理由。
    reverse_diff    = sorted(bot_mech - human_mech)

    bot_sc      = bot_result.get("status_code", 0)
    human_sc    = human_result.get("status_code", 0)
    bot_chain   = bot_result.get("redirect_chain", [])
    human_chain = human_result.get("redirect_chain", [])
    redirect_fork = _redirect_forked(bot_chain, human_chain)
    bot_err   = bot_result.get("error",   "") or ""
    human_err = human_result.get("error", "") or ""

    # C2–C4 的分離條件：BOT 端被擋只證明「對爬蟲有差別待遇」，不證明「藏了什麼」。
    # 合法大站的 WAF 對非瀏覽器 client 一樣回 403 —— 那是反爬蟲，不是 cloaking。
    # 差分要成立，HUMAN 端必須真的落在含**高特異性**惡意機制的頁面上（登入框、品牌圖
    # 這類頁面特徵任何登入頁都有，撐不起「這頁真的有惡意」的絕對判斷）。
    # PhiUSIIL 前 1000 筆實測：未加此條件時合法站陽性率 11.3% > 釣魚站 8.3%。
    human_high_spec = sorted(human_mech & HIGH_SPECIFICITY_MECHANISMS)
    human_malicious = bool(human_high_spec)

    bot_channel_blocked = (
        (bot_sc in (403, 404, 503) and human_sc == 200)
        or ("ERR_HTTP2_PROTOCOL_ERROR" in bot_err and not human_err)
        or (bool(human_text) and not bot_text and not bot_err)
    )

    # C1 的前提：BOT 真的拿到一份頁面。BOT 吃了 403 或空頁時，「BOT 沒有 cred_form」為真
    # 只是因為它什麼都沒拿到。不修的話 C1 會吞掉 C2–C4：C1 管「兩邊都看得到但內容不同」，
    # C2–C4 管「BOT 根本看不到，而 HUMAN 端確實是惡意頁」。
    bot_observed = bool(bot_text) and not bot_err and bot_sc not in (403, 404, 503)

    # 證據字串保留 v1 的「真人」用語（歷史名稱 = human 槽），與舊稽核紀錄逐字一致。
    decisions = [
        ("C1", bool(hidden_from_bot) and bot_observed,
         f"BOT 與 HUMAN 都取得頁面，但 HUMAN 多出惡意機制 → 只對真人展開攻擊: {hidden_from_bot}"),
        ("C2", bot_sc in (403, 404, 503) and human_sc == 200 and human_malicious,
         f"爬蟲被封鎖 HTTP {bot_sc}，真人正常 HTTP {human_sc} 且頁面含高特異性機制 {human_high_spec}"),
        ("C3", "ERR_HTTP2_PROTOCOL_ERROR" in bot_err and not human_err and human_malicious,
         f"爬蟲被 HTTP/2 協議層中斷 (RST_STREAM/GOAWAY)，真人正常訪問且頁面含高特異性機制 {human_high_spec}"),
        ("C4", bool(human_text) and not bot_text and not bot_err and human_malicious,
         f"爬蟲取得空頁面，真人取得含高特異性機制 {human_high_spec} 的完整內容"),
        ("C5", redirect_fork and bool(human_mech) and not bot_mech,
         f"Redirect 分叉且只有真人端落在含惡意機制的頁面: "
         f"BOT->{bot_chain[-1] if bot_chain else 'N/A'} | "
         f"HUMAN->{human_chain[-1] if human_chain else 'N/A'}"),
    ]
    evidence, fired = [], []
    for rule_id, cond, label in decisions:
        if cond:
            fired.append(rule_id)
            evidence.append(f"[{rule_id}] {label}")

    verified = bool(fired)

    # ── 明確記錄「不是 cloaking」的情形 ────────────────────────
    if not verified:
        if shown_to_both:
            evidence.append(
                f"BOT 與 HUMAN 看到相同的惡意機制 {shown_to_both} → "
                f"是釣魚頁但未對爬蟲隱藏，非 Cloaking"
            )
        elif not human_mech:
            evidence.append("兩端皆未偵測到惡意機制 → 非 Cloaking")
        if bot_channel_blocked and not human_malicious:
            detail = (f"真人端只有頁面特徵類機制 {sorted(human_mech)}（登入框 / 品牌圖等，"
                      f"合法網站也有）" if human_mech else "真人端頁面無任何惡意機制")
            evidence.append(
                f"BOT 端被差別對待（HTTP {bot_sc} / 協議中斷 / 空頁）但{detail} "
                f"→ 判為反爬蟲（WAF / rate limit），非 Cloaking"
            )
        if redirect_fork:
            evidence.append(
                "Redirect 分叉但兩端惡意機制相同 → 疑似正常地理/裝置導向，非 Cloaking"
            )

    return {
        "verified":           verified,
        "fired":              fired,
        "evidence":           evidence,
        "bot_mechanisms":     bot_mech,
        "human_mechanisms":   human_mech,
        "hidden_from_bot":    hidden_from_bot,
        "reverse_diff":       reverse_diff,
        "bot_channel_blocked": bot_channel_blocked,
        "redirect_fork":      redirect_fork,
        "bot_eval":           bot_eval,
        "human_eval":         human_eval,
        "content_similarity": _similarity_score(bot_text, human_text),
    }


# ── 可比較的特徵（全部是離散值，沒有相似度門檻）──────────────────────
STABLE_KEYS = ("status", "final_host", "mechanisms")
SYSTEMATIC_KEYS = STABLE_KEYS + ("title", "form_hosts", "script_hosts", "html_sha256")


def features(record, view="html"):
    """一次觀察在比較時用的離散特徵。view="html" = 伺服器主文件；"dom" = JS 執行後。"""
    record = record or {}
    if view == "dom":
        html, text = record.get("dom_html") or "", record.get("dom_text") or ""
        url, title = record.get("page_url") or record.get("final_url") or "", record.get("dom_title") or ""
    else:
        html, text = record.get("html") or "", record.get("text_content") or ""
        url, title = record.get("final_url") or "", record.get("title") or ""
    evaluation = evaluate_page(html, url)
    return {"status": record.get("status_code") or 0, "final_host": host_of(url),
            "title": " ".join(title.split()).lower(),
            "mechanisms": frozenset(evaluation["mechanisms"]),
            "form_hosts": frozenset(_hosts(_FORM_ACTION_RE, html)),
            "script_hosts": frozenset(_hosts(_SCRIPT_SRC_RE, html)),
            "html_sha256": sha256(html), "text_sha256": sha256(" ".join(text.split()).lower()),
            "text_length": len(text), "is_phishing": evaluation["is_phishing"]}


def systematic_differences(b1, b2, h1, h2, keys=SYSTEMATIC_KEYS):
    """同側兩次相同、兩側不同的特徵 = 隨 client 類型系統性改變的特徵。
    同側兩次就不同的特徵（例如每次請求都換的 nonce）解釋不了任何事，不列入。"""
    return [k for k in keys if b1[k] == b2[k] and h1[k] == h2[k] and b1[k] != h1[k]]


# ── 閘門 ─────────────────────────────────────────────────────────
_DOCUMENT_UNUSABLE = frozenset({"missing_observation", "crawl_error", "empty_document",
                                "non_html_document", "document_body_unavailable"})
# 規則能不能跑：BOT 端空文件就是 C4 要的證據，所以只有「根本沒回應」才算不能跑。
_RULE_UNUSABLE_BOT = frozenset({"missing_observation", "crawl_error", "non_html_document"})
# true 的閘門：HUMAN 端必須是完整、可讀、非挑戰頁的 2xx 文件；
# BOT 端的 403／空頁／挑戰頁正是 C2／C4 的證據，只排除「沒回應」與截斷。
_TRUE_BLOCKERS_HUMAN = _DOCUMENT_UNUSABLE | {"http_error_status", "challenge_or_block_page",
                                             "content_truncated"}
_TRUE_BLOCKERS_BOT = frozenset({"missing_observation", "crawl_error", "non_html_document",
                                "content_truncated"})
# false 的閘門：四次觀察都要是完整、可讀的 2xx 文件，且沒有挑戰頁或互動閘門 ——
# 閘門後面的內容可能由我們從未送出的請求取得，在那裡分流我們看不到。
_FALSE_BLOCKERS = _DOCUMENT_UNUSABLE | {"http_error_status", "challenge_or_block_page",
                                        "interaction_gate", "content_truncated"}


def _tagged(name, issues, allowed, skip=()):
    return [f"{name}:{issue}" for issue in sorted(issues & allowed) if issue not in skip]


def label_cloaking(bot, human, url, *, frontend_rules=(), variant_differences=()):
    """三態 cloaking 標籤。bot/human 是兩槽的主觀察，第二次觀察在 ["confirmation"]。

    frontend_rules       靜態 S1–S3 命中（頁面有能力只對特定 client 換內容）→ 擋 false
    variant_differences  referer／mobile 變體出現差異但只有單次觀察 → 擋 false
    """
    b1, h1 = bot or {}, human or {}
    b2, h2 = b1.get("confirmation") or {}, h1.get("confirmation") or {}
    observations = {"bot#1": b1, "bot#2": b2, "human#1": h1, "human#2": h2}
    issues = {name: set(observation_issues(rec, view="html")) for name, rec in observations.items()}
    primary = decide_cloaking(b1, h1, url)
    replicate = decide_cloaking(b2, h2, url) if (b2 and h2) else None
    protocol_reset = ("crawl_error",) if "C3" in primary["fired"] else ()

    rule_blockers = (_tagged("bot#1", issues["bot#1"], _RULE_UNUSABLE_BOT, protocol_reset)
                     + _tagged("human#1", issues["human#1"], _DOCUMENT_UNUSABLE))
    rule_label = "unknown" if rule_blockers else ("true" if primary["fired"] else "false")

    reasons = []
    if rule_label == "unknown":
        reasons = rule_blockers
    elif rule_label == "true":
        for name in ("human#1", "human#2"):
            reasons += _tagged(name, issues[name], _TRUE_BLOCKERS_HUMAN)
        for name in ("bot#1", "bot#2"):
            reasons += _tagged(name, issues[name], _TRUE_BLOCKERS_BOT, protocol_reset)
        if replicate is None:
            reasons.append("missing_replicate_pair")
        elif (replicate["fired"], replicate["hidden_from_bot"]) != (primary["fired"], primary["hidden_from_bot"]):
            reasons.append("difference_not_replicated")
        if not set(primary["hidden_from_bot"]) & HIGH_SPECIFICITY_MECHANISMS:
            reasons.append("difference_without_high_specificity_evidence")
    else:
        for name in observations:
            reasons += _tagged(name, issues[name], _FALSE_BLOCKERS)
        if replicate is None:
            reasons.append("missing_replicate_pair")
        elif replicate["fired"]:
            reasons.append("difference_not_replicated")
        if not reasons:     # 四份文件都可比，才檢查穩定性與系統性差異
            f = {name: features(rec) for name, rec in observations.items()}
            for side in ("bot", "human"):
                reasons += [f"{side}_unstable_{key}" for key in STABLE_KEYS
                            if f[f"{side}#1"][key] != f[f"{side}#2"][key]]
            reasons += [f"systematic_{key}_difference_without_mechanism_evidence"
                        for key in systematic_differences(f["bot#1"], f["bot#2"],
                                                          f["human#1"], f["human#2"])]
            # 只在 JS 執行後才出現的機制從未跨 client 比較過（基準端不執行 JS）
            for name, rec in observations.items():
                if rec.get("dom_html") and features(rec, "dom")["mechanisms"] - f[name]["mechanisms"]:
                    reasons.append(f"{name}:js_rendered_mechanisms_not_compared")
        if frontend_rules:
            reasons.append("frontend_cloaking_code_present:" + ",".join(frontend_rules))
        reasons += [f"variant_difference_unconfirmed:{name}" for name in variant_differences]
    if rule_label != "unknown" and (primary["reverse_diff"] or (replicate and replicate["reverse_diff"])):
        reasons.append("reverse_difference_or_order_effect")

    reasons = list(dict.fromkeys(reasons))        # 去重但保留順序
    label = rule_label if rule_label != "unknown" and not reasons else "unknown"
    if label == "true":
        basis = (f"rules={'+'.join(primary['fired'])} in both interleaved pairs; "
                 f"hidden_from_bot={primary['hidden_from_bot']}")
        reason = "replicated_client_type_mechanism_difference"
    elif label == "false":
        basis = ("no C1-C5 rule in either pair; same status/host/mechanisms/structure across client "
                 "types; stable within each side")
        reason = "not_observed_in_tested_client_types"
    else:
        basis = f"rule={rule_label}; gated by {len(reasons)} reason(s)"
        reason = ";".join(reasons)
    return {"rule_label": rule_label, "label": label, "reasons": reasons, "basis": basis,
            "reason": reason, "primary": primary, "replicate": replicate,
            "issues": {name: sorted(values) for name, values in issues.items()}}


def legacy_dual_results(decision, bot, human):
    """舊診斷欄（bot_*/human_* 與 C1–C5 原始結果）的來源，取主配對。"""
    primary = decision["primary"]
    dual = {"bot_mechanisms": sorted(primary["bot_mechanisms"]),
            "human_mechanisms": sorted(primary["human_mechanisms"]),
            "human_high_spec": sorted(primary["human_mechanisms"] & HIGH_SPECIFICITY_MECHANISMS),
            "hidden_from_bot": primary["hidden_from_bot"], "reverse_diff": primary["reverse_diff"],
            # C1–C5 原始觸發（未經閘門）—— A/A 對照批唯一可比的欄位
            "rule_fired_raw": bool(primary["fired"]), "fired_rules": primary["fired"],
            "bot_channel_blocked": primary["bot_channel_blocked"],
            "bot_is_phishing": primary["bot_eval"]["is_phishing"],
            "human_is_phishing": primary["human_eval"]["is_phishing"],
            "evidence": {"raw_rule_evidence": primary["evidence"],
                         "replicate_rule_evidence": (decision["replicate"] or {}).get("evidence", []),
                         "comparability_issues": decision["reasons"]},
            "dynamic_reliability": "HIGH" if decision["label"] in ("true", "false") else "LOW",
            "content_similarity": primary["content_similarity"], "reason": decision["reason"]}
    for slot, record in (("bot", bot or {}), ("human", human or {})):
        for key in ("status_code", "html_length", "error"):
            dual[f"{slot}_{key}"] = record.get(key)
    return dual
