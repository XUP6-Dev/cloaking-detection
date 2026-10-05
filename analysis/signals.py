"""Cloaking 觀察訊號表：每個訊號保存實際觀察到的值；**任何單一訊號都不裁決 cloaking**。

類別（對應 README「Cloaking 訊號」）：
  ua_browser_type             User-Agent／瀏覽器類型不同時的 HTTP 回應、HTML、DOM 差異
  referer                     Referer 有無對回應或導向鏈的影響（變體；預設未測）
  device                      桌面與行動版面或內容差異（變體；預設未測）
  status_text_dom_js_errors   HTTP 狀態、頁面文字、DOM、JS 行為、錯誤訊息
  redirect_delay_blank_decoy  多段導向、前端導向、延遲載入、空白頁、錯誤頁、看似正常的替代頁
  repeat_observation          重複觀察的時間、存取次數、內容差異

status：
  observed      比較了，有差異或出現該現象（證據在 evidence）
  not_observed  比較了，沒有
  not_tested    本次設定沒有做這種觀察（例如變體未開）—— 不是「沒有」
  unmeasurable  該做的觀察失敗，無法比較

替代解釋（頁面更新、短暫故障、A/B 測試、非同步載入、存取順序）不在這裡排除，而是由
analysis/cloaking.py 的閘門處理：同側兩次不一致 → 不能歸因於 client 類型。
"""
import re
from datetime import datetime

from analysis.cloaking import (_similarity_score, _structural_divergence, evaluate_page, features,
                               systematic_differences)
from crawler.records import BLOCKING_ISSUES, observation_issues
from feeds.urls import host_of

_COMPARE_KEYS = ("status", "final_host", "title", "mechanisms", "form_hosts", "script_hosts",
                 "html_sha256", "text_sha256")
_MEANINGFUL_KEYS = ("status", "final_host", "title", "mechanisms", "form_hosts", "script_hosts")
_ERROR_TITLE = re.compile(r"\b(?:400|401|403|404|410|429|500|502|503)\b|not found|forbidden|"
                          r"access denied|error|suspended|unavailable|bad request|deactivated", re.I)


def _signal(signal_id, category, status, compared, evidence):
    return {"id": signal_id, "category": category, "status": status,
            "compared": list(compared), "evidence": evidence}


def _plain(value):
    return sorted(value) if isinstance(value, frozenset) else value


def _usable(record):
    return bool(record) and not set(observation_issues(record, view="html")) & BLOCKING_ISSUES


def _header(record, name):
    for key, value in (record.get("request_headers") or {}).items():
        if key.lower() == name:
            return value
    return ""


def _differences(fa, fb, keys=_COMPARE_KEYS):
    return {k: [_plain(fa[k]), _plain(fb[k])] for k in keys if fa[k] != fb[k]}


def _observations(bot, human):
    bot, human = bot or {}, human or {}
    named = {"bot#1": bot, "bot#2": bot.get("confirmation") or {},
             "human#1": human, "human#2": human.get("confirmation") or {}}
    return {name: rec for name, rec in named.items() if rec}


# ── ua_browser_type ──────────────────────────────────────────────
def _client_type(obs, f):
    pairs, evidence = [], {"user_agents": {n: _header(r, "user-agent") for n, r in obs.items()},
                           "client_kinds": {n: r.get("kind", "") for n, r in obs.items()}, "pairs": []}
    for a, b in (("bot#1", "human#1"), ("bot#2", "human#2")):
        if a in f and b in f:
            pairs.append((a, b))
            evidence["pairs"].append({
                "pair": f"{a}~{b}", "differences": _differences(f[a], f[b]),
                "text_similarity": round(_similarity_score(obs[a].get("text_content", ""),
                                                           obs[b].get("text_content", "")), 3),
                "structural_divergence": _structural_divergence(obs[a].get("html", ""), obs[b].get("html", ""))})
    if not pairs:
        return _signal("client_type_response_difference", "ua_browser_type", "unmeasurable", [], evidence)
    if len(f) == 4 and all(n in f for n in ("bot#1", "bot#2", "human#1", "human#2")):
        evidence["systematic"] = systematic_differences(f["bot#1"], f["bot#2"], f["human#1"], f["human#2"],
                                                        _COMPARE_KEYS)
    observed = any(set(p["differences"]) & set(_MEANINGFUL_KEYS) for p in evidence["pairs"]) \
        or bool(evidence.get("systematic"))
    return _signal("client_type_response_difference", "ua_browser_type",
                   "observed" if observed else "not_observed", [x for p in pairs for x in p], evidence)


# ── referer / device 變體 ────────────────────────────────────────
def _variant(signal_id, category, variant, controls, view, variants, obs):
    record = variants.get(variant)
    if record is None:
        return _signal(signal_id, category, "not_tested", [], {"reason": "variant_disabled"})
    usable = [c for c in controls if _usable(obs.get(c))]
    if not _usable(record) or not usable:
        return _signal(signal_id, category, "unmeasurable", [], {"variant_issues": observation_issues(record)})
    fv = features(record, view)
    fc = {c: features(obs[c], view) for c in usable}
    keys = ("status", "final_host", "mechanisms", "title")
    evidence = {"variant_profile": record.get("profile_id"),
                "referer_sent": _header(record, "referer"),
                "redirect_chains": {"variant": record.get("redirect_chain", []),
                                    **{c: obs[c].get("redirect_chain", []) for c in usable}},
                "differences": {c: _differences(fc[c], fv, keys) for c in usable}}
    # 只算「變體與每個對照都不同、且對照之間一致」的特徵：對照自己就不穩，差異解釋不了任何事。
    stable_controls = [k for k in keys if len({repr(fc[c][k]) for c in usable}) == 1]
    evidence["differs_from_all_controls"] = [k for k in stable_controls
                                             if all(fc[c][k] != fv[k] for c in usable)]
    evidence["replicated"] = False      # 變體只觀察一次
    status = "observed" if evidence["differs_from_all_controls"] else "not_observed"
    return _signal(signal_id, category, status, [f"variant:{variant}", *usable], evidence)


# ── status_text_dom_js_errors ────────────────────────────────────
def _status(obs):
    statuses = {n: r.get("status_code") or 0 for n, r in obs.items()}
    answered = [s for s in statuses.values() if s]
    if len(answered) < 2:
        return _signal("http_status_difference", "status_text_dom_js_errors", "unmeasurable", [],
                       {"statuses": statuses})
    return _signal("http_status_difference", "status_text_dom_js_errors",
                   "observed" if len(set(answered)) > 1 else "not_observed", list(statuses),
                   {"statuses": statuses})


def _text(obs, f):
    pairs = []
    for a, b in (("bot#1", "human#1"), ("bot#2", "human#2")):
        if a in f and b in f:
            pairs.append({"pair": f"{a}~{b}", "same_normalized_text": f[a]["text_sha256"] == f[b]["text_sha256"],
                          "text_length": [f[a]["text_length"], f[b]["text_length"]],
                          "similarity": round(_similarity_score(obs[a].get("text_content", ""),
                                                                obs[b].get("text_content", "")), 3),
                          "excerpts": [obs[a].get("text_content", "")[:160], obs[b].get("text_content", "")[:160]]})
    if not pairs:
        return _signal("visible_text_difference", "status_text_dom_js_errors", "unmeasurable", [], {})
    systematic = (len(pairs) == 2 and "text_sha256" in systematic_differences(
        f["bot#1"], f["bot#2"], f["human#1"], f["human#2"], ("text_sha256",)))
    status = "observed" if any(not p["same_normalized_text"] for p in pairs) else "not_observed"
    return _signal("visible_text_difference", "status_text_dom_js_errors", status,
                   [p["pair"] for p in pairs], {"pairs": pairs, "systematic": systematic})


def _js_dom(obs, f):
    rows = {}
    for name, rec in obs.items():
        if rec.get("kind") == "browser" and name in f and rec.get("dom_html"):
            fd = features(rec, "dom")
            rows[name] = {"mechanisms_added_by_js": sorted(fd["mechanisms"] - f[name]["mechanisms"]),
                          "mechanisms_removed_by_js": sorted(f[name]["mechanisms"] - fd["mechanisms"]),
                          "text_length": [f[name]["text_length"], fd["text_length"]],
                          "text_changed": f[name]["text_sha256"] != fd["text_sha256"],
                          "title": [f[name]["title"], fd["title"]]}
    if not rows:
        status = "not_tested" if not any(r.get("kind") == "browser" for r in obs.values()) else "unmeasurable"
        return _signal("js_modified_dom", "status_text_dom_js_errors", status, [], {})
    observed = any(r["mechanisms_added_by_js"] or r["mechanisms_removed_by_js"] or r["text_changed"]
                   for r in rows.values())
    return _signal("js_modified_dom", "status_text_dom_js_errors",
                   "observed" if observed else "not_observed", list(rows), rows)


def _scripts(obs):
    def inventory(rec):
        scripts = rec.get("scripts") or {}
        return ({s["sha256"] for s in scripts.get("inline", [])},
                {u.split("?")[0] for u in scripts.get("external", [])})
    pairs = []
    for a, b in (("bot#1", "human#1"), ("bot#2", "human#2")):
        if _usable(obs.get(a)) and _usable(obs.get(b)):
            (ia, ea), (ib, eb) = inventory(obs[a]), inventory(obs[b])
            pairs.append({"pair": f"{a}~{b}", "inline_only_bot": len(ia - ib), "inline_only_human": len(ib - ia),
                          "external_only_bot": sorted(ea - eb)[:10], "external_only_human": sorted(eb - ea)[:10]})
    if not pairs:
        return _signal("script_inventory_difference", "status_text_dom_js_errors", "unmeasurable", [], {})
    observed = any(p["inline_only_bot"] or p["inline_only_human"] or p["external_only_bot"]
                   or p["external_only_human"] for p in pairs)
    return _signal("script_inventory_difference", "status_text_dom_js_errors",
                   "observed" if observed else "not_observed", [p["pair"] for p in pairs], {"pairs": pairs})


def _frontend(static_rules, techniques):
    evidence = {"static_rules": list(static_rules),
                "categories": sorted(k for k in techniques if k != "static_rule"),
                "patterns": {k: v for k, v in techniques.items() if k != "static_rule"}}
    return _signal("frontend_cloaking_code", "status_text_dom_js_errors",
                   "observed" if static_rules else "not_observed", ["analysis_js"], evidence)


def _errors(obs):
    rows = {}
    for name, rec in obs.items():
        if rec.get("kind") == "browser":
            blocked = rec.get("blocked_requests") or []
            failed = rec.get("failed_requests") or []
            rows[name] = {"console_errors": len(rec.get("console_errors") or []),
                          "page_errors": (rec.get("page_errors") or [])[:3],
                          "failed_requests": len(failed),
                          "failed_content_affecting": sum(1 for r in failed if r.get("content_affecting", True)),
                          "blocked_requests": len(blocked),
                          "blocked_reasons": sorted({r.get("reason", "") for r in blocked}),
                          "blocked_content_affecting": sum(1 for r in blocked if r.get("content_affecting", True)),
                          "dialogs": len(rec.get("dialogs") or []), "downloads": len(rec.get("downloads") or []),
                          "popups": len(rec.get("popups") or []), "load_event": rec.get("load_event", "ok"),
                          "document_body_error": rec.get("document_body_error", ""),
                          "error": rec.get("error") or ""}
        else:
            rows[name] = {"error": rec.get("error") or "", "error_kind": rec.get("error_kind", "")}
    observed = any(any(v for k, v in row.items() if k != "load_event") or row.get("load_event") == "timeout"
                   for row in rows.values())
    return _signal("browser_errors", "status_text_dom_js_errors",
                   "observed" if observed else "not_observed", list(rows), rows)


# ── redirect_delay_blank_decoy ───────────────────────────────────
def _redirects(obs):
    rows = {}
    for name, rec in obs.items():
        chain = rec.get("redirect_chain") or []
        hosts = [host_of(u) for u in chain]
        rows[name] = {"hops": max(len(chain) - 1, 0), "hosts": hosts,
                      "cross_host": len(set(h for h in hosts if h)) > 1,
                      "statuses": [r.get("status") for r in rec.get("navigation_responses") or []]}
    observed = any(r["hops"] >= 2 or r["cross_host"] for r in rows.values())
    return _signal("multi_hop_redirect", "redirect_delay_blank_decoy",
                   "observed" if observed else "not_observed", list(rows), rows)


def _client_redirect(obs):
    rows = {name: {"final_url": rec.get("final_url"), "page_url": rec.get("page_url"),
                   "client_navigations": (rec.get("client_navigations") or [])[:10]}
            for name, rec in obs.items() if rec.get("kind") == "browser"}
    if not rows:
        return _signal("client_side_redirect", "redirect_delay_blank_decoy", "not_tested", [], {})
    observed = any(r["client_navigations"] or (r["page_url"] and r["page_url"] != r["final_url"])
                   for r in rows.values())
    return _signal("client_side_redirect", "redirect_delay_blank_decoy",
                   "observed" if observed else "not_observed", list(rows), rows)


def _delayed(obs):
    rows = {}
    for name, rec in obs.items():
        if rec.get("kind") == "browser" and rec.get("dom_snapshots"):
            early = evaluate_page(rec.get("dom_domcontentloaded_html", ""), rec.get("page_url", ""))["mechanisms"]
            late = features(rec, "dom")["mechanisms"]
            rows[name] = {"snapshots": rec["dom_snapshots"],
                          "mechanisms_after_domcontentloaded": sorted(late - early)}
    if not rows:
        return _signal("delayed_content", "redirect_delay_blank_decoy", "not_tested", [], {})

    def delayed(row):
        first, last = row["snapshots"][0], row["snapshots"][-1]
        return bool(row["mechanisms_after_domcontentloaded"]) or (not first["text_length"] and last["text_length"])
    return _signal("delayed_content", "redirect_delay_blank_decoy",
                   "observed" if any(delayed(r) for r in rows.values()) else "not_observed", list(rows), rows)


def _blank(obs):
    rows = {}
    for name, rec in obs.items():
        if rec.get("status_code"):
            rows[name] = {"document_text_empty": not (rec.get("text_content") or "").strip(),
                          "html_length": rec.get("html_length", 0)}
            if rec.get("kind") == "browser":
                rows[name]["dom_text_empty"] = not (rec.get("dom_text") or "").strip()
    if not rows:
        return _signal("blank_page", "redirect_delay_blank_decoy", "unmeasurable", [], {})
    observed = any(r["document_text_empty"] or r.get("dom_text_empty") for r in rows.values())
    return _signal("blank_page", "redirect_delay_blank_decoy",
                   "observed" if observed else "not_observed", list(rows), rows)


def _error_page(obs):
    rows = {name: {"status": rec.get("status_code") or 0, "title": rec.get("title", ""),
                   "dom_title": rec.get("dom_title", "")} for name, rec in obs.items() if rec.get("status_code")}
    if not rows:
        return _signal("error_page", "redirect_delay_blank_decoy", "unmeasurable", [], {})
    observed = any(not 200 <= r["status"] < 300 or _ERROR_TITLE.search(r["title"] or "")
                   or _ERROR_TITLE.search(r["dom_title"] or "") for r in rows.values())
    return _signal("error_page", "redirect_delay_blank_decoy",
                   "observed" if observed else "not_observed", list(rows), rows)


def _decoy(obs, f):
    rows = []
    for a, b in (("bot#1", "human#1"), ("bot#2", "human#2")):
        if a in f and b in f:
            for clean, other in ((a, b), (b, a)):
                if (200 <= f[clean]["status"] < 300 and f[clean]["text_length"] and not f[clean]["mechanisms"]
                        and f[other]["mechanisms"]):
                    rows.append({"benign_looking": clean, "with_mechanisms": other,
                                 "mechanisms": sorted(f[other]["mechanisms"]),
                                 "titles": [f[clean]["title"], f[other]["title"]]})
    if not any(a in f and b in f for a, b in (("bot#1", "human#1"), ("bot#2", "human#2"))):
        return _signal("decoy_candidate", "redirect_delay_blank_decoy", "unmeasurable", [], {})
    return _signal("decoy_candidate", "redirect_delay_blank_decoy",
                   "observed" if rows else "not_observed", [r["benign_looking"] for r in rows], {"cases": rows})


# ── repeat_observation ───────────────────────────────────────────
def _parse(ts):
    try:
        return datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None


def _repeat(obs, f):
    accesses = sorted(({"name": n, "access_index": r.get("access_index", 0), "observed_at": r.get("observed_at", ""),
                        "fetch_time_sec": r.get("fetch_time_sec", 0)} for n, r in obs.items()),
                      key=lambda a: a["access_index"])
    times = [_parse(a["observed_at"]) for a in accesses]
    gaps = [round((b - a).total_seconds(), 3) for a, b in zip(times, times[1:]) if a and b]
    sides = {}
    for side in ("bot", "human"):
        a, b = f"{side}#1", f"{side}#2"
        if a in f and b in f:
            sides[side] = _differences(f[a], f[b])
    evidence = {"accesses": accesses, "gaps_sec": gaps, "within_side_differences": sides}
    if not sides:
        return _signal("repeat_instability", "repeat_observation", "unmeasurable", [], evidence)
    observed = any(set(d) & set(_MEANINGFUL_KEYS) for d in sides.values())
    return _signal("repeat_instability", "repeat_observation",
                   "observed" if observed else "not_observed", [f"{s}#1~{s}#2" for s in sides], evidence)


def _first_access(obs, f):
    ordered = sorted((r.get("access_index", 0), n) for n, r in obs.items() if n in f)
    if len(ordered) < 2:
        return _signal("first_access_only", "repeat_observation", "unmeasurable", [], {})
    first = ordered[0][1]
    later = [n for _, n in ordered[1:]]
    only_first = f[first]["mechanisms"] - frozenset().union(*(f[n]["mechanisms"] for n in later))
    later_status = {f[n]["status"] for n in later}
    status_first_only = len(later_status) == 1 and f[first]["status"] not in later_status
    evidence = {"first": first, "mechanisms_only_in_first_access": sorted(only_first),
                "status_differs_only_in_first_access": status_first_only,
                "per_access": {n: {"status": f[n]["status"], "mechanisms": sorted(f[n]["mechanisms"])}
                               for _, n in ordered}}
    return _signal("first_access_only", "repeat_observation",
                   "observed" if only_first or status_first_only else "not_observed",
                   [n for _, n in ordered], evidence)


def compute_signals(bot, human, *, variants=None, static_rules=(), static_techniques=None):
    """回傳訊號清單（固定順序）。只描述觀察，不下結論。"""
    obs = _observations(bot, human)
    f = {name: features(rec) for name, rec in obs.items() if _usable(rec)}
    variants = variants or {}
    return [
        _client_type(obs, f),
        _variant("referer_presence_effect", "referer", "referer", ("bot#1", "bot#2"), "html", variants, obs),
        _variant("desktop_mobile_difference", "device", "mobile", ("human#1", "human#2"), "dom", variants, obs),
        _status(obs), _text(obs, f), _js_dom(obs, f), _scripts(obs),
        _frontend(static_rules, static_techniques or {}), _errors(obs),
        _redirects(obs), _client_redirect(obs), _delayed(obs), _blank(obs), _error_page(obs), _decoy(obs, f),
        _repeat(obs, f), _first_access(obs, f),
    ]


def summarize(signals):
    """CSV 欄位用：observed 的訊號 id、本次未測的訊號 id。"""
    return ("|".join(s["id"] for s in signals if s["status"] == "observed"),
            "|".join(s["id"] for s in signals if s["status"] == "not_tested"))


def variant_differences(signals):
    """變體訊號中 observed 的變體名稱 —— 單次觀察，只能擋 false，不能支持 true。"""
    names = {"referer_presence_effect": "referer", "desktop_mobile_difference": "mobile"}
    return [names[s["id"]] for s in signals if s["id"] in names and s["status"] == "observed"]
