"""觀察計畫：每個 URL 要做哪些觀察、依什麼順序。全部由 ObservationSettings 決定，
設定快照寫進每一列的 state 與每份 manifest。

預設計畫（PAIR_MODE=bot_human）是交錯四次：

    bot_first:    B1 → H1 → B2 → H2        human_first:  H1 → B1 → H2 → B2
    B = 基準 HTTP（bot 槽）、H = Playwright 瀏覽器（human 槽）

為什麼交錯而不是各跑兩次：兩側各有一次在對方之前、一次在對方之後，頁面更新、
短暫故障或「只對第一次存取給真內容」的 kit 會表現成**同側兩次不一致**，而不是被誤讀成
「兩種 client 看到不同內容」。

CRAWL_ORDER=split 依 URL 的 SHA-1 逐筆決定誰先（跨 process 可重現，不可用內建 hash()：
它對 str 每個 process 加鹽）。bot_first / human_first 是強制覆寫，給 A/A 對照批用。
PAIR_MODE=human_human / bot_bot 兩槽用同一種 client，量「頁面自身變異」的假陽性地板。
可選變體（OBSERVATION_VARIANTS=referer,mobile）排在四次觀察之後各做一次。
"""
import hashlib
import json
import os
from dataclasses import asdict, dataclass, field

from crawler import browser, http_baseline
from crawler.policy import SCOPES
from crawler.profiles import BASELINE, BROWSER, VARIANT_PROFILES
from schemas.evidence import sha256

PAIR_KINDS = {"bot_human": ("http_baseline", "browser"),
              "human_human": ("browser", "browser"),
              "bot_bot": ("http_baseline", "http_baseline")}
CRAWL_ORDERS = ("split", "bot_first", "human_first")
VARIANTS = tuple(VARIANT_PROFILES)
_DEFAULT_PROFILES = {"http_baseline": BASELINE, "browser": BROWSER}


@dataclass(frozen=True)
class ObservationSettings:
    scope: str = "passive"
    pair_mode: str = "bot_human"
    crawl_order: str = "split"
    variants: tuple = field(default_factory=tuple)
    replicates: int = 2

    def __post_init__(self):
        if self.scope not in SCOPES:
            raise ValueError("invalid_CRAWL_SCOPE")
        if self.pair_mode not in PAIR_KINDS:
            raise ValueError("invalid_PAIR_MODE")
        if self.crawl_order not in CRAWL_ORDERS:
            raise ValueError("invalid_CRAWL_ORDER")
        if set(self.variants) - set(VARIANTS):
            raise ValueError("invalid_OBSERVATION_VARIANTS")
        if self.replicates < 1:
            raise ValueError("invalid_replicates")

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        if env.get("HUMAN_PROFILE"):
            raise ValueError("legacy_HUMAN_PROFILE_retired_see_README_v3")
        variants = tuple(sorted({v.strip() for v in env.get("OBSERVATION_VARIANTS", "").split(",")
                                 if v.strip()}))
        return cls(scope=env.get("CRAWL_SCOPE", "passive"), pair_mode=env.get("PAIR_MODE", "bot_human"),
                   crawl_order=env.get("CRAWL_ORDER", "split"), variants=variants)

    @classmethod
    def from_record(cls, record):
        keys = ("scope", "pair_mode", "crawl_order", "variants", "replicates")
        values = {k: record[k] for k in keys if k in record}
        values["variants"] = tuple(values.get("variants", ()))
        return cls(**values)

    def record(self):
        """設定快照：連同每個 client profile 的完整欄位，一起寫進 state 與 manifest。"""
        kinds = PAIR_KINDS[self.pair_mode]
        return {**asdict(self), "variants": list(self.variants),
                "slots": {"bot": kinds[0], "human": kinds[1]},
                "profiles": {"bot": _DEFAULT_PROFILES[kinds[0]].record(),
                             "human": _DEFAULT_PROFILES[kinds[1]].record(),
                             **{f"variant:{v}": VARIANT_PROFILES[v].record() for v in self.variants}}}

    def config_sha256(self):
        return sha256(json.dumps(self.record(), sort_keys=True, ensure_ascii=True))


def effective_order(url, crawl_order="split"):
    if crawl_order in ("bot_first", "human_first"):
        return crawl_order
    if crawl_order != "split":
        raise ValueError("invalid_CRAWL_ORDER")
    return "human_first" if hashlib.sha1(url.encode()).digest()[0] & 1 else "bot_first"


def plan_steps(url, settings):
    """回傳 (順序, [(slot, replicate), …])。槽與先後分開：回傳值依槽指派，不依先後 ——
    依先後指派的話 human − bot 的方向會整個反過來，而且不會有任何錯誤訊息。"""
    order = effective_order(url, settings.crawl_order)
    first, second = ("bot", "human") if order == "bot_first" else ("human", "bot")
    steps = [(slot, rep) for rep in range(1, settings.replicates + 1) for slot in (first, second)]
    return order, steps + [(f"variant:{v}", 1) for v in settings.variants]


def describe(url, settings):
    """可讀的計畫字串，寫進 CSV 的 observation_plan 欄，例如 bot_first:B1,H1,B2,H2;variants=mobile。"""
    order, steps = plan_steps(url, settings)
    letters = {"bot": "B", "human": "H"}
    main = ",".join(f"{letters[s]}{r}" for s, r in steps if not s.startswith("variant:"))
    return f"{order}:{main};variants={','.join(settings.variants)}"


def fetch_observation(kind, url, *, profile=None, scope="passive", meta=None):
    """單次觀察的唯一出口。在呼叫時才查模組屬性，測試可以替換 http_baseline.fetch / browser.fetch。
    meta（槽、第幾次、存取序號…）在觀察開始前寫進紀錄，所以證據檔 record.json 也帶著它們。"""
    module = http_baseline if kind == "http_baseline" else browser
    return module.fetch(url, profile=profile or _DEFAULT_PROFILES[kind], scope=scope, meta=meta)


def observe_url(url, settings):
    """依計畫執行所有觀察。回傳 {"bot", "human", "variants", "order", "plan", "errors"}；
    各槽第二次觀察放在 record["confirmation"]。"""
    order, steps = plan_steps(url, settings)
    kinds = dict(zip(("bot", "human"), PAIR_KINDS[settings.pair_mode]))
    taken, variants, errors = {}, {}, []
    for access_index, (slot, replicate) in enumerate(steps, 1):
        meta = {"replicate": replicate, "access_index": access_index,
                "crawl_order": order, "pair_mode": settings.pair_mode}
        if slot.startswith("variant:"):
            name = slot.split(":", 1)[1]
            kind = "http_baseline" if name == "referer" else "browser"
            record = fetch_observation(kind, url, profile=VARIANT_PROFILES[name], scope=settings.scope,
                                       meta={**meta, "role": "variant", "variant": name})
            variants[name] = record
        else:
            record = fetch_observation(kinds[slot], url, scope=settings.scope, meta={**meta, "role": slot})
            taken[(slot, replicate)] = record
        if record.get("error"):
            errors.append(f"{slot}#{replicate}: {record['error']}")
    bot, human = taken[("bot", 1)], taken[("human", 1)]
    for slot, primary in (("bot", bot), ("human", human)):
        if (slot, 2) in taken:
            primary["confirmation"] = taken[(slot, 2)]
    return {"bot": bot, "human": human, "variants": variants, "order": order,
            "plan": describe(url, settings), "errors": errors}


def dual_crawl(url):
    """相容介面（v2）：回傳 (bot, human, errors)，設定取自環境變數。"""
    result = observe_url(url, ObservationSettings.from_env())
    return result["bot"], result["human"], result["errors"]
