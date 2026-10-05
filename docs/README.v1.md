> Historical v1 documentation only. Unsafe crawler features described below have been removed. Do not use these commands for v2. See ../README.md and research_v2.md.

# Cloaking 偵測

判斷一個 URL **是不是釣魚站**，以及**有沒有對爬蟲隱藏具高特異性惡意機制的內容**
（malicious-content cloaking）。

這個限定不是修辭。判定路徑上每一步都經過 `page_mechanisms.evaluate_page()`（以下稱 φ）：
C1 比的是 φ 的機制集合差，C2–C4 的閘門是「真人端 φ 命中高特異性機制」，C5 同理。
因此 **φ 的 recall 就是本系統 cloaking 判定的 recall 上界** —— 一個對爬蟲完全換頁、
但換出來的頁面 φ 認不出惡意的站，本系統量不到。這類案例回報 `N/A` 而非 `False`
（見「結構分歧降級」），不宣稱「確認無 cloaking」。

管線四步：**存活檢查 → 雙重爬取（含 JS 去混淆）→ 釣魚判定 → cloaking 判定**。

## 本系統的主張

本系統不主張能觸及所有 cloaked 內容。一組極端化的 BOT/HUMAN 配對是做出 cloaking
判定的**最小單位**，而任何單一配對只能產生**下界**：觸發軸正交於此配對的 cloaking
（地理／平台／時間／一次性 token）對它是全盲的——PhishParrot 實測攻擊者 targeting
大量發生在正交的地理／平台軸上。

因此本文報的是「活體釣魚站中 malicious-content cloaking **盛行率的下界**」，
而不是偵測率，也不是「我們比 baseline 抓得更多」。profile 的『選擇』與『差分』
可分離，前者可由 PhishParrot 式最佳化供給，後者（本系統）不受影響。

**釣魚判定不再是唯一輸出，但釣魚判準仍是判定的度量衡。** 管線對 URL 輸出的是
兩個並列的布林，而 φ 同時是差分的那把尺 —— 兩端必須用同一把尺量，否則集合差
沒有意義。這兩件事必須分開講。

兩個判定彼此獨立、不互為前提：一個釣魚站可以不做 cloaking，一個做 cloaking
的站也可以不是釣魚站。所以輸出是兩個並列的欄位，不合成單一風險分數。
Node 3 拿 φ 下 URL 層的裁決，Node 4 拿 φ 對 BOT / HUMAN 兩份頁面各算一次取集合差。

外部威脅情資仍在管線外：`threat_intel.py`（根目錄，不是節點）是獨立工具，用途是驗證
清單標籤是否仍成立，不參與判定（讓它代答釣魚就等於拿別人的答案當自己的結果）。

## 全域設計原則

四條原則貫穿所有節點，看程式碼時對照這四條就懂為什麼那樣寫：

1. **高特異性用布林，統計性才用累加。**
   「合法網站沒有理由做這件事」的特徵（Telegram webhook、憑證表單送去免費主機、ChromeDriver 注入變數）→ 連言規則，命中即定案。
   「合法網站也常做」的特徵（URL 長度、`document.referrer`、`screen.width`）→ 只能累加當佐證，永遠不能單獨裁決。
   把兩類混進同一個加總，就會落入「調高門檻壓誤報 → 漏報變多 → 再調」的循環。

2. **以真人看到的頁面為基準。** 攻擊面是使用者，不是爬蟲。`raw_html` 取 HUMAN 那份，BOT 那份用來做差分。

3. **權重要有依據，沒有就別放。** 目前唯一還在用的權重是判準層的 Layer 2，其中 URL 詞彙那批用 WoE 校準過，其餘標了 `unfitted`。

4. **LLM 不進入 cloaking 的裁決路徑。** 對 `cloaking` 那一欄它只做兩件事：Node 2 的去混淆（前處理）、Node 4 靜態層 S4 的佐證（描述性）。判定由 `decide_cloaking()` 的布林規則做出，那個函式連 `llm` 參數都不收。
   **釣魚那一欄不同** —— Node 3 的 Layer 2 會把 LLM 信心度以 `max(rule, rule*0.7 + llm*0.3)` 融合進去，所以 `is_phishing` 是會受模型影響的。兩欄的可重現性不一樣，論文要分開寫。詳見下節。

---

## Node 1 — 雙重爬取

`nodes/node1_scraper.py` + `nodes/dual_crawler.py`

並行跑兩個 Playwright（錯開 2–4 秒 stagger；誰先出發由 `CRAWL_ORDER` 決定，預設逐筆切一半）：

| | 偽裝方向 | 手段 |
|---|---|---|
| **BOT** | 主動暴露自己是機器人 | Googlebot UA、`_BOT_EXPOSE_JS` 把 `webdriver=true`/`plugins=[]`/`languages=[]` 全部還原、**`cookieEnabled=false` 且 `document.cookie` 恆為空**、1024×768、無 `Accept-Language`、無 `Referer`、保留 `AutomationControlled` 旗標 |
| **HUMAN** | 盡可能像真人 | `_STEALTH_JS` 修補 17 個 headless 洩漏點＋原生函式 toString 遮蔽、Canvas/WebGL/Audio 假指紋、Google session 預熱、貝茲曲線滑鼠軌跡、**互動閘門跨越** |

**輸出**：`bot_crawl` / `human_crawl`（同結構 dict）、`raw_html` = **HUMAN 那份**（HUMAN 失敗才退回 BOT，再失敗才 `requests` fallback）、`js_scripts`（從判定用頁面抽取）。

**IP 維度刻意不極化。** 兩端走同一個出口，差分只建立在 **UA / Headers / TLS /
JS 屬性 / 行為**這五個維度上。這是實驗設計的選擇，不是還沒做完的事：本研究要
檢驗的假設就是「一組極端化的 BOT/HUMAN 配對本身能不能觀察到 cloaking」，
多加一個 IP 維度會讓「觀察到差異」多一個解釋來源，反而模糊掉要檢驗的東西。

已知代價（寫進 limitation，不是隱瞞）：純 IP 判別的 cloaking 對這個差分**全盲**；
同一出口下 per-IP burn-after-read 的 kit 會把真內容燒在先到的那一次。後者無法從
設計上排除，只能量 —— 那就是 `reverse_diff` 那一欄與 `CRAWL_ORDER` 可反轉的用途。

2026-08-07 曾實測過六維版本（BOT 走資料中心、HUMAN 走住宅），40 筆中 IP 維度的
邊際貢獻為 0，沒有任何一筆判定由它促成。樣本小、單一 feed、同一天，
正確的說法是「在本樣本中未觀察到 IP-based cloaking」，不是「IP cloaking 不普遍」。

裝 `curl_cffi` 讓 TLS JA3/JA4 指紋像真 Chrome（這個仍是可選增強）。

**HUMAN profile 可切換**（`HUMAN_PROFILE` 環境變數）：`tw-desktop`（預設）/ `jp-mobile` / `jp-desktop` / `us-desktop` / `jp-mac-safari`。

**爬取順序是批內變因**（`CRAWL_ORDER=split|bot_first|human_first`，預設 `split`）。
固定 BOT 先是有理由的（貼近「爬蟲先到、使用者後到」），但它同時是一個未被檢定的
實驗變因：若順序影響陽性率，那一部分就是順序的產物而不是 cloaking 的產物。

`split` 依 URL 的 **SHA-1** 逐筆切一半，同一個 URL 永遠落在同一組；
`bot_first` / `human_first` 則強制單一順序，給 A/A 對照批與測試用。
`crawl_order` 欄記的是**這一列實際跑的順序**，不是模組常數 ——
`split` 之下常數只說明「有切分」，說不出某一列落在哪組。

> 為什麼是批內切分而不是跑兩批：分兩批會把順序和批次綁在一起。兩批相隔數小時，
> feed 已經換過、站又死了一批，兩比例檢定量到的差異分不出哪些來自順序、
> 哪些來自時間。批內切分讓兩組落在同一份清單、同一段時間。
>
> ⚠️ 切分**不可**改用 Python 內建 `hash()`：它對 `str` 每個 process 加鹽
> （`PYTHONHASHSEED` 預設隨機），同一個 URL 換一次 run 就可能換組，分派會從
> 「固定」變成「隨機」且事後無法重現。`test_crawl_order_split_is_stable_and_balanced`
> 鎖住這件事。

回傳值依「槽」而非「先後」指派，`test_crawl_order_does_not_swap_roles` 鎖住這一點 ——
接錯的話 `human − bot` 的方向會整個反過來，而且不會有任何錯誤訊息。

**A/A 配對模式**（`PAIR_MODE=bot_human|human_human|bot_bot`）：兩個槽都用同一個身分，
量的是「頁面自身變異造成的假陽性地板」。`_confirm_c1` 只確認「陽性可重現」，
不量「同身分兩次爬取本來就會差多少」—— 那正是 Cloak of Visibility 每 profile 爬 3 次
在做的事，A/A 批把它補回來。`human_human` 是主結果必須顯著高過的那條線；
`bot_bot` 量的是伺服器對爬蟲的回應穩不穩定（WAF 是否隨機擋），解釋 C2–C4 的噪音來源。

⚠️ **A/A 批要看的是 `rule_fired_raw`，不是 `cloaking` 那一欄**：`bot_bot` 模式下
`prewarm_ok` 恆為 False → 全批 `LOW` → 全批 `N/A`，用結論欄比等於沒跑。
主批同樣輸出 `rule_fired_raw`，兩者才是同口徑的比較。

### 極化了哪些軸 —— 對照 CrawlPhish 的機制分類

CrawlPhish（S&P'21）Table V 統計了 36,903 個用戶端 cloaking 實作的分布。九個機制軸裡，本系統的 BOT/HUMAN 配對對齊了六個：

| CrawlPhish 機制 | 實作佔比 | 本系統的差分軸 | |
|---|---|---|---|
| ClickThrough | 22.11% | HUMAN 點一個閘門 / BOT 不點 | ✔ |
| Timing | 19.80% | HUMAN 預熱＋等待 / BOT 直取 | ✔ |
| Alert | 17.19% | HUMAN `accept` / BOT 預設 dismiss | ✔ |
| MouseDetection | 16.53% | HUMAN 貝茲曲線軌跡 / BOT 無滑鼠 | ✔ |
| Cookie | 12.53% | BOT `cookieEnabled=false` / HUMAN 正常 | ✔ |
| Referrer | 6.69% | HUMAN `google.com` / BOT 無 `Referer` | ✔ |
| Randomization | 4.63% | C1 重爬確認會當成頁面變異撤銷 | △ |
| Notification | 4.34% | 偵測為閘門但不跨越 → `N/A` | ✘ |
| User-Agent | 3.98% | Googlebot / 真實 Chrome | ✔ |

**Randomization 是設計取捨而非疏漏**：用 `Math.random()` 決定顯示內容的 kit，在 `_confirm_c1` 重爬時多半不會重現，於是被判為頁面自身變異並撤銷。那條重爬是為了擋輪播／A-B test 的誤報，代價就是把隨機型 cloaking 一併剔除。

**但這張表量的是用戶端 cloaking，不是本系統的主戰場。** 動態層 C1–C5 比的是伺服器端差異化遞送 —— 那是 CrawlPhish 的靜態 AST 分析看不到的類別（決策發生在觀察者拿到任何內容之前）。這張表回答的是「極化配對能觸發哪些已知的用戶端偵測」，不是覆蓋率。

**互動閘門跨越（只有 HUMAN 做）**：自動接受 alert/confirm、點擊一個「看起來像閘門」的按鈕。

這不是外掛補丁而是補完既有設計——形式模型的 ℛ 本來就包含 `Behavior` 維度，先前只做了一半（滑鼠移動、捲動），沒有點擊。CrawlPhish Table V 統計 User Interaction 類佔客戶端 cloaking 的 **57.60%**，而「爬蟲不互動、真人會互動」本身就是一條乾淨的極端化軸。

安全上限（不可放寬，有測試把關）：
1. **絕不點 `<form>` 內元素或 `type=submit`**——分析的是釣魚站，誤點等於代替受害者把資料送給攻擊者。
2. **絕不點帶送出語意的字樣**（sign in / submit / pay / 登入 / 送出 / 付款），即使不在表單內。
3. **絕不解 CAPTCHA**——法律與倫理問題，且是 PhishDecloaker 一整篇論文的工作量。遇到就讓 Node 4 回報 `N/A`。
4. 只點可見、夠大、字樣像閘門的元素，最多點一個。

已跨越的閘門不再計入「沒看到內容」（否則加了這功能反而更多案例掉進 `N/A`）；CAPTCHA 永遠算未跨越。

極端化處理的是「bot ↔ human」軸，但 PhishParrot（GLOBECOM'25）實測攻擊者的 targeting 大量發生在**正交的地理／平台軸**上（91 種最佳 profile；日本住宅網路 53.83%、美國資料中心 30.71%、macOS Safari + 日本住宅 8.77%）。這正是「單一配對只能產生下界」那句話的實證依據，見開頭〈本系統的主張〉。

---

## Node 2 — JS 去混淆

`nodes/node2_js_analyzer.py`

八種手法：Dean Edwards Packer、`eval(atob())`、hex/unicode 跳脫、obfuscator.io 字串陣列、JSFuck/JJencode 偵測、字串常數合併、js-beautify、LLM 分塊迭代（`obfuscation_score > 0.45` 才觸發）。

**為什麼必須在 Node 4 之前**：Node 4 的靜態層與機制判準都比對可讀原始碼。壓縮成 `n.wD` 的字串比對不到 `navigator.webdriver`。這是整條 pipeline 唯一真正的順序依賴。

---

## 惡意機制判準 —— Node 3 與 Node 4 的共享判斷函數 φ

`nodes/page_mechanisms.py` —— **這不是一個節點**，是規則層。兩個節點共用它：

```
Node 3:  is_phishing     = evaluate_page(HUMAN, extra_js=去混淆JS) ⊕ 混淆權重 ⊕ LLM
Node 4:  hidden_from_bot = evaluate_page(HUMAN).mechanisms − evaluate_page(BOT).mechanisms
```

「BOT 沒有惡意機制」這句話的定義就在這個檔案裡。兩端必須用同一把尺量，
否則差分沒有意義 —— 這也是為什麼判準要獨立成共享函數而不是寫進任一個節點。

### 規則的 scope：哪些條可以看去混淆後的 JS

每條規則有一個 `scope`：

| scope | 類別 | 比對範圍 |
|---|---|---|
| `all`（預設） | 程式碼行為類（webhook 外洩、定時跳轉、封鎖 DevTools、解碼後執行…） | HTML + `extra_js` |
| `html` | 頁面語意類（`credential_harvesting`、`brand_impersonation`） | 只有 HTML |

**為什麼要分**：後兩類問的是「這一頁在跟使用者要什麼 / 展示哪個品牌」，答案只可能
在 HTML 裡。讓它們跑進第三方 JS，撈到的是廣告／同意管理／分析 bundle 的欄位字典與
廠商清單 —— 8/21 那批 100 筆實測，`credential_harvesting` 命中 48 筆、其中 **31 筆
只存在於外部 JS**，`brand_impersonation` 命中 **44 筆**，連 GoDaddy 的
「Account Suspended」錯誤頁都有 `password, ssn` 與 `paypal, amazon`。

程式碼行為類則相反，**必須**看 `extra_js`：混淆過的釣魚套件正是在去混淆之後才現形。
`test_page_semantics_rules_ignore_third_party_js` 與
`test_code_behaviour_rules_still_read_deobfuscated_js` 分別鎖住兩個方向。

Node 4 呼叫 `evaluate_page` 時本來就不帶 `extra_js`，所以 scope 只作用在 Node 3，
`cloaking` 那一欄不受影響。

兩個呼叫端有一處**刻意的不對稱**：Node 3 帶 `extra_js`（去混淆後的 JS），
Node 4 不帶。因為 Node 4 比的是兩端差異，而 BOT 端沒有對應的去混淆結果可帶，
單邊帶就等於用兩把尺；Node 3 下的是真人端那一份的絕對判定，混淆過的釣魚套件
正是在去混淆後才現形，不帶會整批漏抓。`test_node3_phishing.py::
test_deobfuscated_js_reaches_the_rules` 鎖住這一點。

### φ 的 recall 是 cloaking 判定的天花板 —— 而 Node 3 是量它的儀器

cloaking 的判定路徑（C1–C5）**全部**經過 φ，所以 φ 的 recall 就是 cloaking
判定的 recall 上界。這句話原本只寫在 `_assess_dynamic_reliability` 的註解裡。

分母改由 feed 標籤決定之後（見「盛行率是一個區間」），`is_phishing` 不再是分母，
那句註解就變成**可以量的數字**：在「feed 說是釣魚、站還活著」的子集裡，
φ 在真人端一個機制都沒認出來的比例。`evaluate.py::report_phi_blindspot()` 印兩個數：

| | 意義 |
|---|---|
| 真人端零機制 | φ 完全認不出 → 這些站無論 C1–C5 怎麼調都判不出 cloaking |
| Node 3 判為釣魚 | φ ＋ 混淆加權 ＋ LLM 融合之後對活體釣魚站的 recall |

兩者的差距就是「有機制但不足以判釣魚」那一段。主結果的下界要配著第一個數讀 ——
它說明下界為什麼比看起來更保守。

### Layer 1：布林裁決 — 命中即定案，跳過評分與 LLM

| | 條件（AND） |
|---|---|
| D1 | 前端把資料送往 Telegram / Discord / Slack webhook |
| D2 | 憑證表單 action 指向裸 IP |
| D3 | 憑證表單 action 指向免費主機 / 動態 DNS |
| D4 | 品牌名出現在 weebly / pages.dev 類託管平台 |
| D5 | URL 含 `@` 符號 |
| D6 | 憑證表單 + Punycode 同形字網域 |
| D7 | 憑證表單 + 解碼後 eval + 封鎖 DevTools |

收錄標準：①合法網站沒有合理情境會觸發（已扣除 SSO / CDN / analytics 白名單）②攻擊者規避成本高。

### Layer 2：統計累加（閾值 0.45）

弱訊號才進這層。URL 詞彙特徵的權重 = `0.04 × WoE`，係數由一條不變式決定：**全部命中總分 0.43 < 0.45**，所以 URL 特徵永遠只能當佐證。

實測移除的：`dot>=4`（WoE −0.33，是反向證據）。實測新增的：`entropy>4.2`、`digit_ratio>0.1`。未採用：`is_https=0`（WoE −2.02，資料集年代偏誤）。

**`evaluate_page(html, url)`** 是這層的公開入口，Node 4 也呼叫它 —— 兩處必須是同一個實作，否則「BOT 沒有惡意機制」這句話在兩個節點會是兩個意思。

**隱藏 iframe 的兩個排除條件**（8/19 實測，兩筆合法站誤判的根因都在這裡）：
1. **沒有 `src` 的空白 iframe 不算。** 送不出任何東西 —— 廣告/分析的暫存框、表單的 target 都長這樣。brightika.com 被單一個 `<iframe style="display:none">` 從 0.100 推到 0.487。
2. **社群分享外掛的 iframe 不算**（`_SOCIAL_WIDGET_HOSTS`）。原本白名單只有 `facebook.net`（SDK 的 script 來源），而分享按鈕的 iframe 指向 `facebook.com`，差一個 TLD。socialpolicy.org 被 5 個 `fb:share_button` 從 0.170 推到 0.495。

這張社群白名單**刻意不併進 `_COMMON_THIRD_PARTY`** —— 那會一併放行 `brand_asset_hotlink`，而「盜連 facebook.com 的圖 + 收憑證」正是仿冒 FB 登入頁的典型手法，那條偵測必須留著。兩條規則問的是不同問題，白名單就不該共用（有測試分別鎖住兩邊）。

---

## Node 4 — Cloaking 判定

`nodes/node4_cloaking_analyzer.py`

### 靜態：前端 JS（S1–S4，布林）

定義：**偵測環境 → 依結果改變使用者看到的東西**。兩半都不能單獨成立。

| | 條件（AND） |
|---|---|
| S1 | 爬蟲框架洩漏識別符 + 差異化跳轉 |
| S2 | 指紋條件分流 + 差異化跳轉 |
| S3 | 爬蟲偵測 + 指紋條件分流 |
| S4 | LLM 判定 + 高特異性偵測佐證 |

一般性環境偵測（UA / referrer / screen / geo / devtools / mouse）**記錄為證據但不參與裁決** —— 那是統計性特徵，布林化只會把現代網站判成 cloaking。

### 動態：BOT vs HUMAN 機制集合差（C1–C5，布林）

```
hidden_from_bot = evaluate_page(HUMAN).mechanisms − evaluate_page(BOT).mechanisms
```

五條規則依「BOT 有沒有拿到頁面」分成兩組，職責不重疊：

| | 前提 | 條件（AND） |
|---|---|---|
| C1 | **BOT 確實取得頁面** | HUMAN 多出 BOT 沒有的惡意機制（完整機制集合） |
| C2 | BOT 沒拿到 | 爬蟲被封鎖 403/404/503、真人 200 ＋ **真人端含高特異性機制** |
| C3 | BOT 沒拿到 | 爬蟲被 HTTP/2 協議層中斷 ＋ **真人端含高特異性機制** |
| C4 | BOT 沒拿到 | 爬蟲拿到空頁面 ＋ **真人端含高特異性機制** |
| C5 | — | Redirect 分叉且只有真人端落在含惡意機制的頁面 |

**為什麼 C1 要有「BOT 確實取得頁面」的前提**：機制集合差只有在兩邊都看到東西時才是差異。BOT 吃了 403 或空頁時，「BOT 沒有 `cred_form`」為真只是因為它什麼都沒拿到 —— 這是把 BOT 單方面的「沒看到」讀成「沒有」，跟三態輸出要避免的是同一件事，只是不對稱。

不修的話 C1 會把 C2–C4 整個吞掉：只要真人端有任何一個機制（一個登入框就夠），BOT 被 WAF 擋掉就直接 C1 成立，C2–C4 的閘門永遠走不到。8/19 那批的兩筆合法站 cloaking 誤判就是這個形狀。

**為什麼 C2–C4 要「高特異性」而不是「任何機制」**：`cred_form` / `credential_harvesting` / `brand_asset_hotlink` / `hidden_iframe` 只代表「頁面有登入框 / 引用了品牌圖 / 有個隱藏 iframe」，任何登入頁與任何掛了同意管理橫幅的網站都命中。C2–C4 下的是**絕對**判斷（這頁真的有惡意），用得起的只有 `HIGH_SPECIFICITY_MECHANISMS`（webhook 外洩、表單送往免費主機、解碼後動態執行、封鎖 DevTools…）。C1 比的是兩端**差異**、同一把尺量兩邊，所以仍用完整集合 —— 「BOT 看不到登入表單而真人看得到」本身就是有意義的差異。兩組定義在 `page_mechanisms.py`，有 assert 鎖住從屬關係。

**2026-08-23：`hidden_iframe` 從高特異性降級。** 依據是收錄標準本身（「合法網站沒有
理由做這件事」），不是任何一批的數字 —— 隱藏 iframe 撐不起這句話：同意管理平台
（OneTrust / Cookiebot）、廣告 cookie sync、金流的 PCI iframe、客服 widget 全都是
隱藏 iframe，全都是合法網站每天在做的事。後果是「BOT 被 WAF 擋掉 ＋ 真人端只有一個
隱藏 iframe」不再構成 cloaking，那種情形回到「反爬蟲」那一類。它仍留在
`MALICIOUS_MECHANISM_FLAGS`，C1 的集合差照用。

同時擴充了隱藏 iframe 的白名單（`_EMBED_WIDGET_HOSTS`，涵蓋 CMP / 廣告技術 /
金流 / 客服 / 產品分析）。這一條比降級更急，因為它影響的是 **C1**：這些 iframe
幾乎都由 JS 注入，BOT 端不執行 JS 就沒有 → 只在 HUMAN 端出現 → 集合差非空 → C1 成立。
這正是 `_SOCIAL_WIDGET_HOSTS` 當初為 FB 分享按鈕開的同一個洞，只是換了一批廠商，
而且 **`_confirm_c1` 擋不住它** —— 重爬 HUMAN，CMP iframe 照樣出現，
於是被確認為「穩定重現」，直接變成陽性進主結果的分子。
白名單刻意**不併進** `_COMMON_THIRD_PARTY`：那會一併放行 `brand_asset_hotlink`，
而「盜連品牌圖 ＋ 收憑證」正是仿冒登入頁的典型手法，那條偵測必須留著。

PhiUSIIL 前 1000 筆實測，未加這些條件時**合法站的 cloaking 陽性率 11.3% 反而高於釣魚站的 8.3%** —— 方向與假設相反，因為誤判的分母是 OpenPageRank 高排名站，它們普遍掛 WAF。差別待遇仍會記錄成證據（「判為反爬蟲，非 Cloaking」），只是不再構成裁決。

⚠️ **那個反轉同時暴露了對照組本身的偏誤**：MUD 的 benign / OpenPageRank 高排名站
普遍掛 WAF/CDN，與釣魚站的託管環境（免費主機、被入侵的共享主機）根本不可比。
「合法站陽性率高於釣魚站」有相當一部分是託管環境的差異，不是判定邏輯的差異。
下一輪要討論的是要不要改用**同型託管的合法站**（免費主機、共享主機上的正常站）當對照。

明確區分四種「不是 cloaking」：兩端都有惡意機制（是釣魚但沒藏）、兩端都乾淨、分叉但機制相同（地理導向）、BOT 被擋但真人端不是惡意頁（反爬蟲）。

**C1 陽性確認**：只有 C1 依賴「單次觀測到的機制」，所以 C1 單獨成立時會重爬一次 HUMAN，確認機制穩定重現才維持判定；沒重現就判為頁面自身變異（輪播／A-B test／個人化）並撤銷。C2–C5 依據狀態碼、傳輸層錯誤、空頁面、redirect 鏈，都是當次事實，不重爬。

對照 Cloak of Visibility（S&P'16）每個 profile 全量爬 3 次算變異度基線——**那兩件事目的不同，不能互相取代**：

| | 目的 | 成本 |
|---|---|---|
| `_confirm_c1` 重爬 | 陽性**穩定性**確認（這個機制是不是只出現一次） | `1 × 陽性率` |
| A/A 對照批（`PAIR_MODE=human_human`） | **變異度基線**（同身分兩次爬取本來會差多少） | 一次性一整批 |

先前 README 寫「成本從 3× 降為 1×陽性率」是把兩者混為一談了：省掉的正是變異度基線，
而 C1 用的是完整機制集合（含 `cred_form` 這種泛用旗標），對頁面隨機性的敏感度遠高於
C2–C4 —— 廣告輪播換一支第三方 script、SPA 的 `fetch(..., POST)` 隨載入時序有無，
都足以製造非空的集合差。基線要用 A/A 批量，不能靠重爬推導。

重爬失敗時保守維持原判定，不讓網路問題製造漏報。

**為什麼不用文字相似度**：相似度低 ≠ cloaking（多語言、A/B test、個人化）；相似度高 ≠ 沒有 cloaking（只塞一支外洩腳本可以到 0.98）。相似度仍然計算並列印，但標記「不參與判定」。

### 反向差 `reverse_diff`（診斷欄，不參與裁決）

```
reverse_diff = evaluate_page(BOT).mechanisms − evaluate_page(HUMAN).mechanisms
```

它不是 cloaking 的證據，是**實驗設定失效**的證據：per-IP burn-after-read 的 kit 在
「BOT 先到 + 同出口」時會把真內容燒在 BOT 那次，HUMAN 只拿到誘餌 —— 集合差為空
甚至方向相反，安靜地變成 `False`，而先前連它發生過都不知道。兩端共用出口時這個
效應無法從設計上排除，只能量它。這一欄在活體 feed 上的非空比例，
就是順序汙染是否成立的直接量測（`evaluate.py` 會印出來）。

### 結構分歧降級：兩端皆無機制但明顯不是同一份頁面 → `N/A`

判定路徑每一步都經過 φ，所以 φ 的 recall 就是 cloaking 判定的 recall 上界。
一個對 BOT 完全換頁、但換出來的釣魚頁沒命中任何高特異性機制的站（整頁一張圖 +
一個送到自家後端的 `<form action="/a.php">`），集合差為空、C2–C4 的閘門開不了，
先前會輸出 `False` —— 而 `False` 的語意是「驗過了，確認沒有 cloaking」。那是謊稱，
跟互動閘門那條漏報是完全同一個病：**「量不到」不等於「沒有」**。

所以兩端皆無機制時，額外檢查結構性證據，命中就降級為 `LOW`（輸出 `N/A`）：

| 理由 | 條件 |
|---|---|
| `form_action_hosts_disjoint` | 兩端都有表單，但 action 的主機集合完全不相交 |
| `form_presence_differs` | 一端有表單、另一端沒有 |
| `script_hosts_jaccard<0.34` | 兩端的 `<script src>` 主機集合幾乎不重疊 |
| （redirect 分叉） | 兩端最終落在不同網域 |

**刻意不用 `content_similarity`**：相似度低的最大宗是多語言／個人化／輪播，那是
文字層差異，不代表遞送了不同的東西。`test_multilingual_page_with_same_structure_stays_high`
就是為了鎖住這件事 —— 防止有人把相似度塞進降級條件。

**代價要誠實承認**：多語言站、A/B test、大量第三方腳本的合法站會被降級成 `N/A`，
`N/A` 比例會上升。這是**用統計檢定力換結論誠實性**的交換，所以論文要報改動前後的
`N/A` 比例變化與降級理由分布，並用三種盛行率（見下）讓讀者自己看影響區間。

### LLM 在這條管線的位置

```
LLM ──→ deobfuscated_js ──→ 靜態層 S1–S4 ──→ static_detected ──→ evidence 字串（列印）
                                                              └─→ cloaking_tier（診斷欄）

cloaking 判定 ←── cloaking_verified ←── decide_cloaking()   純布林，不收 llm 參數
              └── dynamic_reliability ←── 狀態碼／耗時／閘門／結構分歧，不含 LLM
```

三個接觸點：

| | 實例 | 觸發條件 | 影響 |
|---|---|---|---|
| Node 2 去混淆 | `llm_code` | `obfuscation_score > 0.45` | 產出 `deobfuscated_js`，靜態層與 Node 3 讀 |
| Node 3 釣魚 Layer 2 | `llm_phish` | 未被 Layer 1 布林裁決攔下時一律呼叫 | **直接進 `is_phishing` 結論欄** |
| Node 4 靜態 S4 | `llm_cloak` | LLM 說有 **且** 規則層看到爬蟲框架洩漏／指紋條件分流 | 併入 `static_detected` |

第二列是唯一會改變結論的接觸點，而且它只能把分數往上推（`max(rule, blended)`）。
量化一下影響範圍：`llm` 回 1.0 時，規則分數只要 ≥ (0.45 − 0.3) / 0.7 = **0.214**
就會被判成釣魚。合法登入頁的規則分數實測 0.233 —— **就在這條線上面**，
也就是說 LLM 有能力單獨把規則層認定為正常的頁面翻成釣魚。
`test_node3_phishing.py::test_llm_can_tip_a_borderline_page` 明示鎖住這個性質，
並在註解裡寫了兩個收緊的改法。LLM 失敗／無 API key 時 `confidence = 0.0`，
純規則的結論不受影響。

**動態層不看去混淆結果**，讀的是兩份原始 HTML：

```python
bot_eval   = evaluate_page(bot_result.get("html", ""),   url)
human_eval = evaluate_page(human_result.get("html", ""), url)
```

而 `static_detected` 的三個分支全部只 append 證據字串，不改 `verified`。因此 **LLM 對輸出的 `cloaking` 欄位有零影響**（對 `is_phishing` 則有，見上）。

這是刻意的，也是可以主張的性質：cloaking 判定完全可重現，不受模型、溫度、供應商影響；換掉 LLM 或完全不設 API key，`cloaking` 那一欄的結果一模一樣。代價是 LLM 目前撐不起「本系統用 LLM 做 cloaking 偵測」這種說法 —— 論文不能那樣寫。

反過來說，`is_phishing` 那一欄**不具備**這個性質。要在論文裡報釣魚的數字，得先講清楚是哪個模型跑的，或者關掉 LLM 只報純規則版本。

`static_detected` 唯一還會改變的是 `cloaking_confidence_tier`。它**不進結論欄**，但寫進 `batch_results` 的 `cloaking_tier` 診斷欄，好讓 LLM 的貢獻是可稽核的而不是隱形的。

### 可信度分級

`CONFIRMED`（雙瀏覽器可信 + 實驗確認）/ `SUSPECTED`（單側證據或動態不可信）/ `AMBIGUOUS`（兩端一致且可信 → 沒有 cloaking）。

降級為 `LOW` 的條件：任一端 error、HUMAN 耗時過短、預熱失敗、**兩端皆無機制但頁面存在未跨越的互動閘門**（CAPTCHA / alert / notification / click gate），以及**兩端皆無機制但結構分歧／redirect 分叉**（見上節）。

**閘門那一條**是必要的：CrawlPhish（S&P'21）Table V 統計 User Interaction 類佔客戶端 cloaking 實作的 **57.60%**，而爬蟲不點擊、不關 alert、不解 CAPTCHA —— 兩端都停在閘門前，機制集合差為空，但爬取本身「很健康」會拿到 `HIGH`，於是輸出 `False`，等於謊稱「驗過了，確認沒有 cloaking」。**對稱的「看不到」不能當成對稱的「沒有」**，這種情況必須回報 `N/A`。

---

## Node 5 — 輸出

`nodes/node5_output.py` → `csv_reports/cloaking_report_<時間戳>.csv`

```
url,alive,is_phishing,cloaking
```

`cloaking` 是**三態**：`True` / `False` / `N/A`。「沒驗到」和「驗過沒有」是兩件事 —— 雙瀏覽器 `LOW`/`FAILED` 時寫 `N/A`，不謊稱已確認無 cloaking。

`is_phishing` 只有**兩態**，這是不對稱的、且是刻意的：cloaking 需要兩份頁面比對才能下結論，任一端量測失敗就無從比較；釣魚判定只看真人端那一份，抓不到內容就是沒有任何證據 → `False`。若要把「抓不到」與「驗過不是」分開，得另外加一欄，不能改寫 `is_phishing`。

沒有風險分數：判定已經在 Node 3 / Node 4 用布林做完，再把兩個布林乘權重合成 0~1 的數字，只是把明確的結論重新變回需要解釋的東西。

---

## 環境安裝

```bash
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m playwright install chromium
```

`requirements.txt` 只列實際會 import 的套件（核對過，沒有用不到的東西）；`langchain-anthropic`/`langchain-google-genai` 是延遲 import，缺套件會提示而非崩潰。`curl_cffi` 是選用增強（TLS 指紋偽裝），註解在檔案裡，要用才裝。

日常開發用 VS Code 要記得把直譯器切到這個 `.venv`（右下角狀態列或 `Ctrl+Shift+P` → `Python: Select Interpreter`），否則會撿到系統上其他 Python 安裝，版本對不上、Playwright 瀏覽器快取版本也可能不一致。

## 準備 URL 清單

```bash
python build_urls.py 1000       # MUD 資料集的釣魚 URL，先探測存活再寫入
python build_urls.py 1000 --no-scan   # 只挑不探測（快，但約一成是死站）
python fetch_feed.py 300        # 對照組：OpenPhish 當日 feed + 合法樣本
```

`build_urls.py` 讀 `dataset/MUD_malicious_urls_2026_V2.csv`（632,844 筆，其中
釣魚 91,741 筆），依資料集自帶的 `reachability_class` 先挑高良率的桶再探測。

實測各桶抽 40 筆用我們自己的判準驗證：`active` 90% 存活、`unavailable` 90%、
`unreachable_or_unscanned` 只有 18%。`unavailable` 也有九成不是矛盾 ——
Node 0 把任何 HTTP 回應（含 403/404/5xx）都算存活，資料集的「unavailable」
正是我們的「alive」。先挑前四個桶可把探測浪費從八成降到一成：實測探測 1,141 筆
就湊滿 1,000 個存活站（89.0%），對照 PhiUSIIL 需要探測約 2,000 筆（51.5%）。

`build_urls.py` **不寫 `ground_truth.csv`** —— 全部都是釣魚標籤，分組沒有意義。
`evaluate.py` 沒有基準檔也能跑；若目錄裡留著對不上的舊基準檔，它會明講並改用整批統計。

## 執行

### 在 VS Code 裡跑（建議）

`.vscode/launch.json` 把實驗的每一種設定各做成一個 config，從「執行與偵錯」側欄的
下拉選單挑，F5 偵錯 / Ctrl+F5 直接執行：

| config | 設定 |
|---|---|
| 冒煙測試 | `--limit 15` + `SAVE_PAIR_HTML` |
| 主批 | `bot_human` + `CRAWL_ORDER=split`（順序批內切半）+ `SAVE_PAIR_HTML`，連跑三天 |
| A/A 對照 ×2 | `human_human` / `bot_bot`，同樣 `split` 以維持可比 |
| fetch_feed（`300 300`）/ evaluate（±`--baseline`）/ annotate / score | 對應的周邊工具 |

⚠️ launch config 的 `env` 會**覆蓋**預設值 —— 每個 config 都明寫了 `CRAWL_ORDER`，
改預設值時記得一起改，否則 `split` 永遠不會生效而且不會有任何提示。

**為什麼要用 launch config 而不是在終端機下 `$env:`**：PowerShell 的 `$env:X` 會留在
整個 session，跑完 A/A 批忘了改回來，下一批就沿用上一批的模式，而且不會有任何提示。
launch config 的 `env` 只作用於該次程序，天生不會殘留。

`main.py --limit N` 只取清單前 N 筆，冒煙測試不必為了跑 15 筆去動 `urls.txt`
（動了就得記得改回來，而那件事沒有任何東西會提醒你）。

### 在終端機裡跑

開發機是 Windows + PowerShell，所以下面是 PowerShell 語法。
⚠️ **PowerShell 的 `$env:X` 會留在整個 session**（不像 bash 的 `X=1 cmd` 只作用於單一指令），
跑完一批一定要改掉或清掉，否則下一批會沿用上一批的模式 —— manifest 會記錄實際值，
發現搞混時去 `csv_reports/run_*.json` 對。

```powershell
# 1. 主批（活體 feed，抓完立刻跑，別隔夜）
#    連跑三天累積 —— 單次 OpenPhish feed 只有數百筆，而盲標要 90 個陽性
#    （下界盛行率 ~10% 時需要約 900 筆存活釣魚站）。三天之間設定一個字都不能動，
#    否則三批不可合併；每批的 label 已逐列寫進 CSV，分母不會被覆蓋。
python fetch_feed.py 300 300
$env:PAIR_MODE = "bot_human"; $env:SAVE_PAIR_HTML = "1"
python main.py
#    CRAWL_ORDER 預設 split，兩種順序在同一批內各半，不必再跑第二次
Remove-Item Env:\SAVE_PAIR_HTML -ErrorAction SilentlyContinue

# 2. 噪音底線（同一份 urls.txt，釣魚 + 合法各 200 筆即可）
$env:PAIR_MODE = "human_human"; python main.py
$env:PAIR_MODE = "bot_bot";     python main.py
$env:PAIR_MODE = "bot_human"    # 記得改回來

# 3. 統計
python evaluate.py --baseline csv_reports/batch_results_<human_human那批>.csv

# 4. 盲標 → precision
python annotate.py --n-positive 90 --n-negative 50 --seed 20260821
python score_annotations.py
```

每批都會寫一份 **run manifest**（`csv_reports/run_<時間戳>.json`）記錄 git commit
＋**工作區是否乾淨**、URL 清單的 sha256、標籤筆數、`HUMAN_PROFILE`、`PAIR_MODE`、
`CRAWL_ORDER`、LLM 供應商。

沒有 manifest 的話，半年後沒有人說得出某個 CSV 是哪種設定跑出來的。

⚠️ **`git_dirty: true` 的批次不能當正式結果。** 工作區有未提交變更時，
manifest 記的那個 commit 指向的**不是**實際在跑的程式碼 —— 拿它去追溯只會看到舊版判準。
`main.py` 在批次開頭就會把這件事印出來（不是跑完才說），因為那時候重跑只花幾分鐘。
未追蹤的新檔也算 dirty：`git diff` 看不到它們，但 `page_mechanisms.py` 這種
還沒 commit 的新檔正是判準本體。

並行度預設 2（`main.py` 的 `max_concurrent`）。每個 URL 需 ~300MB RAM 給 Playwright，
LLM 走遠端 API 不吃本機資源；記憶體吃緊或要除錯時降回 1。

`csv_reports/batch_results_*.csv` 除了 Node 5 那四個結論欄，另有一個**分母欄**與十二個診斷欄（全部取自已算好的 state，零額外成本）：

| 欄位 | 用途 |
|---|---|
| `label` | **分母**。`fetch_feed.py` 寫進 `ground_truth.csv` 的清單標籤（`phishing` / `benign`），逐列複製到這裡。空白 = 沒有第二方標籤（`build_urls.py` 的純釣魚清單），**留空是刻意的**，見下 |
| `phishing_confidence` | `0.95` 一定是 Layer 1 布林裁決；落在閾值 `0.45` 附近的是 Layer 2 擦邊過關，兩者要分開看 |
| `phishing_indicators` | 命中的規則類別摘要（`類別: 前兩個命中`），含 `decisive_rule` 與 `llm_detected` |
| `cloaking_fired` | 觸發了哪幾條 C 規則（`C1｜C2…`），空白代表沒有 |
| `cloaking_tier` | 靜態層（含 LLM 的 S4）的產物，**不參與判定**，用來稽核 LLM 的貢獻 |
| `dynamic_reliability` | `HIGH` / `LOW` / `FAILED`，解釋 `N/A` 從哪來 |
| `human_mechanisms` | 真人端命中的完整機制集合 |
| `human_high_spec` | 其中屬於高特異性的子集 —— C2–C4 的閘門看的是這欄 |
| `content_similarity` | 描述性數據，不參與判定 |
| `reverse_diff` | BOT 端獨有的機制。**不參與裁決**，量的是順序汙染／burn-after-read |
| `rule_fired_raw` | C1–C5 是否有任一條觸發（未經可信度閘門）—— A/A 對照批唯一可比的欄位 |
| `crawl_order` / `pair_mode` | 這一列是哪種設定跑的，讓多批 CSV 可以直接串起來分組。`crawl_order` 是**實際**順序，不是模組常數 |

沒有這些欄位的話，1,000 筆跑完只會拿到 1,000 行布林，任何誤判都歸因不了。

#### `label` 為什麼必須逐列存，而不是事後 join

`ground_truth.csv` 是**單一固定檔名**，每跑一次 `fetch_feed.py` 就被覆蓋。跑第二批
就沖掉第一批的分母，而且不會有任何提示 —— 事後拿它去 join，對到的是最新那份清單，
不是這批當初跑的那份。對不上時 join 會安靜地少掉一堆列；對得上但內容已換時更糟：
分組照印、CI 照算，只有數字是錯的。

`evaluate.py` 的 `resolve_labels()` 因此有明確的優先序：**CSV 自帶的 `label` 欄 >
`ground_truth.csv` > 沒有**。`label` 欄存在但全空時**不會**回頭 join 基準檔——
那等於憑空生出一個分母。四條優先序全部由 `evaluate._selfcheck()` 鎖住，
`label` 的留空與帶值契約則由 `test_label_is_list_provenance_not_a_verdict` 鎖住。

⚠️ `label` **絕不可流進 `pairs/meta.json`**。它不是系統的判定，但它是**先驗**：
標註者知道「這站被 OpenPhish 標為釣魚」就會往 yes 靠，κ 與 precision 一起虛高。
`test_pair_meta_contains_no_verdict` 的 `forbidden_keys` 與全文字表（含 `benign`）
把兩條路都堵死，`annotate._selfcheck()` 另外掃 `build_html` 的**實際產出**。

### 分母：feed 標籤，不是 `is_phishing`

主結果是「**活體釣魚站中** cloaking 盛行率的下界」，分母是釣魚站。那個「是釣魚站」
由誰認定，決定了整個數字能不能讀：

**不能用 Node 3 的 `is_phishing`。** 它用 φ 判定，而分子（cloaking）的判定路徑
也全部經過 φ —— 同一把尺量分子和分母，兩邊的誤差是相關的。φ 偏一格，
分子分母同時偏，而比值看不出來。

**用 `label`**：`fetch_feed.py` 從 OpenPhish 取得的清單標籤，逐列寫進
`batch_results`。OpenPhish 是系統之外的第二方，這是唯一讓分母獨立於 φ 的方式。
`evaluate.py` 依 `label` 分組：釣魚組是主結果，合法組的 cloaking 率是特異性地板。

兩條隨之而來的 limitation，方向都已知，**都往下偏**，所以「報下界」這個主張
不受威脅，反而更站得住：

1. **定義上的蘊含。** cloaking 的定義本來就是「差別遞送**惡意**內容」，
   所以 cloaking 陽性在邏輯上已經預設了惡意 —— 兩欄不是彼此獨立的證據。
   這不是可以靠重排管線解掉的耦合：若 cloaking 不指向惡意內容，
   它就只是「差別遞送」，那 CDN、A/B test、多語系全部算數。
2. **feed 本身的選擇偏誤。** 能進 OpenPhish feed 的釣魚站，是 OpenPhish 的偵測
   管線**看得到**的站，也就是對它的爬蟲沒有成功 cloak 的站。真正會 cloak 的站
   系統性地較難進 feed，於是分子被壓低。分母換來源等於把 φ 的耦合換成 OpenPhish
   的偏誤 —— 但後者的方向明確且與「下界」相容，前者不是。

### 盛行率是一個區間，不是一個數

`evaluate.py` 對每組報三個數（全部附 Wilson CI）：

| | 定義 | 讀法 |
|---|---|---|
| ① 下界 | `True / N` | 「至少這麼多」，`N/A` 全當非 cloaking **← 主結果引用這個** |
| ③ 條件 | `True / (True + False)` | 排除 `N/A`，假設 `N/A` 與可判定子集同率 |
| ② 上界 | `(True + N/A) / N` | 「至多這麼多」，`N/A` 全當 cloaking |

`① ≤ ③ ≤ ②` 是這三個定義的不變式（`evaluate._selfcheck()` 用隨機三態向量驗證）。
③ 的那個假設**很可能不成立且要在論文裡明講**：`N/A` 富集了掛閘門與結構分歧的站，
那些正是更可能 cloak 的 —— 也就是說偏誤方向已知，① 比看起來更保守。
若 ① 和 ② 差了兩三倍，那本身就是必須在 limitation 裡討論的事實。

### 盲標 → precision

目前沒有任何獨立於系統之外的東西確認過一個陽性是對的。`_confirm_c1` 只是拿同一把尺
再量一次 —— 它確認「可重現」，不確認「正確」。量測框架下需要的正是 precision。

`SAVE_PAIR_HTML=1` 會把每個 URL 的兩份原始 HTML 寫到 `pairs/<sha1(url)[:12]>/`，
連同一份 `meta.json`。**`meta.json` 絕對不含任何判定結果** —— 盲標的前提是標註者
看不到答案，`test_pair_meta_contains_no_verdict` 用集合差 + 全文掃描鎖住這件事。

`annotate.py` 從陽性抽 90 筆、陰性抽 50 筆混進去打散（固定種子，不得依判定結果排序），
產生一份離線 HTML：左右並排兩份 HTML 的**渲染結果**（`<iframe srcdoc>`，sandbox 只給
`allow-same-origin`，絕不給 `allow-scripts` / `allow-forms` / `allow-top-navigation`
—— 我們在渲染釣魚頁）、下方附純文字 diff、三個按鈕（是差別遞送／不是／看不出來）。
標完按「匯出 annotations.csv」。

`score_annotations.py` 把標註接回批次結果，算保守與寬鬆兩種 precision、**依規則分的
precision**、陰性樣本被標為「是」的比例（不是 recall，但是漏報的下界資訊），
以及兩位標註者的 Cohen's κ。分規則的 precision 是這份工作最有價值的產出：
若 C1 的 precision 遠低於 C2–C4，就有實證理由把 C1 收緊，而那會是有資料支持的
設計決策，不是又一次調門檻。κ < 0.6 就先把準則寫清楚再重標。

GSB / VirusTotal / urlscan 回答的是「是不是釣魚」不是「有沒有 cloaking」，
`threat_intel.py` 的定位維持「驗證清單標籤是否仍成立」，不可越用。

**testbed 的排除已於 2026-08-23 解除。** 原本的理由是「只證明抓得到自己寫的東西，
**對盛行率無幫助**」—— 那是為盛行率寫的。主結果改成偵測能力之後它不再自動成立：
testbed 是 cloaking ground truth 的唯一來源，而 recall 沒有 ground truth 就量不了。
「只證明抓得到自己寫的東西」這個反對仍然有效，避開它的唯一方法是**刻意放進
預期抓不到的格子**（純 IP 分流、一次性 token、隨機分流）—— 涵蓋清單見
[`docs/mechanism_coverage.md`](docs/mechanism_coverage.md) 第五節。
testbed 只給 recall 與已知陰性，盛行率仍然只能來自活體樣本。

### `THREAT_INTEL` 已無作用

外部威脅情資（GSB / VirusTotal / urlscan）曾經是管線最前面的一個節點，會代答釣魚判定。
即使釣魚判定已經回到管線（Node 3），它仍然留在管線外：`threat_intel.py`
是獨立工具，用途是**驗證清單標籤是否仍成立**（`check_url(url)`）。

這個區分很重要：外部情資絕不可餵回管線當判定，那會讓量測對象與量測工具混在一起；
但拿它當獨立於受測系統之外的第三方背書，正是驗證「這批 URL 現在是否仍是釣魚站」
該用的東西 —— PhiUSIIL 的標記是 2024 年的狀態，兩年後不會自動仍然成立。

環境變數：

| | 說明 |
|---|---|
| `LLM_PROVIDER` | `lmstudio`（預設）/ `deepseek` / `anthropic` / `openai` / `google` |
| `<PROVIDER>_API_KEY` | 對應的 key；未設定則所有 LLM 節點退化為純規則模式（`lmstudio` 例外，見下）|
| `LLM_MODEL` | 覆寫預設模型 |
| `HUMAN_PROFILE` | `tw-desktop`（預設）/ `jp-mobile` / `jp-desktop` / `us-desktop` / `jp-mac-safari` |
| `CRAWL_ORDER` | `bot_first`（預設）/ `human_first` —— 誰先出發 |
| `PAIR_MODE` | `bot_human`（預設）/ `human_human` / `bot_bot` —— A/A 對照批用後兩者 |
| `SAVE_PAIR_HTML` | `=1` 保存配對 HTML 供盲標（1000 筆 ≈ 數百 MB，只在要標的批次開）|
| `GOOGLE_SAFEBROWSING_API_KEY` / `VT_API_KEY` / `URLSCAN_API_KEY` | 僅供 `threat_intel.check_url()` 這個獨立驗證工具使用，不在管線內 |

⚠️ Claude 5 系列已移除 `temperature` / `top_p` / `top_k`，送出直接回 400 —— `_make_llm` 依供應商決定要不要帶。

### 接 LM Studio（本地模型）

LM Studio 開的是本地 OpenAI 相容端點，跟 `deepseek` 走同一條 `ChatOpenAI(base_url=...)` 路徑，不用裝新套件。

```bash
# 1. LM Studio 內開啟 Local Server（預設 port 1234），載入想用的模型
# 2. 設定環境變數並啟動
$env:LLM_PROVIDER = "lmstudio"
$env:LLM_MODEL    = "<Local Server 分頁顯示的確切 model identifier>"
python main.py
```

| | 說明 |
|---|---|
| `LMSTUDIO_API_KEY` | 選填，LM Studio 不驗證這個值，不設定會自動帶入佔位字串 |
| `LMSTUDIO_BASE_URL` | 選填，預設 `http://localhost:1234/v1` |
| `LLM_MODEL` | **幾乎一定要設**——多模型時 LM Studio 靠這個欄位路由到已載入的模型，隨便填字串可能連不到 |

本地推理通常比雲端 API 慢，若常常 timeout，直接調大 `llm.py` 裡 `llm_code`/`llm_phish`/`llm_cloak` 三個 `_make_llm()` 呼叫的 `timeout` 參數即可（純數字，沒有另外的設定系統）。

## 測試

```bash
python test_page_mechanisms.py && python test_node3_phishing.py && python test_node4_cloaking.py && python test_node4_static.py && python test_pipeline_e2e.py
```

66 個測試。`test_pipeline_e2e.py` 的 cloaked 情境會觸發 `_confirm_c1` 的重爬（那一次是真的連網，連不上就走「重爬失敗保守維持原判定」那條路，斷言不受影響）；其餘全部不連網。`evaluate.py` / `annotate.py` / `score_annotations.py` 各自帶 `_selfcheck()`，執行時自動跑（盛行率不變式、盲標頁不含系統結論、precision 與手算一致）。`test_pipeline_e2e.py` 換掉的是兩處網路呼叫 —— `dual_crawl` 與 Node 0 的可達性探測（`node0_liveness.requests`）—— 節點本身與節點之間的條件路由都是真的在跑，所以 edge 接錯時這裡會失敗。

## Graph 拓撲

```
node0 ─┬─ dead ──────────────────→ END（報告已在 node0 寫好）
       └─ alive → node1 ─┬─ 抓不到內容 → node5（釣魚記 False、cloaking 記 N/A）
                         └─ node2 → node3 → node4 → node5
```

| | 節點 | 產出 |
|---|---|---|
| node0 | `node0_liveness` | `alive` |
| node1 | `node1_scraper` | `bot_crawl` / `human_crawl` / `raw_html` |
| node2 | `node2_js_analyzer` | `deobfuscated_js` |
| node3 | `node3_phishing_classifier` | `is_phishing` |
| node4 | `node4_cloaking_analyzer` | `cloaking_verified` / `dual_crawl_results` |
| node5 | `node5_output` | CSV 一行 + `report` |

**Node 2 不可跳過。** Node 4 的靜態層比對的是可讀原始碼，壓縮成 `n.wD` 的字串
比對不到 `navigator.webdriver`。這是整條管線唯一真正的順序依賴。

**node3 與 node4 的先後沒有語意。** 釣魚與 cloaking 互不為前提，兩者都只讀
node2 的輸出、寫不相交的 state 欄位。串成線性只是因為 LangGraph 的分岔合流
要寫 reducer，而並行在這裡沒有任何好處。

**Node 0 與 Node 1 的「活著」不同義。** Node 0 用一次 HTTP 請求測可達性，
Node 1 用真瀏覽器跑完整渲染 —— 後者才會遇到逾時、JS 崩潰、空白頁，
所以存活檢查過了仍可能抓不到內容。

## 檔案

| 檔案 | 行數 | 職責 |
|---|---|---|
| `main.py` | 465 | 批次執行、進度條、彙整輸出、CLI |
| `graph.py` | 84 | LangGraph 組裝與條件路由 |
| `llm.py` | 203 | LLM 供應商工廠（5 種）、`.env` 載入 |
| `state.py` | 34 | `AnalysisState` TypedDict |
| `nodes/node0_liveness.py` | 56 | 存活檢查（管線與 `build_urls.py` 預掃共用同一判準）|
| `nodes/dual_crawler.py` | 1077 | BOT/HUMAN Playwright 爬取層 |
| `nodes/node1_scraper.py` | 138 | 呼叫雙重爬取、抽 JS |
| `nodes/node2_js_analyzer.py` | 331 | 去混淆 |
| `nodes/node3_phishing_classifier.py` | 148 | 兩層釣魚判定（規則層在 `page_mechanisms.py`）|
| `nodes/node4_cloaking_analyzer.py` | 878 | 靜態 + 動態 cloaking 判定 |
| `nodes/node5_output.py` | 95 | 四欄 CSV 輸出 |
| `nodes/page_mechanisms.py` | 1120 | **不是節點**：惡意機制判準 φ，Node 3 與 Node 4 共用 |

周邊工具（皆非節點）：

| 檔案 | 職責 |
|---|---|
| `build_urls.py` | 從 MUD 資料集挑存活的釣魚 URL → `urls.txt` |
| `fetch_feed.py` | 對照組：OpenPhish 當日 feed + MUD 合法樣本 → `urls.txt` + `ground_truth.csv` |
| `evaluate.py` | 三種盛行率、A/A 比對（`--baseline`）、爬取順序分組、反向差非空率 |
| `annotate.py` | 產生盲標用的並排檢視頁（讀 `pairs/`，畫面上不含任何系統結論）|
| `score_annotations.py` | 把標註接回批次結果 → precision（總體 / 分規則）+ Cohen's κ |
| `threat_intel.py` | GSB / VirusTotal / urlscan 查詢，驗證清單標籤是否仍成立 |
| `draft/make_fig1.py` | 重畫論文 Fig.1 架構圖（中英各一份，PNG + SVG）|

架構圖是**產生**的不是手畫的：`python draft/make_fig1.py`。圖上的數字（D1–D7、15 類加權訊號、
C1–C5、5 種受害者輪廓、輸出欄位）由腳本裡的 `_selfcheck()` 對著規則表核對，對不上就直接失敗 ——
上一版手畫的圖漂移了三個版本沒人發現，這是為了讓它不可能再默默過期。

（`nodes/__init__.py` 只固定主控台編碼、`nodes/prompts.py` 只放 LLM prompt 常數，不列職責）

---

## 已知限制

### 量測框架本身的限制（這幾條決定論文能講什麼）

1. **φ 的 recall 是 cloaking 判定的 recall 上界。** 判定路徑每一步都經過
   `evaluate_page()`，所以 φ 認不出惡意的頁面，本系統就量不到差別遞送。
   這類案例回報 `N/A` 而非 `False`（結構分歧降級），但降級只涵蓋「結構上看得出
   不是同一份頁面」的子集 —— 換頁換得結構也一樣的，仍然會落在 `False` 裡。
   這條上界現在**有數字**：`report_phi_blindspot()` 量「feed 說是釣魚、站還活著、
   但真人端零機制」的比例（見「φ 的 recall 是 cloaking 判定的天花板」）。
2. **單一配對只能產生下界。** 觸發軸正交於此配對的 cloaking（地理／平台／時間／
   一次性 token）對它全盲。所以報的是盛行率下界，不是偵測率。
3. **`N/A` 的偏誤方向已知但未量化。** `N/A` 富集了掛閘門與結構分歧的站，那些正是
   更可能 cloak 的 —— 因此下界比看起來更保守。要收窄區間需要對 `N/A` 子集抽樣人工判讀。
4. **樣本本身有存活偏誤。** blocklist 是「已被偵測到」的樣本，成功的 cloaking 在
   裡面是**系統性低估**的。分母改由 feed 標籤決定之後，這條偏誤直接進入主結果 ——
   能進 OpenPhish 的是它的爬蟲看得到的站，也就是對它沒有成功 cloak 的站
   （見「分母：feed 標籤，不是 `is_phishing`」）。方向已知且往下偏，與「報下界」
   相容。要不要量化（例如比較 feed 上架後不同時間窗的陽性率）尚未決定。
5. **合法對照組不可比。** OpenPageRank 高排名站普遍掛 WAF/CDN，與釣魚站的託管環境
   根本不同型；「合法站陽性率 11.3% > 釣魚站 8.3%」那個反轉有相當一部分來自託管
   環境而非判定邏輯。
6. **Randomization 型 cloaking 被 `_confirm_c1` 一併剔除**（見上），這是為了擋輪播／
   A-B test 誤報付的代價。
7. **cloaking 與釣魚兩欄不是彼此獨立的證據。** cloaking 的定義是「差別遞送**惡意**
   內容」，陽性在邏輯上已經預設了惡意。這不是可以靠重排管線解掉的耦合 ——
   若 cloaking 不指向惡意內容，它就只是「差別遞送」，那 CDN、A/B test、多語系
   全部算數。分母改用 feed 標籤能讓**分母**獨立於 φ，但分子與「惡意」的綁定
   是定義本身，必須在論文裡當成前提講明，不能當成待修的缺陷。

### 實作層的限制

7. **CAPTCHA 類閘門仍看不到。** click / alert 類已可跨越，但 CAPTCHA 刻意不破解 → 兩端對稱看不到內容，誠實回報 `N/A`。跨閘門的啟發式也只點「字樣像閘門」的元素，非典型措辭的閘門會漏。
8. **IP 維度沒有極化（刻意的）。** 兩端共用出口，純 IP 判別的 cloaking 全盲，同一出口下的 burn-after-read 汙染也無法從設計上排除，只能用 `reverse_diff` 與 `CRAWL_ORDER` 反轉去量。這是為了讓「五維極化配對本身夠不夠」這個假設可被檢驗而付的代價。
9. **單次執行只用一個 HUMAN profile。** 已可用 `HUMAN_PROFILE` 切換五種預設，但一次跑只覆蓋一種；針對其他地區／平台的 kit 仍會把 HUMAN 判為非目標 → 兩端對稱 → 漏報。要完整覆蓋需跑多個 profile 再取聯集，成本線性增加。
10. **Node 4 的機制比對吃原始 HTML，不吃去混淆結果。** 兩端對等，但混淆過的釣魚頁可能兩端都測不出機制（`code_obfuscation_exec` 這個 flag 部分擋住）。修法是對兩份 HTML 都跑去混淆，代價是 LLM 成本 ×2。
11. **機制詞彙的收錄與分級沒有經驗校準。** 這是現在真正的限制，而不是權重或閾值 —— cloaking 判定只看**哪些 flag 亮起來**（`evaluate_page().mechanisms`），Layer 2 的分數與 `PHISHING_CONFIDENCE_THRESHOLD` 都不參與。所以要問的是：哪些 pattern 該算一個「機制」、`HIGH_SPECIFICITY_MECHANISMS` 與 `PAGE_FEATURE_MECHANISMS` 的分界畫在哪裡。
   目前這條分界是**依「合法網站有沒有理由做這件事」手工判斷**的，唯一的實證來自 8/19–8/20 的誤判歸因（`brand_asset_hotlink` / `hidden_iframe` / `credential_harvesting` 是第三方 widget 造成的偽陽性主因）。要真正校準需要一份**帶 cloaking 標記**的資料集，而公開資料集都只有釣魚／合法標記 —— 這是本專案最根本的資料缺口。
12. **Node 2 的 LLM 去混淆（timeout 240s）是剩下最貴的一塊。** 產物有兩個消費者：Node 3 的釣魚判準（`extra_js`，**會影響 is_phishing**）與 Node 4 的靜態層（只產出佐證與 `cloaking_tier`）。動態層讀原始 HTML，所以對 `cloaking` 那一欄這筆成本換到的是診斷，不是判定。
