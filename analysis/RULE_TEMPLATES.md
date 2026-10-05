# 規則模板速查表

`page_mechanisms.py`（φ：釣魚判定與 cloaking 機制集合差共用）與 `static_cloaking.py`
（前端 JS 特徵）裡有 5 種規則表，形狀各不相同。要新增規則時不用重讀整個檔案，複製對應
模板貼進去、填空就好。

前三種住在 `page_mechanisms.py`，是因為釣魚判定與 cloaking 機制集合差必須用同一把尺 ——
改這三張表會同時移動兩欄輸出，而且之前跑過的批次全部不能與之後合併。**動 φ 之前**：
同時改 `schemas/versions.py` 的 `RULE_VERSION` 與 `MEASUREMENT_VERSION`，以及
`tests/test_compat.py` 鎖住的 φ 雜湊（那個測試會擋下「順手」的修改）。

---

## 1. Layer 2 加權信號 — `PHISHING_RULES`
[page_mechanisms.py:33](page_mechanisms.py#L33)

單一 pattern 命中不能直接判釣魚的弱訊號，累加到 0.45 才算數。

```python
"你的信號名稱": {
    "weight": 0.10,   # 越獨特權重越高；合法網站也常見 → 壓到 0.02~0.08
    "patterns": [
        r"你的正則",
    ]
},
```

貼進 `PHISHING_RULES = {` 字典裡任一位置即可。**別讓所有規則權重加起來輕易超過
0.45**（目前設計是要讓合法網站基礎分落在 0.30 以下）。

---

## 2. Layer 1 布林裁決 — `DECISIVE_RULES`
[page_mechanisms.py:309](page_mechanisms.py#L309)

命中即定案，跳過計分。只放「合法網站不可能觸發」的組合。

```python
{
    "id": "D8",
    "flags": ["flag_a", "flag_b"],   # 全部要命中（AND）；flag 名稱對應 PHISHING_RULES 的 key
    "label": "一句話說明為什麼合法網站不會這樣做",
},
```

貼進 `DECISIVE_RULES = [` 列表最後。新增前檢查：①合法網站有沒有合理情境會觸發
②攻擊者要規避這個組合，成本是不是真的高（不是隨手改個字串就能繞過）。

---

## 3. 組合信號 — `COMBO_RULES`
[page_mechanisms.py:369](page_mechanisms.py#L369)

比 Layer 1 弱一階：不是「合法網站不可能」，是「同時出現才夠可疑」。

```python
{
    "required": {
        "信號A": 1,   # key 對應 PHISHING_RULES，數字是該類別至少要命中幾個 pattern
        "信號B":   2,
    },
    "bonus": 0.20,       # 加到 rule_score
    "label": "一句話說明這個組合代表什麼攻擊鏈",
},
```

貼進 `COMBO_RULES = [` 列表任一位置。

---

## 4. 前端 cloaking 特徵庫 — `CLOAKING_SIGNATURES`
[static_cloaking.py:57](static_cloaking.py#L57)

純特徵字典，只記錄「命中了什麼」，本身不裁決 cloaking。

```python
"你的技術名稱": {
    "patterns": [
        r"你的正則",
    ]
},
```

貼進 `CLOAKING_SIGNATURES = {` 字典裡。新增後記得決定它該歸進下面第 5 項的哪一組
（`_CRAWLER_ARTIFACTS` / `_GENERIC_PROBES` / `_COND_FINGERPRINT` / `_EVASION_ACTIONS`，
定義在同檔案 17~33 行），不歸組的話 import 時的檢查會直接失敗。

---

## 5. 前端 cloaking 布林規則 — `STATIC_CLOAKING_RULES`
[static_cloaking.py:35](static_cloaking.py#L35)

「偵測環境」+「依結果改內容」兩半都要命中才成立，沒有門檻分數。命中的效果是
**擋住 cloaking=false**（頁面有能力只對特定 client 換內容），不會讓標籤變 true。

```python
("S5", [(_CRAWLER_ARTIFACTS, 1), (_COND_FINGERPRINT, 1)],
 "一句話說明這個組合"),
```

`(分組集合, 該組最少命中幾個技術)`，多個 tuple 之間是 AND。分組集合必須是第 4 項
裡定義好的那幾個 `_XXX` set，不要臨時湊一個新 set 除非你也打算長期維護它。

---

## 這張表沒收錄的

- C1–C5（兩種 client 的機制集合差）不是查表可加的，邏輯在 `cloaking.py` 的
  `decide_cloaking()`；最終三態標籤的閘門在 `label_cloaking()`。改動前讀
  [README.md](../README.md) 的「標籤定義」與「Cloaking 訊號」兩節。
- 想調整既有規則的權重/門檻而不是新增規則：直接改對應字典裡的數字，不需要模板 ——
  但那仍是改 φ，見上面的版本規則。
