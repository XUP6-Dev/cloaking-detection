"""相容轉接：φ 已搬到 analysis/page_mechanisms.py（內容逐位元組未變）。

`import nodes.page_mechanisms` 拿到的是同一個模組物件，不是複本 —— 判準只能有一份，
否則「兩邊用同一把尺」就不再成立。新程式請直接 import analysis.page_mechanisms。
"""
import sys

from analysis import page_mechanisms as _phi

sys.modules[__name__] = _phi
