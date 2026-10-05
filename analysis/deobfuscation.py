"""JS 去混淆：確定性的字串還原（eval/atob、hex、unicode、obfuscator.io 字串陣列、字串合併、
beautify），模型重建只作參考。

為什麼必須在釣魚與 cloaking 判定之前：兩者的規則都比對可讀原始碼，壓縮成 `n.wD` 的字串
比對不到 `navigator.webdriver`，S1–S3 與 φ 會在沒有任何錯誤訊息的情況下失效。
這是整條管線唯一真正的順序依賴（graph.py 鎖住它）。

模型重建的程式碼存在 model_code，**從不覆寫** deobfuscated —— 規則只讀確定性結果，
換模型或停用模型，規則看到的內容一模一樣。
"""
import base64
import re
import urllib.parse
from typing import Any, Dict, List

import jsbeautifier

from llm.contract import model_observation
from llm.prompts import DEOBFUSCATE_PROMPT

# ── 常數 ─────────────────────────────────────────────────────
MAX_ITERATIONS   = 3      # 最多迭代幾輪
LLM_CHUNK_SIZE   = 2500   # 每塊送給 LLM 的字元上限
OBF_SCORE_THRESH = 0.45   # 觸發 LLM 的混淆分數門檻


class Deobfuscator:

    @staticmethod
    def _well_formed_js_text(code: str) -> str:
        # JS 以 UTF-16 code unit 表示字串。合併成對的 surrogate；孤立的 surrogate
        # 保留成可見的 JS 跳脫，而不是變成無法編碼成 UTF-8 的 Python 字串。
        code = code.encode("utf-16-le", errors="surrogatepass").decode("utf-16-le", errors="surrogatepass")
        return re.sub(r"[\ud800-\udfff]", lambda m: f"\\u{ord(m.group()):04x}", code)

    def beautify(self, code: str) -> str:
        opts = jsbeautifier.default_options()
        opts.indent_size           = 2
        opts.break_chained_methods = True
        opts.unescape_strings      = True
        opts.jslint_happy          = False
        try:
            return self._well_formed_js_text(jsbeautifier.beautify(code, opts))
        except Exception:
            return self._well_formed_js_text(code)

    def decode_eval_patterns(self, code: str) -> str:
        def decode_atob(m):
            try:
                return base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            except Exception:
                return m.group(0)

        def decode_unescape(m):
            try:
                return urllib.parse.unquote(m.group(1))
            except Exception:
                return m.group(0)

        code = re.sub(
            r"eval\s*\(\s*atob\s*\(\s*['\"]([A-Za-z0-9+/=]+)['\"]\s*\)\s*\)",
            decode_atob, code
        )
        code = re.sub(
            r"eval\s*\(\s*unescape\s*\(\s*['\"]([^'\"]+)['\"]\s*\)\s*\)",
            decode_unescape, code
        )
        return code

    def decode_hex_strings(self, code: str) -> str:
        def decode_hex(m):
            try:
                return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")
            except Exception:
                return m.group(0)
        return re.sub(r"\\x([0-9a-fA-F]{2})", decode_hex, code)

    def decode_unicode_escapes(self, code: str) -> str:
        def replace_pair(m: re.Match) -> str:
            high, low = int(m.group(1), 16), int(m.group(2), 16)
            return chr(0x10000 + ((high - 0xD800) << 10) + low - 0xDC00)
        code = re.sub(r"\\u([dD][89aAbB][0-9a-fA-F]{2})\\u([dD][c-fC-F][0-9a-fA-F]{2})", replace_pair, code)

        def replace_unicode(m: re.Match) -> str:
            try:
                value = int(m.group(1), 16)
                return m.group(0) if 0xD800 <= value <= 0xDFFF else chr(value)
            except (ValueError, OverflowError):
                return m.group(0)
        return re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, code)

    def decode_obfuscator_io(self, code: str) -> tuple:
        changed = False
        array_pattern = re.compile(
            r"var\s+(_0x[0-9a-fA-F]+)\s*=\s*\[([^\]]*)\]\s*;",
            re.DOTALL
        )
        for m in array_pattern.finditer(code):
            arr_name = m.group(1)
            raw_items = m.group(2)

            items: List[str] = []
            for item_m in re.finditer(
                r"'((?:[^'\\]|\\.)*)'\s*,?|\"((?:[^\"\\]|\\.)*)\"\s*,?",
                raw_items
            ):
                items.append(
                    item_m.group(1) if item_m.group(1) is not None
                    else item_m.group(2)
                )
            if not items:
                continue

            lookup_pattern = re.compile(
                r"function\s+(_0x[0-9a-fA-F]+)\s*\([^)]*\)\s*\{"
                r"[^}]*return\s+" + re.escape(arr_name) + r"\s*\[",
                re.DOTALL
            )
            lm = lookup_pattern.search(code)
            if not lm:
                continue
            lookup_fn = lm.group(1)

            def replace_call(cm, _items=items):
                try:
                    idx = int(cm.group(1), 16)
                    if 0 <= idx < len(_items):
                        return repr(_items[idx])
                except Exception:
                    pass
                return cm.group(0)

            new_code = re.sub(
                re.escape(lookup_fn) + r"\s*\(\s*0x([0-9a-fA-F]+)\s*\)",
                replace_call, code
            )
            if new_code != code:
                code = new_code
                changed = True

        return code, changed

    def is_jsfuck_or_jjencode(self, code: str) -> bool:
        stripped = re.sub(r'\s', '', code)
        if not stripped:
            return False
        jsfuck_chars = set('[]!+()')
        jsfuck_ratio = sum(1 for c in stripped if c in jsfuck_chars) / len(stripped)
        is_jjencode  = stripped.startswith('$=~[]') or stripped.startswith('$$$=~[]')
        return jsfuck_ratio > 0.85 or is_jjencode

    def fold_string_concat(self, code: str) -> str:
        pattern = re.compile(
            r"""(['"])((?:[^'"\\]|\\.)*)\1\s*\+\s*(['"])((?:[^'"\\]|\\.)*)\3"""
        )
        for _ in range(5):
            new_code = pattern.sub(
                lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1),
                code
            )
            if new_code == code:
                break
            code = new_code
        return code

    def llm_deobfuscate(self, code: str, llm_instance) -> str:
        if len(code) <= LLM_CHUNK_SIZE:
            return self._llm_invoke_chunk(code, llm_instance)
        chunks  = self._split_by_boundary(code, LLM_CHUNK_SIZE)
        results = []
        for i, chunk in enumerate(chunks):
            print(f"    [LLM] 分塊 {i+1}/{len(chunks)} ({len(chunk)} chars)...")
            results.append(self._llm_invoke_chunk(chunk, llm_instance))
        return "\n".join(results)

    def _split_by_boundary(self, code: str, chunk_size: int) -> List[str]:
        chunks, start = [], 0
        while start < len(code):
            end = start + chunk_size
            if end >= len(code):
                chunks.append(code[start:])
                break
            boundary = code.rfind('\n', start, end)
            if boundary <= start:
                boundary = end
            chunks.append(code[start:boundary])
            start = boundary
        return chunks

    def _llm_invoke_chunk(self, chunk: str, llm_instance) -> str:
        audit = model_observation(llm_instance, "code", DEOBFUSCATE_PROMPT % chunk)
        self.model_audits.append(audit)
        return audit["output"]["code"] if audit["status"] == "valid" else chunk

    def _measure_obfuscation(self, code: str) -> float:
        if not code:
            return 0.0
        words = re.findall(r'[a-zA-Z_$][a-zA-Z0-9_$]*', code)
        if not words:
            return 0.0
        avg_len     = sum(len(w) for w in words) / len(words)
        short_ratio = sum(1 for w in words if len(w) <= 2) / len(words)
        hex_ratio   = len(re.findall(r'\\x[0-9a-fA-F]{2}', code)) / max(len(code), 1)
        obfio_ratio = sum(1 for w in words if w.startswith('_0x')) / max(len(words), 1)
        stripped    = re.sub(r'\s', '', code)
        jsfuck_chars  = set('[]!+()')
        jsfuck_ratio  = (
            sum(1 for c in stripped if c in jsfuck_chars) / len(stripped)
            if stripped else 0
        )
        score = (
            short_ratio  * 0.25 +
            obfio_ratio  * 0.35 +
            (hex_ratio * 100) * 0.15 +
            (max(0, 4 - avg_len) / 4) * 0.15 +
            jsfuck_ratio * 0.10
        )
        return min(1.0, score)

    def deobfuscate(self, code: str, llm_instance) -> Dict[str, Any]:
        self.model_audits = []
        techniques_used: List[str] = []
        prev_score = self._measure_obfuscation(code)

        for iteration in range(MAX_ITERATIONS):
            changed = False
            tag = f"[round{iteration+1}]"

            if re.search(r"eval\s*\(\s*atob\s*\(", code) or \
               re.search(r"eval\s*\(\s*unescape\s*\(", code):
                new = self.decode_eval_patterns(code)
                if new != code:
                    code = new
                    techniques_used.append(f"{tag} eval decode (atob/unescape)")
                    changed = True

            if re.search(r"\\x[0-9a-fA-F]{2}", code):
                code = self.decode_hex_strings(code)
                techniques_used.append(f"{tag} hex decode (\\xNN)")
                changed = True

            if re.search(r"\\u[0-9a-fA-F]{4}", code):
                code = self.decode_unicode_escapes(code)
                techniques_used.append(f"{tag} unicode decode (\\uXXXX)")
                changed = True

            if re.search(r"var\s+_0x[0-9a-fA-F]+\s*=\s*\[", code):
                code, io_changed = self.decode_obfuscator_io(code)
                if io_changed:
                    techniques_used.append(f"{tag} obfuscator.io string array decode")
                    changed = True

            new = self.fold_string_concat(code)
            if new != code:
                code = new
                techniques_used.append(f"{tag} string concat folding")
                changed = True

            code = self.beautify(code)

            current_score = self._measure_obfuscation(code)
            if not changed and current_score >= prev_score - 0.02:
                break
            prev_score = current_score

        final_score = self._measure_obfuscation(code)
        is_special  = self.is_jsfuck_or_jjencode(code)

        model_code = None
        if llm_instance is not None and (final_score > OBF_SCORE_THRESH or is_special):
            label = "JSFuck/JJencode" if is_special else f"score={final_score:.2f}"
            print(f"    → 觸發 LLM 去混淆 ({label})")
            model_code = self.llm_deobfuscate(code[:10000], llm_instance)
            # 模型重建只作參考，絕不覆寫確定性證據。

        if not techniques_used:
            techniques_used.append("no obfuscation detected")

        return {
            "deobfuscated":      code,
            "model_code": model_code,
            "model_outputs": self.model_audits,
            "techniques_used":   techniques_used,
            "obfuscation_score": self._measure_obfuscation(code),
        }
