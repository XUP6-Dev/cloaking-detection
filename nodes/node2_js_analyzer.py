"""Node 2：JS 去混淆（analysis/deobfuscation.py）。不可跳過：Node 3 與 Node 4 的規則都比對
還原後的可讀原始碼，graph.py 把它接成 Node 1 之後唯一的路。"""
from analysis.deobfuscation import Deobfuscator


def analyze_js_node(state, llm):
    print("\n[Node 2] JS 去混淆...")
    deobfuscator = Deobfuscator()
    deobfuscated = []
    total = len(state["js_scripts"])
    for i, script in enumerate(state["js_scripts"]):
        print(f"  → [去混淆 {i+1}/{total}] {script['type']} ({len(script['content'])} chars)...")
        result = deobfuscator.deobfuscate(script["content"], llm)
        state["model_outputs"] = state.get("model_outputs", []) + result["model_outputs"]
        deobfuscated.append({**script,
                             "deobfuscated": result["deobfuscated"],
                             "model_code": result["model_code"],
                             "techniques_used": result["techniques_used"],
                             "obfuscation_score": result["obfuscation_score"]})
        print(f"     分數: {result['obfuscation_score']:.2f} | 工具: {', '.join(result['techniques_used'])}")
    state["deobfuscated_js"] = deobfuscated
    print(f"  → 去混淆完成: {len(deobfuscated)} 個腳本")
    return state
