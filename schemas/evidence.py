"""證據值的共同處理：UTC 時間、SHA-256、JSON 化。

所有證據都以「原始值 + 雜湊」保存，雜湊讓事後能驗證檔案沒被動過。
"""
import hashlib
from datetime import datetime, timezone


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(value):
    # 不可信的 JS／模型字串可能含孤立的 UTF-16 surrogate。surrogatepass 讓它們
    # 仍可雜湊且不會把不同的 code unit 摺疊成同一個值；一般 Unicode 的雜湊不受影響。
    data = value if isinstance(value, bytes) else value.encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(data).hexdigest()


def jsonable(value):
    """set → 排序後的 list（讓輸出可重現）；tuple → list；其餘遞迴處理。"""
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, set):
        return [jsonable(v) for v in sorted(value)]
    if isinstance(value, (tuple, list)):
        return [jsonable(v) for v in value]
    return value
