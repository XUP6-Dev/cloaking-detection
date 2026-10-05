"""保守的 URL 正規化 —— 只做「確定不會把兩個不同樣本合併」的轉換。

不合併 /x 與 /x/、不重排 query、不解碼跳脫、不去掉 fragment：任何一項都可能把
攻擊者刻意區分的兩條路徑併成一筆，分母因此安靜地縮水。版本號寫進每個批次 manifest。
"""
import re
from urllib.parse import urlsplit, urlunsplit

NORMALIZATION_VERSION = "conservative-url-v1"


def normalize_url(raw):
    value = raw.strip()
    if not value or re.search(r"[\x00-\x20\x7f\\]", value):
        raise ValueError("invalid_url_characters")
    p = urlsplit(value)
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        raise ValueError("http_url_required")
    if p.username is not None or p.password is not None:
        raise ValueError("userinfo_not_allowed")
    host = p.hostname.encode("idna").decode("ascii").lower()
    port = p.port  # 壞 port 會在這裡拋 ValueError
    if ":" in host:
        host = f"[{host}]"
    if port and port != (443 if p.scheme.lower() == "https" else 80):
        host += f":{port}"
    return urlunsplit((p.scheme.lower(), host, p.path or "/", p.query, p.fragment))


def origin(url):
    p = urlsplit(normalize_url(url))
    return f"{p.scheme}://{p.netloc}"


def host_of(url):
    """比較用的主機名（小寫、無 port）；解析不了回空字串，不拋例外。"""
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""
