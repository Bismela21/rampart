"""Access-log parsers: Caddy JSON, nginx JSON (log_format provided by `rmon setup`) and nginx 'combined'."""
import json
import re
from dataclasses import dataclass, field


@dataclass
class Request:
    ip: str
    method: str = "GET"
    host: str = ""
    path: str = "/"
    query: str = ""
    status: int = 0
    size: int = 0
    ua: str = ""
    al: str = ""      # Accept-Language
    ae: str = ""      # Accept-Encoding
    sua: str = ""     # Sec-CH-UA
    sup: str = ""     # Sec-CH-UA-Platform
    has_fp: bool = False   # False for formats that cannot carry the extra headers (nginx combined)
    extra: dict = field(default_factory=dict)

    def fp_parts(self):
        return {"ua": self.ua, "al": self.al, "ae": self.ae, "sua": self.sua, "sup": self.sup}


COMBINED = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) (\d+|-) "[^"]*" "([^"]*)"')


def _first(v):
    if isinstance(v, list):
        return str(v[0]) if v else ""
    return "" if v is None else str(v)


def _split_uri(uri):
    p, _, q = str(uri).partition("?")
    return p, q


def parse_caddy(j):
    r = j.get("request") or {}
    ip = r.get("client_ip") or r.get("remote_ip") or ""
    path, query = _split_uri(r.get("uri", "/"))
    h = r.get("headers") or {}
    ua = j.get("fp_ua", _first(h.get("User-Agent")))
    has_fp = "fp_ua" in j or bool(h)
    return Request(ip=ip, method=r.get("method", "GET"), host=r.get("host", ""), path=path, query=query, status=int(j.get("status") or 0),
                   size=int(j.get("size") or 0), ua=ua or "", al=j.get("fp_al", _first(h.get("Accept-Language"))) or "", ae=j.get("fp_ae", _first(h.get("Accept-Encoding"))) or "",
                   sua=j.get("fp_sua", _first(h.get("Sec-Ch-Ua"))) or "", sup=j.get("fp_sup", _first(h.get("Sec-Ch-Ua-Platform"))) or "", has_fp=has_fp)


def parse_nginx_json(j):
    path, query = _split_uri(j.get("uri", "/"))
    return Request(ip=j.get("ip", ""), method=j.get("method", "GET"), host=j.get("host", ""), path=path, query=query, status=int(j.get("status") or 0),
                   size=int(j.get("bytes") or 0), ua=j.get("ua", ""), al=j.get("al", ""), ae=j.get("ae", ""), sua=j.get("sua", ""), sup=j.get("sup", ""), has_fp="ua" in j)


def parse_combined(line):
    m = COMBINED.match(line)
    if not m:
        return None
    path, query = _split_uri(m.group(3))
    return Request(ip=m.group(1), method=m.group(2), path=path, query=query, status=int(m.group(4)), size=0 if m.group(5) == "-" else int(m.group(5)), ua=m.group(6))


def parse_line(line, fmt="auto"):
    """Returns a Request or None. 'auto' detects JSON (Caddy or nginx) versus combined."""
    line = line.strip()
    if not line:
        return None
    if fmt in ("auto", "caddy_json", "nginx_json") and line.startswith("{"):
        try:
            j = json.loads(line)
        except ValueError:
            return None
        if fmt == "nginx_json" or (fmt == "auto" and "request" not in j and "ip" in j):
            return parse_nginx_json(j)
        return parse_caddy(j)
    if fmt in ("auto", "nginx_combined"):
        return parse_combined(line)
    return None
