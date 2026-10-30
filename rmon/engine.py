"""The guard engine: feed it parsed requests, it decides ban / challenge / fingerprint-ban and records them in the Store.

Two tiers keep false positives at zero for humans:
  * CERTAIN detections (trap files, PHP in uploads, injections, scanners) -> ban immediately.
  * AMBIGUOUS detections (many 404s, failed logins, a high risk score) -> captcha CHALLENGE, never a ban. A human passes in ~1 s;
    a bot that ignores it (40 requests) or never solves it (3 challenges in 24 h) is banned.
"""
import collections
import hashlib
import socket
import time

from . import netutil, rules

CH_IGNORE_HITS = 40
RISK_HALF_LIFE = 300.0
FP_BAD_MIN = 3


class Engine:
    def __init__(self, cfg, store, clock=time.time):
        self.cfg, self.store, self.clock = cfg, store, clock
        g = cfg["guard"]
        self.never = netutil.parse_nets(g.get("never_ban", []))
        self.login_paths = tuple(p.lower() for p in g.get("login_paths", []))
        self.s = {"login": collections.defaultdict(collections.deque), "n404": collections.defaultdict(collections.deque),
                  "paths": collections.defaultdict(collections.deque), "risk": {}, "hits": collections.defaultdict(collections.deque), "recent": {},
                  "fp": {}, "fp_sent": {}, "crawler": {}}
        self._lists_t = 0
        self._banned, self._chall, self._pass = set(), set(), set()

    # -- helpers ----------------------------------------------------------------------------------------------------
    def _refresh(self, now):
        if now - self._lists_t > 5:
            self._lists_t = now
            self._banned, self._chall = set(self.store.active("bans", now)), set(self.store.active("challenges", now))
            self._pass = set(self.store.active("passes", now))
            self._trusted = set(self.store.load("trusted", []) if isinstance(self.store.load("trusted", []), list) else [])

    def _trusted_ip(self, ip):
        return netutil.in_nets(ip, self.never) or any(netutil.covers(t, ip) for t in getattr(self, "_trusted", ()))

    def _good_crawler(self, ip, ua):
        if not rules.GOOD_UA.search(ua or ""):
            return False
        if ip in self.s["crawler"]:
            return self.s["crawler"][ip]
        ok = False
        try:   # genuine crawlers: reverse DNS then forward DNS must agree (anyone can claim to be Googlebot in a User-Agent)
            name = socket.gethostbyaddr(ip)[0]
            ok = name.endswith((".googlebot.com", ".google.com", ".search.msn.com", ".crawl.yahoo.net", ".applebot.apple.com")) and ip in {x[4][0] for x in socket.getaddrinfo(name, None)}
        except Exception:
            ok = False
        self.s["crawler"][ip] = ok
        return ok

    @staticmethod
    def fp_hash(req):
        parts = req.fp_parts()
        return hashlib.sha1("\x1f".join(parts[k] for k in ("ua", "al", "ae", "sua", "sup")).encode("utf-8", "replace")).hexdigest()[:12], parts

    def _fp_note(self, req, how):
        if not (self.cfg["guard"].get("fingerprint") and req.has_fp):
            return None
        h, parts = self.fp_hash(req)
        rec = self.s["fp"].get(h)
        if rec is None:
            if len(self.s["fp"]) >= 2000:
                for k in sorted(self.s["fp"], key=lambda k: self.s["fp"][k]["t"])[:200]:
                    del self.s["fp"][k]
            rec = self.s["fp"][h] = {"c": parts, "bad": set(), "ok": set(), "trusted": False, "t": 0}
        rec["t"] = self.clock()
        if how == "trusted":
            rec["trusted"] = True
        elif how in ("bad", "ok") and len(rec[how]) < 50:
            rec[how].add(req.ip)
        return h

    def _fp_decide(self, h, now):
        rec = self.s["fp"].get(h)
        if not rec or rec["trusted"] or len(rec["bad"]) < FP_BAD_MIN or len(rec["ok"] - rec["bad"]) > 1 or now - self.s["fp_sent"].get(h, 0) < 600:
            return None
        ua = rec["c"]["ua"]
        if len(ua) < 8 or rules.GOOD_UA.search(ua) or len(self.store.active("fpbans", now)) >= 20:
            return None
        self.s["fp_sent"][h] = now
        self.store.add_fp_ban(h, rec["c"], "same tool behind %d banned addresses" % len(rec["bad"]), now=now)
        return {"type": "fpban", "kind": "fingerprint of an attack tool (%d banned addresses)" % len(rec["bad"]), "fp": h, "ip": ""}

    def ua_weight(self, req):
        an = rules.ua_anomaly(req.ua, req.al, req.sua) if req.has_fp or req.ua else 0.0
        if self.cfg["guard"].get("fingerprint") and req.has_fp:
            rec = self.s["fp"].get(self.fp_hash(req)[0])
            if rec and rec["bad"] and not (rec["ok"] - rec["bad"]):
                an += 0.5
        return an

    # -- detection --------------------------------------------------------------------------------------------------
    def classify(self, req, now):
        """Returns (kind, hard) or (None, False)."""
        g = self.cfg["guard"]
        path = req.path.lower()
        if rules.path_trap(req.path, g.get("extra_trap_paths", []), g.get("extra_trap_exact", []), g.get("allow_paths", [])):
            return "sensitive-file probe", True
        if rules.PHP_UPLOADS.search(path):
            return "php requested in uploads (trap)", True
        if rules.INJECTION.search(req.query) or rules.INJECTION.search(path) or rules.SCANNER_UA.search(req.ua):
            return "injection / scanner", True
        ip = req.ip
        if req.method == "POST" and path.endswith(self.login_paths):
            if req.status in (302, 303):
                return None, False
            dq = self.s["login"][ip]
            dq.append(now)
            while dq and now - dq[0] > 60:
                dq.popleft()
            if len(dq) >= 6:
                return "login brute force (6 attempts in 1 min)", False
        elif req.status == 404:
            dq = self.s["n404"][ip]
            dq.append(now)
            while dq and now - dq[0] > 30:
                dq.popleft()
            if len(dq) >= 20:
                return "scan (20 missing pages in 30 s)", False
        w = 3.0 if req.status in (403, 406) else (1.2 if req.method == "POST" and path.endswith(self.login_paths) else (0.5 if req.status == 404 else 0.0))
        if w and not path.startswith("/__rmon/"):
            prev = self.s["risk"].get(ip)
            val = (prev[0] * 0.5 ** ((now - prev[1]) / RISK_HALF_LIFE) if prev else 0.0) + w * (1.0 + self.ua_weight(req))
            self.s["risk"][ip] = (val, now)
            ps = self.s["paths"][ip]
            ps.append((now, path))
            while ps and now - ps[0][0] > 300:
                ps.popleft()
            if val >= g.get("risk_challenge", 8.0) and len({p for _, p in ps}) >= 5:
                return "risk score %d" % val, False
        return None, False

    # -- main entry -------------------------------------------------------------------------------------------------
    def feed(self, req, now=None):
        """Returns a list of event dicts {type: ban|challenge|fpban, ip, kind} (empty for ordinary traffic)."""
        now = now or self.clock()
        self._refresh(now)
        ip = req.ip
        if not netutil.is_public(ip) or netutil.in_cloudflare(ip):
            return []
        trusted = self._trusted_ip(ip)
        tgt = netutil.target(ip)
        if trusted:
            self._fp_note(req, "trusted")
            return []
        if tgt in self._banned:
            self._fp_note(req, "bad")
            return []
        self._fp_note(req, "ok" if req.status in (200, 304) else None)
        if tgt in self._chall:   # under challenge: only the verification page is served; insisting means a bot
            if not req.path.startswith("/__rmon/"):
                dq = self.s["hits"][ip]
                dq.append(now)
                while dq and now - dq[0] > 300:
                    dq.popleft()
                if len(dq) >= CH_IGNORE_HITS:
                    return self._ban(req, "challenge ignored (%d requests in 5 min)" % len(dq), now, fp=True)
            return []
        kind, hard = self.classify(req, now)
        if not kind:
            return []
        if self._good_crawler(ip, req.ua):
            return []
        if now - self.s["recent"].get(ip, 0) < 60:
            return []
        self.s["recent"][ip] = now
        if hard:
            return self._ban(req, kind, now, fp=True)
        if tgt in self._pass:   # solved the captcha less than pass_hours ago: a human, not challenged again for soft signals
            return []
        if self.store.challenge(ip, self.cfg, kind, now):
            self._lists_t = 0
            return [{"type": "challenge", "ip": ip, "kind": kind}]
        return self._ban(req, "challenge never solved (3 detections in 24 h)", now, fp=False)

    def _ban(self, req, kind, now, fp):
        if len(self.store.active("bans", now)) >= self.cfg["guard"].get("max_active_bans", 300):
            return []
        self.store.ban(req.ip, self.cfg, kind, now)
        self._lists_t = 0
        ev = [{"type": "ban", "ip": req.ip, "kind": kind}]
        if fp:
            h = self._fp_note(req, "bad")
            if h:
                e = self._fp_decide(h, now)
                if e:
                    ev.append(e)
        return ev
