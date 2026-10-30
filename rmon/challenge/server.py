"""The challenge server (listens on 127.0.0.1 only; your web server proxies /__rmon/* to it and rewrites banned / challenged visitors to /__rmon/p/<kind>).
It runs as an unprivileged user: it only edits the state files; the guard daemon (root) re-applies the web-server configuration when they change.

Decision (see rules.bot_prob): probability that the visitor is a robot from the captcha score, the browser environment, the behaviour and the history.
  p < lo -> unblocked / verified    lo <= p < hi -> one confirmation step (a click, trusted-event checked)    p >= hi -> stays blocked
Unbanning a real ban is stricter than lifting a simple challenge; serious detections (injection, php in uploads) are never lifted automatically."""
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import netutil, rules
from . import pages, providers

SERIOUS = ("php requested", "injection")
MSG = {
    "en": {"not_blocked": "Your address is not blocked. If this page keeps showing, clear your browser cache or try again in a moment.", "serious": "This block cannot be lifted automatically.",
           "already": "You were already unblocked in the last 24 hours: the block stays active.", "busy": "Too many unblocks right now, please try later.", "again": "Verification already done several times today, try later.",
           "step2": "One last step: click the button to confirm.", "no": "We could not confirm that you are human. Try another browser, without VPN or private mode.",
           "bad": "Verification refused, please retry.", "limit": "Too many attempts: retry in a few minutes."},
    "fr": {"not_blocked": "Votre adresse n'est pas bloquée. Si cette page s'affiche encore, videz le cache du navigateur ou réessayez dans un instant.", "serious": "Ce blocage ne peut pas être levé automatiquement.",
           "already": "Vous avez déjà été débloqué ces dernières 24 heures : le blocage reste actif.", "busy": "Trop de déblocages en ce moment, réessayez plus tard.", "again": "Vérification déjà effectuée plusieurs fois aujourd'hui, réessayez plus tard.",
           "step2": "Dernière étape : cliquez sur le bouton pour confirmer.", "no": "Nous n'avons pas pu confirmer que vous êtes humain. Essayez un autre navigateur, sans VPN ni mode privé.",
           "bad": "Vérification refusée, réessayez.", "limit": "Trop d'essais : réessayez dans quelques minutes."},
}
FEATS = {"wd": (0, 1), "hl": (0, 1), "sw": (0, 1), "ut": (0, 1000), "mc": (0, 1e5), "tc": (0, 1e5), "kc": (0, 1e5), "sc": (0, 1e5), "clk": (0, 1000), "mmn": (0, 1000), "mms": (0, 1), "mmv": (0, 10), "dt": (0, 6e5)}


def clean_features(f):
    out = {}
    if isinstance(f, dict):
        for k, (lo, hi) in FEATS.items():
            v = f.get(k)
            v = int(v) if isinstance(v, bool) else v
            if isinstance(v, (int, float)) and v == v:
                out[k] = round(min(max(float(v), lo), hi), 3)
    return out


class Decider:
    """All the policy, without any HTTP: easy to test."""

    def __init__(self, cfg, store, clock=time.time):
        self.cfg, self.store, self.clock = cfg, store, clock
        self.m = MSG.get(cfg["branding"].get("lang", "en"), MSG["en"])

    def decide(self, ip, feat, score, step):
        """Returns {"ok": bool, "msg": str, "step2": bool, "p": float|None, "flags": [...]}."""
        now, st, cfg = self.clock(), self.store, self.cfg
        tgt = netutil.target(ip)
        bans, chall = st.active("bans", now), st.active("challenges", now)
        banned, challenged = tgt in bans, tgt in chall
        if not banned and not challenged:
            return {"ok": False, "msg": self.m["not_blocked"], "step2": False, "p": None, "flags": []}
        un = st.load("unlock")
        if banned:
            if str(bans[tgt].get("why", "")).startswith(SERIOUS):
                return {"ok": False, "msg": self.m["serious"], "step2": False, "p": None, "flags": []}
            if now - un.get(tgt, 0) < 86400:
                return {"ok": False, "msg": self.m["already"], "step2": False, "p": None, "flags": []}
            if len([1 for v in un.values() if isinstance(v, (int, float)) and now - v < 3600]) >= 10:
                return {"ok": False, "msg": self.m["busy"], "step2": False, "p": None, "flags": []}
        else:
            recent = [x for x in un.get("p:" + tgt, []) if now - x < 86400]
            if len(recent) >= 2:
                return {"ok": False, "msg": self.m["again"], "step2": False, "p": None, "flags": []}
        prior = max(0, len([x for x in st.load("ch_hist").get(tgt, []) if now - x < 86400]) - 1)
        p, flags = rules.bot_prob(feat, score, step, prior)
        lo, hi = (0.25, 0.5) if banned else (0.35, 0.65)
        s2 = [x for x in un.get("s2:" + tgt, []) if now - x < 3600]
        res = {"ok": False, "msg": self.m["no"], "step2": False, "p": round(p, 2), "flags": flags}
        if p >= hi or (p >= lo and (step >= 2 or len(s2) >= 2)):
            return res
        if p >= lo:
            with st.lock:
                un = st.load("unlock")
                un["s2:" + tgt] = s2 + [now]
                st.save("unlock", un)
            res.update(msg=self.m["step2"], step2=True)
            return res
        with st.lock:
            un = st.load("unlock")
            if banned:
                st.unban(ip)
                un[tgt] = now
            else:
                st.pass_challenge(ip, cfg, now)
                un["p:" + tgt] = [x for x in un.get("p:" + tgt, []) if now - x < 86400] + [now]
            st.save("unlock", {k: v for k, v in un.items() if not isinstance(v, (int, float)) or now - v < 7 * 86400})
        res.update(ok=True, msg="ok")
        return res

    def strike(self, ip):
        """A rejected / replayed token. 5 in an hour from a blocked address = not a human: extend the ban to 7 days (a low SCORE is never punished)."""
        now, st = self.clock(), self.store
        tgt = netutil.target(ip)
        with st.lock:
            un = st.load("unlock")
            fl = [x for x in un.get("f:" + tgt, []) if now - x < 3600] + [now]
            un["f:" + tgt] = fl
            st.save("unlock", un)
            if len(fl) >= 5 and (tgt in st.active("bans", now) or tgt in st.active("challenges", now)):
                st.ban(ip, self.cfg, "captcha tampering (5 rejected tokens in 1 h)", now, ttl=7 * 86400)
                un.pop("f:" + tgt, None)
                st.save("unlock", un)


class Handler(BaseHTTPRequestHandler):
    server_version = "rmon"
    timeout = 10
    dec = None   # set by serve()
    cfg = None
    sec = None
    tries = {}
    glock = threading.Lock()

    def log_message(self, *a):
        pass

    def _client_ip(self):
        a = netutil.parse_ip(self.headers.get("X-Rmon-Ip", ""))
        return str(a) if a is not None and a.is_global else None

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text") else ""))
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path.split("?")[0]
        m = re.fullmatch(r"/__rmon/p/(ban|challenge)", p)
        if m:
            return self._send(403, pages.render(m.group(1), self.cfg, self.cfg["challenge"].get("site_key", "")), "text/html")
        if p == "/__rmon/health":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not_found"})

    def _limited(self, ip):
        now = time.time()
        with self.glock:
            t = [x for x in self.tries.get(ip, []) if now - x < 600]
            g = [x for x in self.tries.get("*", []) if now - x < 600]
            lim = len(t) >= 5 or len(g) >= 60
            if not lim:
                t.append(now)
                g.append(now)
            self.tries[ip], self.tries["*"] = t, g
            if len(self.tries) > 5000:
                for k in [k for k, v in self.tries.items() if not v or now - v[-1] > 600]:
                    del self.tries[k]
        return lim

    def do_POST(self):
        if self.path.split("?")[0] != "/__rmon/unlock":
            return self._send(404, {"error": "not_found"})
        ip, m = self._client_ip(), self.dec.m
        if not ip:
            return self._send(400, {"ok": False, "msg": m["bad"]})
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n)) if 0 < n <= 6000 else {}
            token, feat, step = body.get("token"), clean_features(body.get("f")), (2 if body.get("step") == 2 else 1)
        except (ValueError, TypeError, AttributeError):
            return self._send(400, {"ok": False, "msg": m["bad"]})
        if not isinstance(token, str) or not 1 <= len(token) <= 4096:
            return self._send(400, {"ok": False, "msg": m["bad"]})
        if self._limited(ip):
            return self._send(429, {"ok": False, "msg": m["limit"]})
        prov = self.cfg["challenge"].get("provider", "none")
        try:
            v = providers.verify(prov, self.sec.get("captcha_secret", ""), token, ip)
        except Exception:
            return self._send(502, {"ok": False, "msg": self.cfg_unavailable()})
        host = re.sub(r":\d+$", "", self.headers.get("Host", "").lower())
        good = v["ok"] and (prov == "none" or not v["hostname"] or v["hostname"] == host) and (v["action"] in (None, "unlock"))
        if not good:
            if set(v["codes"]) & {"invalid-input-response", "timeout-or-duplicate", "missing-input-response"} or (v["ok"] and v["hostname"] and v["hostname"] != host):
                self.dec.strike(ip)
            return self._send(403, {"ok": False, "msg": m["bad"]})
        res = self.dec.decide(ip, feat, v["score"] if v["score"] is not None else (0.8 if prov != "none" else None), step)
        print(time.strftime("%H:%M:%S"), ip, "ok" if res["ok"] else "no", "p=%s" % res["p"], ",".join(res["flags"]), flush=True)
        self._send(200, {k: res[k] for k in ("ok", "msg", "step2")})

    def cfg_unavailable(self):
        return pages.TEXT.get(self.cfg["branding"].get("lang", "en"), pages.TEXT["en"])["unavailable"]


def serve(cfg, store, secrets, host="127.0.0.1"):
    Handler.dec, Handler.cfg, Handler.sec = Decider(cfg, store), cfg, secrets
    srv = ThreadingHTTPServer((host, int(cfg["challenge"]["port"])), Handler)
    print("rmon challenge server on %s:%s (%s)" % (host, cfg["challenge"]["port"], cfg["challenge"].get("provider")), file=sys.stderr, flush=True)
    srv.serve_forever()
