"""Persistent state: bans, challenges, passes, fingerprint bans, history (recidivism). Plain JSON files, atomic writes."""
import json
import os
import threading
import time

from . import netutil

try:
    import fcntl
except ImportError:   # Windows (tests only)
    fcntl = None


class _Lock:
    """Re-entrant lock shared by threads AND processes (the guard daemon and the challenge server both write the state files)."""

    def __init__(self, path):
        self.path, self.t, self.depth, self.fh = path, threading.RLock(), 0, None

    def __enter__(self):
        self.t.acquire()
        if self.depth == 0 and fcntl:
            self.fh = open(self.path, "a")
            fcntl.flock(self.fh, fcntl.LOCK_EX)
        self.depth += 1

    def __exit__(self, *a):
        self.depth -= 1
        if self.depth == 0 and self.fh:
            fcntl.flock(self.fh, fcntl.LOCK_UN)
            self.fh.close()
            self.fh = None
        self.t.release()


class Store:
    def __init__(self, state_dir):
        self.dir = state_dir
        os.makedirs(self.dir, mode=0o750, exist_ok=True)
        self.lock = _Lock(os.path.join(self.dir, ".lock"))

    def signature(self):
        """Cheap change detector: the daemon re-applies the web-server configuration when it changes (e.g. the challenge server unbanned someone)."""
        out = []
        for n in ("bans", "challenges", "fpbans"):
            try:
                st = os.stat(self._p(n))
                out.append((st.st_mtime_ns, st.st_size))
            except OSError:
                out.append(None)
        return tuple(out)

    def _p(self, name):
        return os.path.join(self.dir, name + ".json")

    def load(self, name, default=None):
        try:
            with open(self._p(name), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {} if default is None else default

    def save(self, name, obj):
        tmp = self._p(name) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f)
        os.replace(tmp, self._p(name))

    # ---- bans -------------------------------------------------------------------------------------------------
    def active(self, name, now=None):
        now = now or time.time()
        return {k: v for k, v in self.load(name).items() if v.get("until", 0) > now}

    def ban_ttl(self, tgt, cfg, now=None):
        """First ban: ban_hours. Repeat offenders: 7 days, then 30 days (configurable)."""
        g = cfg["guard"]
        n = len((self.load("history").get(tgt) or {}).get("bans", []))
        days = g.get("repeat_ban_days", [7, 30])
        if n == 0:
            return int(g["ban_hours"] * 3600)
        return int(days[0 if n < 3 else 1] * 86400)

    def ban(self, ip, cfg, why, now=None, ttl=None):
        now = int(now or time.time())
        tgt = netutil.target(ip)
        with self.lock:
            ttl = ttl or self.ban_ttl(tgt, cfg)
            bans = self.load("bans")
            bans[tgt] = {"since": now, "until": now + ttl, "why": str(why)[:80], "ip": str(ip)}
            self.save("bans", bans)
            ch = self.load("challenges")
            if ch.pop(tgt, None) is not None:
                self.save("challenges", ch)
            h = self.load("history")
            e = h.setdefault(tgt, {"bans": []})
            e["bans"] = (e["bans"] + [{"since": now, "until": now + ttl}])[-20:]
            self.save("history", h)
        return tgt

    def unban(self, who):
        with self.lock:
            bans = self.load("bans")
            tgt = netutil.target(who) if who != "all" else None
            n = len(bans)
            bans = {} if who == "all" else {k: v for k, v in bans.items() if k != tgt}
            self.save("bans", bans)
            ch = self.load("challenges")
            ch = {} if who == "all" else {k: v for k, v in ch.items() if k != tgt}
            self.save("challenges", ch)
        return n - len(bans)

    def is_banned(self, ip, now=None):
        return netutil.target(ip) in self.active("bans", now)

    # ---- challenges (ambiguous detections) ----------------------------------------------------------------------
    def challenge(self, ip, cfg, kind, now=None):
        """Put an address under captcha challenge. Returns False when it already had 2 unsolved challenges in 24 h
        (a patient bot: the caller should ban instead)."""
        now = int(now or time.time())
        tgt = netutil.target(ip)
        with self.lock:
            h = self.load("ch_hist")
            recent = [x for x in h.get(tgt, []) if now - x < 86400]
            if len(recent) >= 2:
                return False
            h[tgt] = recent + [now]
            self.save("ch_hist", {k: v for k, v in h.items() if v})
            ch = self.load("challenges")
            ch[tgt] = {"since": now, "until": now + int(cfg["challenge"]["challenge_minutes"] * 60), "kind": str(kind)[:80], "ip": str(ip)}
            self.save("challenges", ch)
        return True

    def pass_challenge(self, ip, cfg, now=None):
        now = int(now or time.time())
        tgt = netutil.target(ip)
        with self.lock:
            ch = self.load("challenges")
            ch.pop(tgt, None)
            self.save("challenges", ch)
            ps = self.load("passes")
            ps[tgt] = {"until": now + int(cfg["challenge"]["pass_hours"] * 3600)}
            self.save("passes", ps)
            h = self.load("ch_hist")
            if h.pop(tgt, None) is not None:   # a human: the unsolved-challenge history is erased
                self.save("ch_hist", h)

    # ---- fingerprints -----------------------------------------------------------------------------------------------
    def add_fp_ban(self, h, comps, why, hours=24, now=None):
        now = int(now or time.time())
        with self.lock:
            fb = self.load("fpbans")
            fb[h] = {"since": now, "until": now + hours * 3600, "comps": comps, "why": str(why)[:80]}
            self.save("fpbans", fb)

    # ---- housekeeping -------------------------------------------------------------------------------------------------
    def expire(self, now=None):
        """Drops expired entries; returns True when something changed (backends must then be re-applied)."""
        now = now or time.time()
        changed = False
        with self.lock:
            for name in ("bans", "challenges", "passes", "fpbans"):
                cur = self.load(name)
                keep = {k: v for k, v in cur.items() if v.get("until", 0) > now}
                if len(keep) != len(cur):
                    self.save(name, keep)
                    changed = True
        return changed

    def snapshot(self, now=None):
        return {"bans": sorted(self.active("bans", now)), "challenges": sorted(self.active("challenges", now)),
                "fpbans": [v["comps"] for v in self.active("fpbans", now).values()]}
