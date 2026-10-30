"""The guard daemon: follows the access log, feeds the engine, keeps the web-server configuration in sync with the store, sends notifications."""
import glob
import os
import sys
import threading
import time

from . import backends, engine as engine_mod, logparse, notify as notify_mod, store as store_mod

CANDIDATES = ("/var/log/caddy/rmon-access.log", "/var/log/nginx/rmon-access.log", "/var/log/caddy/access.log", "/var/log/nginx/access.log")


def find_log(cfg):
    if cfg["web"].get("log_path"):
        return cfg["web"]["log_path"]
    for p in CANDIDATES:
        if os.path.exists(p):
            return p
    return ""


def follow(path, stop=lambda: False, poll=0.25):
    """Yields new lines like `tail -F`: survives rotation (inode change / truncation), starts at the end of the file."""
    f, ino = None, None
    while not stop():
        try:
            st = os.stat(path)
            if f is None or st.st_ino != ino or st.st_size < f.tell():
                if f:
                    f.close()
                f = open(path, encoding="utf-8", errors="replace")
                ino = st.st_ino
                if ino is not None and not getattr(follow, "_first_done_" + path, False):
                    f.seek(0, os.SEEK_END)   # first open: only new traffic
                    setattr(follow, "_first_done_" + path, True)
        except OSError:
            f = None
            time.sleep(1)
            continue
        line = f.readline()
        if line:
            yield line
        else:
            time.sleep(poll)


class Guard:
    def __init__(self, cfg, secrets, store=None, backend=None, notifier=None):
        self.cfg = cfg
        self.store = store or store_mod.Store(cfg["state_dir"])
        self.engine = engine_mod.Engine(cfg, self.store)
        self.backend = backend or backends.get(cfg)
        self.notifier = notifier or notify_mod.Notifier(cfg, secrets)
        self._sig = None
        self._lock = threading.Lock()

    def sync(self, force=False):
        """Re-applies the web-server state when the store changed (new ban, expiry, unban by the challenge server)."""
        with self._lock:
            self.store.expire()
            sig = self.store.signature()
            if force or sig != self._sig:
                ok = self.backend.apply(self.store.snapshot())
                self._sig = sig if ok else None   # retry next round if the server refused the configuration
                return ok
        return True

    def handle_line(self, line):
        req = logparse.parse_line(line, self.cfg["web"].get("log_format", "auto"))
        if not req:
            return []
        events = self.engine.feed(req)
        for e in events:
            self._announce(e)
        if events:
            self.sync()
        return events

    def _announce(self, e):
        t = e["type"]
        if t == "ban":
            self.notifier.send("important", "Address banned", "%s banned for: %s" % (e["ip"], e["kind"]), key="ban:" + e["ip"])
        elif t == "fpban":
            self.notifier.send("important", "Attack tool blocked", e["kind"], key="fp:" + e.get("fp", ""))
        # challenges are silent: a human passes by himself, only ignored challenges become bans (announced above)

    def run(self, stop=lambda: False):
        path = find_log(self.cfg)
        if not path:
            print("rmon: no access log found; set web.log_path in /etc/rmon/config.json", file=sys.stderr, flush=True)
        self.sync(force=True)

        def ticker():   # expiry, and unbans / passes written by the challenge server, even when there is no traffic
            while not stop():
                time.sleep(2)
                self.sync()
        threading.Thread(target=ticker, daemon=True).start()
        print("rmon guard started (%s, %s)" % (self.backend.name, path or "no log"), file=sys.stderr, flush=True)
        if not path:
            while not stop():
                time.sleep(5)
            return
        for line in follow(path, stop):
            self.handle_line(line)
