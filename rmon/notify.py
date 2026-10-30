"""Notifications: telegram, ntfy (push without any account), email, webhook, and a phone CALL (twilio / asterisk / your own command).
Levels: info < important < alert. Only `alert` can ring a phone. Everything is optional; with no channel configured, alerts go to the journal."""
import base64
import json
import smtplib
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage

LEVELS = {"info": 0, "important": 1, "alert": 2}


def _post(url, data=None, headers=None, timeout=15, as_json=False, auth=None):
    body = None
    h = dict(headers or {})
    if as_json:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    elif data is not None:
        body = data if isinstance(data, bytes) else urllib.parse.urlencode(data).encode()
    if auth:
        h["Authorization"] = "Basic " + base64.b64encode(("%s:%s" % auth).encode()).decode()
    req = urllib.request.Request(url, data=body, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read(2000)


class Notifier:
    def __init__(self, cfg, secrets, log=None, clock=time.time):
        self.cfg, self.sec, self.clock = cfg, secrets, clock
        self.log = log or (lambda m: print(m, file=sys.stderr, flush=True))
        self.last = {}

    @property
    def bot(self):
        return self.cfg["branding"].get("bot_name") or "RMON"

    def send(self, level, title, text, key=None, min_gap=60):
        """Sends to every configured channel whose min level is reached. `key` throttles repeats (min_gap seconds)."""
        n = self.cfg["notify"]
        if LEVELS.get(level, 0) < LEVELS.get(n.get("min_level", "important"), 1):
            return []
        now = self.clock()
        if key and now - self.last.get(key, 0) < min_gap:
            return []
        self.last[key or title] = now
        sent = []
        full = "[%s] %s" % (self.bot, title)
        for ch in n.get("channels", []):
            try:
                getattr(self, "_" + ch)(level, full, text)
                sent.append(ch)
            except Exception as e:   # one broken channel must never stop the others
                self.log("notify %s failed: %s" % (ch, type(e).__name__))
        if not sent:
            self.log("%s: %s" % (full, text))
        return sent

    # ---- channels -----------------------------------------------------------------------------------------------------
    def _telegram(self, level, title, text):
        tok = self.sec.get("telegram_token", "")
        chat = self.cfg["notify"]["telegram"].get("chat_id", "")
        if tok and chat:
            _post("https://api.telegram.org/bot%s/sendMessage" % tok, {"chat_id": chat, "text": "%s\n%s" % (title, text)}, as_json=True)

    def _ntfy(self, level, title, text):
        c = self.cfg["notify"]["ntfy"]
        if not c.get("topic"):
            return
        h = {"Title": title.encode("utf-8", "replace").decode("latin-1", "replace"), "Priority": {"info": "2", "important": "3", "alert": "5"}[level],
             "Tags": {"info": "information_source", "important": "warning", "alert": "rotating_light"}[level]}
        if self.sec.get("ntfy_token"):
            h["Authorization"] = "Bearer " + self.sec["ntfy_token"]
        _post("%s/%s" % (c.get("server", "https://ntfy.sh").rstrip("/"), c["topic"]), text.encode("utf-8"), h)

    def _email(self, level, title, text):
        c = self.cfg["notify"]["email"]
        if not (c.get("smtp_host") and c.get("to")):
            return
        m = EmailMessage()
        m["Subject"], m["From"], m["To"] = title, c.get("from") or c.get("user") or "rmon@localhost", c["to"]
        m.set_content(text)
        with smtplib.SMTP(c["smtp_host"], int(c.get("smtp_port", 587)), timeout=20) as s:
            if c.get("starttls", True):
                s.starttls()
            if c.get("user") and self.sec.get("smtp_password"):
                s.login(c["user"], self.sec["smtp_password"])
            s.send_message(m)

    def _webhook(self, level, title, text):
        url = self.cfg["notify"]["webhook"].get("url")
        if url:
            _post(url, {"level": level, "title": title, "text": text, "bot": self.bot, "time": int(self.clock())}, as_json=True)

    def _call(self, level, title, text):
        c = self.cfg["notify"]["call"]
        if level != "alert" or c.get("driver", "none") == "none" or not c.get("to"):
            return
        if c.get("only_during_quiet_hours"):
            a, b = c.get("quiet_hours", [22, 8])
            h = time.localtime(self.clock()).tm_hour
            if not (h >= a or h < b):   # outside quiet hours a message is enough
                return
        say = "%s. %s" % (title, text)
        getattr(self, "_call_" + c["driver"])(c, say[:300])

    def _call_twilio(self, c, say):
        t = c["twilio"]
        sid, tok = t.get("account_sid"), self.sec.get("twilio_token")
        if not (sid and tok and t.get("from")):
            return
        twiml = "<Response><Say language=\"%s\">%s</Say></Response>" % ("fr-FR" if self.cfg["branding"]["lang"] == "fr" else "en-US", say.replace("&", " and ").replace("<", " "))
        _post("https://api.twilio.com/2010-04-01/Accounts/%s/Calls.json" % sid, {"To": c["to"], "From": t["from"], "Twiml": twiml}, auth=(sid, tok))

    def _call_asterisk(self, c, say):
        """Needs a dialplan context (see docs/VOIP.md) that plays ${RMON_MESSAGE} (TTS or a recorded prompt). Uses the local `asterisk -rx` CLI."""
        a = c["asterisk"]
        if not a.get("endpoint"):
            return
        ep = c["to"] if "/" in c["to"] else "%s/%s" % (a["endpoint"], c["to"])
        safe = "".join(ch for ch in say if ch.isalnum() or ch in " .,-")[:200]
        subprocess.run(["asterisk", "-rx", "dialplan set global RMON_MESSAGE %s" % safe], capture_output=True, timeout=20)
        subprocess.run(["asterisk", "-rx", "channel originate %s extension s@%s" % (ep, a.get("context", "rmon-alert"))], capture_output=True, timeout=20)

    def _call_command(self, c, say):
        """Your own caller. The command is run WITHOUT a shell; {message} and {to} are substituted as single arguments."""
        import shlex
        if not c.get("command"):
            return
        args = [a.replace("{message}", say).replace("{to}", c["to"]) for a in shlex.split(c["command"])]
        subprocess.run(args, capture_output=True, timeout=60)
