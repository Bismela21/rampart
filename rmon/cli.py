"""Command line: rmon setup | guard | challenge | canary | bans | unban | trust | status | doctor | notify-test | explain"""
import argparse
import json
import os
import shutil
import sys
import time

from . import __version__, backends, config, netutil, notify as notify_mod
from . import store as store_mod

CHANNELS = ("telegram", "ntfy", "email", "webhook", "call")
CAPTCHAS = {"1": "none", "2": "recaptcha_v3", "3": "turnstile", "4": "hcaptcha"}
AIS = {"1": "none", "2": "mistral", "3": "deepseek", "4": "openai", "5": "ollama", "6": "custom"}


class IO:
    """Wizard I/O. `answers` (dict) makes it fully non-interactive: used by tests and unattended installs."""

    def __init__(self, answers=None):
        self.answers = answers

    def ask(self, key, prompt, default="", secret=False):
        if self.answers is not None:
            return str(self.answers.get(key, default))
        shown = " [%s]" % default if default and not secret else ""
        try:
            if secret:
                import getpass
                v = getpass.getpass("%s (input hidden): " % prompt)
            else:
                v = input("%s%s: " % (prompt, shown))
        except EOFError:
            v = ""
        return v.strip() or default

    def yes(self, key, prompt, default=False):
        v = self.ask(key, prompt + (" [Y/n]" if default else " [y/N]"), "y" if default else "n").lower()
        return v[:1] in ("y", "o", "1", "t")

    def say(self, text=""):
        if self.answers is None:
            print(text)


def _state_dir_ready(cfg):
    os.makedirs(cfg["state_dir"], mode=0o750, exist_ok=True)


def setup(io, cfg=None, sec=None, write=True):
    """Asks a handful of questions (everything has a sensible default or is detected), writes the config, secrets and the web-server snippets."""
    cfg = cfg or config.load()
    sec = sec if sec is not None else config.load_secrets()
    io.say("RMON %s setup - every question can be skipped with Enter; nothing leaves this machine except what you enable below.\n" % __version__)

    b = cfg["branding"]
    b["bot_name"] = io.ask("bot_name", "1/8 Name of your bot (shown in alerts and on the block page)", b["bot_name"])
    b["lang"] = io.ask("lang", "    Language (en/fr)", b["lang"])
    b["lang"] = b["lang"] if b["lang"] in ("en", "fr") else "en"
    b["logo"] = io.ask("logo", "    Path to your logo (PNG/SVG, optional)", b["logo"])

    det = backends.detect_server()
    cfg["web"]["server"] = io.ask("server", "2/8 Web server (caddy / nginx / none) - detected: %s" % det, det if cfg["web"]["server"] == "auto" else cfg["web"]["server"])
    cfg["web"]["log_path"] = io.ask("log_path", "    Access log path (empty = autodetect)", cfg["web"]["log_path"])

    io.say("\n3/8 Captcha for people blocked by mistake: 1) none  2) Google reCAPTCHA v3  3) Cloudflare Turnstile  4) hCaptcha")
    ch = cfg["challenge"]
    ch["provider"] = CAPTCHAS.get(io.ask("captcha", "    Choice", {v: k for k, v in CAPTCHAS.items()}[ch["provider"]]), "none")
    if ch["provider"] != "none":
        ch["site_key"] = io.ask("site_key", "    Site key (public)", ch["site_key"])
        s = io.ask("captcha_secret", "    Secret key (stored in secrets.json, mode 600)", "", secret=True)
        if s:
            sec["captcha_secret"] = s

    io.say("\n4/8 Alerts. Channels: telegram, ntfy (free push), email, webhook, call (phone ring)")
    n = cfg["notify"]
    chosen = [c.strip() for c in io.ask("channels", "    Channels, comma separated (empty = none)", ",".join(n["channels"])).split(",") if c.strip() in CHANNELS]
    n["channels"] = chosen
    if "telegram" in chosen:
        n["telegram"]["chat_id"] = io.ask("tg_chat", "    Telegram chat id", n["telegram"]["chat_id"])
        t = io.ask("tg_token", "    Telegram bot token", "", secret=True)
        if t:
            sec["telegram_token"] = t
    if "ntfy" in chosen:
        n["ntfy"]["server"] = io.ask("ntfy_server", "    ntfy server", n["ntfy"]["server"])
        n["ntfy"]["topic"] = io.ask("ntfy_topic", "    ntfy topic (pick a long random name)", n["ntfy"]["topic"] or "rmon-" + os.urandom(6).hex())
    if "email" in chosen:
        e = n["email"]
        e["smtp_host"], e["to"] = io.ask("smtp_host", "    SMTP host", e["smtp_host"]), io.ask("mail_to", "    Send alerts to", e["to"])
        e["user"], e["from"] = io.ask("smtp_user", "    SMTP user", e["user"]), io.ask("mail_from", "    From address", e["from"] or e["user"])
        p = io.ask("smtp_password", "    SMTP password", "", secret=True)
        if p:
            sec["smtp_password"] = p
    if "webhook" in chosen:
        n["webhook"]["url"] = io.ask("webhook_url", "    Webhook URL", n["webhook"]["url"])
    if "call" in chosen:
        c = n["call"]
        io.say("    Phone call for critical alerts: twilio | asterisk (your own SIP/VoIP PBX) | command (your own script)")
        c["driver"] = io.ask("call_driver", "    Driver", c["driver"] if c["driver"] != "none" else "twilio")
        c["to"] = io.ask("call_to", "    Number or extension to call", c["to"])
        c["only_during_quiet_hours"] = io.yes("call_quiet", "    Only ring at night (22h-8h), message otherwise?", c["only_during_quiet_hours"])
        if c["driver"] == "twilio":
            c["twilio"]["account_sid"], c["twilio"]["from"] = io.ask("twilio_sid", "    Twilio account SID", c["twilio"]["account_sid"]), io.ask("twilio_from", "    Twilio number", c["twilio"]["from"])
            t = io.ask("twilio_token", "    Twilio auth token", "", secret=True)
            if t:
                sec["twilio_token"] = t
        elif c["driver"] == "asterisk":
            c["asterisk"]["endpoint"] = io.ask("ast_endpoint", "    Asterisk channel prefix (e.g. PJSIP)", c["asterisk"]["endpoint"] or "PJSIP")
        elif c["driver"] == "command":
            c["command"] = io.ask("call_cmd", "    Command ({message} and {to} are substituted)", c["command"])
    n["min_level"] = "important"

    io.say("\n5/8 Optional AI that explains incidents in plain words (read-only: it can never ban or change anything)")
    io.say("    1) none  2) Mistral  3) DeepSeek  4) OpenAI  5) local Ollama  6) any OpenAI-compatible API")
    cfg["ai"]["provider"] = AIS.get(io.ask("ai", "    Choice", {v: k for k, v in AIS.items()}[cfg["ai"]["provider"]]), "none")
    if cfg["ai"]["provider"] == "custom":
        cfg["ai"]["base_url"] = io.ask("ai_url", "    Base URL (e.g. https://host/v1)", cfg["ai"]["base_url"])
        cfg["ai"]["model"] = io.ask("ai_model", "    Model name", cfg["ai"]["model"])
    if cfg["ai"]["provider"] not in ("none", "ollama"):
        k = io.ask("ai_key", "    API key", "", secret=True)
        if k:
            sec["ai_key"] = k

    cfg["canary"]["enabled"] = io.yes("canary", "\n6/8 Plant canary files (fake secrets: opening one raises an alert)?", cfg["canary"]["enabled"])
    nb = io.ask("never_ban", "7/8 Your own IPs / networks that must NEVER be blocked (comma separated)", ",".join(cfg["guard"]["never_ban"]))
    cfg["guard"]["never_ban"] = [x.strip() for x in nb.split(",") if x.strip()]
    cfg["guard"]["ban_hours"] = int(io.ask("ban_hours", "8/8 First ban duration in hours (repeat offenders get 7 then 30 days)", str(cfg["guard"]["ban_hours"])) or 24)

    if write:
        config.save(cfg)
        config.save_secrets(sec)
        write_snippets(cfg, io)
    return cfg, sec


def write_snippets(cfg, io):
    srv = cfg["web"]["server"]
    if srv == "caddy":
        from .backends import caddy
        p = "/etc/rmon/caddy/rmon.caddy"
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(caddy.snippet(cfg))
        if not os.path.exists("/etc/rmon/caddy/rmon-state.conf"):
            open("/etc/rmon/caddy/rmon-state.conf", "w").write(caddy.CaddyBackend(cfg).render({"bans": [], "challenges": [], "fpbans": []}))
        io.say("\nCaddy: add this line at the TOP of /etc/caddy/Caddyfile, and `import rmon_guard` inside every site you want protected:\n    import /etc/rmon/caddy/rmon.caddy\n"
               "If your sites sit behind Cloudflare, also add in the global options: servers { trusted_proxies static <cloudflare ranges> client_ip_headers Cf-Connecting-Ip X-Forwarded-For }")
    elif srv == "nginx":
        from .backends import nginx
        os.makedirs("/etc/rmon/nginx", exist_ok=True)
        open("/etc/rmon/nginx/rmon-http.conf", "w").write(nginx.http_conf(cfg))
        open("/etc/rmon/nginx/rmon-guard.conf", "w").write(nginx.guard_conf(cfg))
        if not os.path.exists("/etc/rmon/nginx/rmon-state.conf"):
            open("/etc/rmon/nginx/rmon-state.conf", "w").write(nginx.NginxBackend(cfg).render({"bans": [], "challenges": [], "fpbans": []}))
        io.say("\nnginx: inside http { } add `include /etc/rmon/nginx/rmon-http.conf;` and inside each protected server { } add `include /etc/rmon/nginx/rmon-guard.conf;`\n"
               "Behind Cloudflare / a proxy, enable the realip module so $remote_addr is the real visitor.")
    if cfg["notify"]["call"]["driver"] == "asterisk":
        io.say("\nAsterisk: add the dialplan from docs/VOIP.md to extensions.conf (context [%s])." % cfg["notify"]["call"]["asterisk"]["context"])
    io.say("\nThen: sudo systemctl enable --now rmon-guard rmon-challenge%s   and   rmon doctor" % (" rmon-canary" if cfg["canary"]["enabled"] else ""))


def doctor(cfg, sec, out=print):
    ok = True

    def line(good, msg):
        nonlocal ok
        ok = ok and good
        out(("  OK   " if good else "  FAIL ") + msg)
    out("RMON %s" % __version__)
    srv = backends.get(cfg)
    line(True, "web server integration: %s%s" % (srv.name, "" if srv.name != "none" else " (bans are only recorded: see `rmon bans`)"))
    from .guard import find_log
    lp = find_log(cfg)
    line(bool(lp) and os.path.exists(lp), "access log: %s" % (lp or "not found"))
    line(os.access(cfg["state_dir"], os.W_OK), "state dir writable: %s" % cfg["state_dir"])
    p = cfg["challenge"]["provider"]
    line(p == "none" or bool(cfg["challenge"]["site_key"] and sec.get("captcha_secret")), "captcha: %s%s" % (p, "" if p == "none" else " (keys set)"))
    line(True, "notification channels: %s" % (", ".join(cfg["notify"]["channels"]) or "none (alerts go to the journal)"))
    line(True, "AI: %s" % cfg["ai"]["provider"])
    line(not cfg["canary"]["enabled"] or sys.platform.startswith("linux"), "canary files: %s" % ("on" if cfg["canary"]["enabled"] else "off"))
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rmon", description="RMON: self-hosted web guard (traps, risk score, captcha challenge, fingerprint, alerts)")
    ap.add_argument("--version", action="version", version="rmon " + __version__)
    sp = ap.add_subparsers(dest="cmd")
    s = sp.add_parser("setup", help="interactive setup wizard")
    s.add_argument("--answers", help="JSON file with the answers (unattended install)")
    for name in ("guard", "challenge", "canary", "bans", "status", "doctor", "notify-test", "explain"):
        sp.add_parser(name)
    for name in ("unban", "trust"):
        sp.add_parser(name).add_argument("target", help="IP address (or 'all' for unban)")
    a = ap.parse_args(argv)
    cfg, sec = config.load(), config.load_secrets()
    store = store_mod.Store(cfg["state_dir"]) if a.cmd in ("guard", "challenge", "canary", "bans", "unban", "trust", "status", "explain") else None

    if a.cmd == "setup":
        answers = json.load(open(a.answers)) if a.answers else None
        setup(IO(answers))
    elif a.cmd == "guard":
        from .guard import Guard
        Guard(cfg, sec, store).run()
    elif a.cmd == "challenge":
        from .challenge import server
        server.serve(cfg, store, sec)
    elif a.cmd == "canary":
        from .canary import Canary
        notifier = notify_mod.Notifier(cfg, sec)

        def on_event(e):
            where = "%s by %s" % (e["op"], e.get("proc") or "unknown process")
            ip = e.get("ssh_ip")
            if ip and netutil.is_public(ip) and not netutil.in_nets(ip, netutil.parse_nets(cfg["guard"]["never_ban"])):
                store.ban(ip, cfg, "opened a canary file over SSH")
                where += " (SSH session from %s: banned)" % ip
            notifier.send("alert", "Canary file opened", "%s: %s" % (e["file"], where), key="canary:" + e["file"], min_gap=30)
        Canary(cfg, on_event).run()
    elif a.cmd == "bans":
        now = time.time()
        for k, v in sorted(store.active("bans", now).items()):
            print("ban   %-40s until %s  %s" % (k, time.strftime("%d/%m %H:%M", time.localtime(v["until"])), v.get("why", "")))
        for k, v in sorted(store.active("challenges", now).items()):
            print("check %-40s until %s  %s" % (k, time.strftime("%d/%m %H:%M", time.localtime(v["until"])), v.get("kind", "")))
        for h, v in sorted(store.active("fpbans", now).items()):
            print("tool  %-40s until %s  %s" % (h, time.strftime("%d/%m %H:%M", time.localtime(v["until"])), v["comps"]["ua"][:50]))
    elif a.cmd == "unban":
        print("removed %d" % store.unban(a.target))
    elif a.cmd == "trust":
        if netutil.parse_ip(a.target) is None:
            print("not an IP address")
            return 1
        tr = store.load("trusted", [])
        tr = tr if isinstance(tr, list) else []
        store.save("trusted", sorted(set(tr + [netutil.target(a.target)])))
        store.unban(a.target)
        print("trusted:", netutil.target(a.target))
    elif a.cmd == "status":
        now = time.time()
        print("bans %d, challenges %d, fingerprint blocks %d, passes %d" % tuple(len(store.active(n, now)) for n in ("bans", "challenges", "fpbans", "passes")))
    elif a.cmd == "doctor":
        return 0 if doctor(cfg, sec) else 1
    elif a.cmd == "notify-test":
        sent = notify_mod.Notifier(cfg, sec).send("alert", "Test", "This is a test alert from %s." % cfg["branding"]["bot_name"])
        print("sent to: %s" % (", ".join(sent) or "no channel configured"))
    elif a.cmd == "explain":
        from . import ai
        rows = ["%s: %s" % (k, v.get("why", "")) for k, v in list(store.active("bans").items())[-15:]]
        out = ai.ask(cfg, sec, "Summarise these recent bans and say if anything needs attention.", "\n".join(rows) or "no recent bans")
        print(out or "AI is off or unavailable (rmon setup).")
    else:
        ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
