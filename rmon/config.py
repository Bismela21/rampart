"""Configuration: one JSON file (/etc/rmon/config.json) + one secrets file (/etc/rmon/secrets.json, mode 0600).
Nothing is hard-coded about any infrastructure: every default below is generic."""
import copy
import json
import os

DEFAULTS = {
    "branding": {
        "bot_name": "RMON",          # shown in alerts and on the challenge / block pages
        "logo": "",                  # path to a PNG/SVG/JPG, embedded in the pages ("" = built-in shield)
        "accent": "#c2294a",
        "lang": "en",                # en | fr
    },
    "web": {
        "server": "auto",            # auto | caddy | nginx | none
        "log_path": "",              # "" = autodetect
        "log_format": "auto",        # auto | caddy_json | nginx_json | nginx_combined
        "trusted_proxies": [],       # extra CIDRs whose X-Forwarded-For we trust (Cloudflare ranges are built in)
    },
    "guard": {
        "never_ban": [],             # CIDRs / IPs that are never banned nor challenged (your office, your monitoring...)
        "ban_hours": 24,
        "repeat_ban_days": [7, 30],  # 2nd-3rd ban, 4th and later
        "max_active_bans": 300,
        "risk_challenge": 8.0,       # risk score (decays by half every 5 min) that triggers a captcha challenge
        "login_paths": ["/wp-login.php", "/xmlrpc.php", "/login", "/admin/login", "/user/login", "/users/sign_in"],
        "extra_trap_paths": [],      # substrings no real visitor requests on YOUR sites
        "extra_trap_exact": [],
        "allow_paths": [],           # paths that are NEVER traps on your sites (override)
        "fingerprint": True,
    },
    "challenge": {
        "provider": "none",          # none | recaptcha_v3 | turnstile | hcaptcha
        "site_key": "",              # public key (the secret key goes in secrets.json)
        "port": 8772,
        "challenge_minutes": 60,
        "pass_hours": 6,
    },
    "canary": {
        "enabled": False,
        "paths": ["/root/passwords.txt", "/root/.aws/credentials", "/root/secrets.env", "/root/backup/db-dump.sql"],
        "extra_paths": [],
    },
    "notify": {
        "min_level": "important",    # info | important | alert
        "channels": [],              # any of: telegram ntfy email webhook call
        "telegram": {"chat_id": ""},
        "ntfy": {"server": "https://ntfy.sh", "topic": ""},
        "email": {"smtp_host": "", "smtp_port": 587, "starttls": True, "user": "", "from": "", "to": ""},
        "webhook": {"url": ""},
        "call": {                    # phone call for alerts: pick one driver
            "driver": "none",        # none | twilio | asterisk | command
            "to": "",                # number / extension to call
            "twilio": {"account_sid": "", "from": ""},
            "asterisk": {"endpoint": "", "context": "rmon-alert"},
            "command": "",           # e.g. /usr/local/bin/my-caller "{message}" "{to}"
            "quiet_hours": [22, 8],  # calls only for level=alert; at other hours a push/message is used instead
            "only_during_quiet_hours": False,
        },
    },
    "ai": {
        "provider": "none",          # none | mistral | deepseek | openai | ollama | custom
        "base_url": "",              # custom / override (OpenAI-compatible /chat/completions API)
        "model": "",
        "send_ips": False,           # IPs are masked before anything is sent to a model unless you turn this on
    },
    "state_dir": "/var/lib/rmon",
}

PRESETS = {
    "mistral": {"base_url": "https://api.mistral.ai/v1", "model": "mistral-small-latest"},
    "deepseek": {"base_url": "https://api.deepseek.com/v1", "model": "deepseek-chat"},
    "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini"},
    "ollama": {"base_url": "http://127.0.0.1:11434/v1", "model": "llama3.1"},
}


def deep_merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def config_path():
    return os.environ.get("RMON_CONFIG") or "/etc/rmon/config.json"


def secrets_path():
    return os.environ.get("RMON_SECRETS") or os.path.join(os.path.dirname(config_path()), "secrets.json")


def load(path=None):
    cfg = copy.deepcopy(DEFAULTS)
    try:
        with open(path or config_path(), encoding="utf-8") as f:
            cfg = deep_merge(cfg, json.load(f))
    except FileNotFoundError:
        pass
    if os.environ.get("RMON_STATE_DIR"):
        cfg["state_dir"] = os.environ["RMON_STATE_DIR"]
    prov = PRESETS.get(cfg["ai"].get("provider"))
    if prov:
        cfg["ai"]["base_url"] = cfg["ai"].get("base_url") or prov["base_url"]
        cfg["ai"]["model"] = cfg["ai"].get("model") or prov["model"]
    return cfg


def load_secrets(path=None):
    """Secrets file first, then RMON_SECRET_<NAME> environment variables (handy for containers)."""
    sec = {}
    try:
        with open(path or secrets_path(), encoding="utf-8") as f:
            sec = json.load(f)
    except FileNotFoundError:
        pass
    for k, v in os.environ.items():
        if k.startswith("RMON_SECRET_"):
            sec[k[len("RMON_SECRET_"):].lower()] = v
    return sec


def save(cfg, path=None):
    path = path or config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")


def save_secrets(sec, path=None):
    path = path or secrets_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(sec, f, indent=2)
        f.write("\n")
    try:   # readable by the unprivileged challenge server (group "rmon"), never world-readable
        import shutil
        try:
            shutil.chown(path, group="rmon")
            os.chmod(path, 0o640)
        except (LookupError, PermissionError):
            os.chmod(path, 0o600)
    except OSError:
        pass
