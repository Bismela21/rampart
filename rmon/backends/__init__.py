"""Enforcement backends: turn the Store's state (bans / challenges / fingerprint bans) into web-server configuration."""
import os
import shutil

CONF_DIR = "/etc/rmon"


def detect_server():
    """caddy | nginx | none, from what is installed."""
    if shutil.which("caddy") or os.path.exists("/etc/caddy/Caddyfile"):
        return "caddy"
    if shutil.which("nginx") or os.path.isdir("/etc/nginx"):
        return "nginx"
    return "none"


def get(cfg):
    kind = cfg["web"].get("server", "auto")
    if kind == "auto":
        kind = detect_server()
    if kind == "caddy":
        from . import caddy
        return caddy.CaddyBackend(cfg)
    if kind == "nginx":
        from . import nginx
        return nginx.NginxBackend(cfg)
    from . import base
    return base.NullBackend(cfg)
