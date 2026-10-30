#!/usr/bin/env python3
"""Builds rmon_<version>_all.deb with nothing but the Python standard library (works on Windows, macOS and Linux CI).
    python packaging/build_deb.py [--out dist] [--homepage https://github.com/Bismela21/rmon] [--maintainer "Name <mail>"]"""
import argparse
import gzip
import hashlib
import io
import os
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from rmon import __version__  # noqa: E402

SERVICES = {
    "rmon-guard.service": """[Unit]
Description=RMON guard: follows the web access log, bans / challenges abusive clients
After=network.target

[Service]
ExecStart=/usr/bin/rmon guard
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""",
    "rmon-challenge.service": """[Unit]
Description=RMON challenge server (captcha unblock page, 127.0.0.1 only)
After=network.target

[Service]
User=rmon
Group=rmon
ExecStart=/usr/bin/rmon challenge
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/rmon
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
""",
    "rmon-canary.service": """[Unit]
Description=RMON canary files (fake secrets: opening one raises an alert)
After=network.target

[Service]
ExecStart=/usr/bin/rmon canary
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
""",
}

POSTINST = """#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    getent group rmon >/dev/null || addgroup --system rmon
    getent passwd rmon >/dev/null || adduser --system --ingroup rmon --no-create-home --home /nonexistent --shell /usr/sbin/nologin rmon
    install -d -m 0750 -o rmon -g rmon /var/lib/rmon
    install -d -m 0750 -o root -g rmon /etc/rmon
    if [ -x /bin/systemctl ]; then systemctl daemon-reload || true; fi
    echo
    echo "RMON installed. Next step:   sudo rmon setup"
    echo "then:                        sudo systemctl enable --now rmon-guard rmon-challenge"
fi
exit 0
"""
PRERM = """#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    for s in rmon-guard rmon-challenge rmon-canary; do systemctl disable --now $s 2>/dev/null || true; done
fi
exit 0
"""
POSTRM = """#!/bin/sh
set -e
if [ "$1" = "purge" ]; then rm -rf /var/lib/rmon; fi
if [ -x /bin/systemctl ]; then systemctl daemon-reload || true; fi
exit 0
"""
BIN = """#!/usr/bin/python3
import sys
from rmon.cli import main
sys.exit(main())
"""


def tar_bytes(entries):
    """entries: [(path, bytes|None (dir), mode)] -> gzip'd tar with root ownership and a fixed mtime (reproducible)."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w", format=tarfile.GNU_FORMAT) as t:
        for path, data, mode in entries:
            ti = tarfile.TarInfo(path)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            ti.mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "1767225600"))
            ti.mode = mode
            if data is None:
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            else:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
    raw = bio.getvalue()
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as g:
        g.write(raw)
    return out.getvalue()


def ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += b"%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name.encode(), 0, 0, 0, b"100644", len(data))
        out += data + (b"\n" if len(data) % 2 else b"")
    return out


def collect():
    data, dirs, md5 = [], set(), []

    def add(path, content, mode):
        parts = path.strip("/").split("/")
        for i in range(1, len(parts)):
            d = "./" + "/".join(parts[:i]) + "/"
            if d not in dirs:
                dirs.add(d)
                data.append((d, None, 0o755))
        data.append(("./" + path.strip("/"), content, mode))
        md5.append("%s  %s\n" % (hashlib.md5(content).hexdigest(), path.strip("/")))

    pkg = os.path.join(ROOT, "rmon")
    for base, ds, fs in os.walk(pkg):
        ds[:] = sorted(d for d in ds if d != "__pycache__")
        for f in sorted(fs):
            if f.endswith((".py",)):
                full = os.path.join(base, f)
                rel = os.path.relpath(full, ROOT).replace(os.sep, "/")
                add("usr/lib/python3/dist-packages/" + rel, open(full, "rb").read().replace(b"\r\n", b"\n"), 0o644)
    add("usr/bin/rmon", BIN.encode(), 0o755)
    for n, t in SERVICES.items():
        add("lib/systemd/system/" + n, t.encode(), 0o644)
    for doc in ("README.md", "LICENSE"):
        p = os.path.join(ROOT, doc)
        if os.path.exists(p):
            add("usr/share/doc/rmon/" + doc, open(p, "rb").read(), 0o644)
    for p in sorted(os.listdir(os.path.join(ROOT, "docs"))) if os.path.isdir(os.path.join(ROOT, "docs")) else []:
        add("usr/share/doc/rmon/docs/" + p, open(os.path.join(ROOT, "docs", p), "rb").read(), 0o644)
    return data, "".join(md5)


def build(out_dir, homepage, maintainer):
    data, md5 = collect()
    size_kb = sum(len(c) for _, c, _ in data if c) // 1024 + 1
    control = f"""Package: rmon
Version: {__version__}
Section: admin
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), adduser
Recommends: caddy | nginx
Suggests: asterisk
Installed-Size: {size_kb}
Maintainer: {maintainer}
Homepage: {homepage}
Description: self-hosted guard for web servers
 Traps, risk scoring, captcha challenge (reCAPTCHA / Turnstile / hCaptcha),
 client fingerprinting, canary files and alerts (Telegram, ntfy, email,
 webhook, phone call). Works with Caddy or nginx. Optional AI explanations
 through any OpenAI-compatible API (Mistral, DeepSeek, OpenAI, Ollama).
 No telemetry: nothing leaves the machine except what you enable.
"""
    ctrl = [("./", None, 0o755), ("./control", control.encode(), 0o644), ("./md5sums", md5.encode(), 0o644),
            ("./postinst", POSTINST.encode(), 0o755), ("./prerm", PRERM.encode(), 0o755), ("./postrm", POSTRM.encode(), 0o755)]
    deb = ar([("debian-binary", b"2.0\n"), ("control.tar.gz", tar_bytes(ctrl)), ("data.tar.gz", tar_bytes([("./", None, 0o755)] + data))])
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "rmon_%s_all.deb" % __version__)
    with open(path, "wb") as f:
        f.write(deb)
    with open(path + ".sha256", "w") as f:
        f.write("%s  %s\n" % (hashlib.sha256(deb).hexdigest(), os.path.basename(path)))
    return path


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(ROOT, "dist"))
    ap.add_argument("--homepage", default="https://github.com/Bismela21/rmon")
    ap.add_argument("--maintainer", default="RMON contributors <rmon@invalid.example>")
    a = ap.parse_args()
    print(build(a.out, a.homepage, a.maintainer))
