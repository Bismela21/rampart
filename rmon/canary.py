"""Canary files (honeytokens). Fake secrets nobody has a reason to open: any open = someone is rummaging through the machine.
Linux fanotify "permission" events suspend the opening process just long enough to read /proc/<pid> (command, user, ancestry and the SSH client
address from SSH_CONNECTION), then ALLOW the open: we observe, we never block. If the daemon dies the kernel allows everything by itself.
Files are dated in the past and never read by RMON (find/stat/ls do not open them)."""
import ctypes
import hashlib
import json
import os
import re
import secrets as _secrets
import select
import struct
import sys
import time

FAN_CLOEXEC, FAN_CLASS_CONTENT, FAN_NONBLOCK, FAN_MARK_ADD, FAN_ALLOW = 0x1, 0x4, 0x2, 0x1, 0x1
FAN_MODIFY, FAN_OPEN_PERM, FAN_OPEN_EXEC_PERM = 0x2, 0x10000, 0x40000
MASK = FAN_MODIFY | FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM
OPS = ((FAN_OPEN_EXEC_PERM, "execution"), (FAN_MODIFY, "modification"), (FAN_OPEN_PERM, "open"))
META, RESP = struct.Struct("<IBBHQii"), struct.Struct("<iI")
OLD = time.mktime((2025, 3, 14, 10, 12, 0, 0, 0, -1))


def _rnd(n, alpha="abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"):
    return "".join(_secrets.choice(alpha) for _ in range(n))


def fake_content(path):
    """Plausible but FAKE content with random tokens: nothing grants access to anything."""
    b = os.path.basename(path)
    if b == "credentials":
        return "[default]\naws_access_key_id = AKIA%s\naws_secret_access_key = %s\nregion = eu-west-3\n" % (_rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"), _rnd(40))
    if b.startswith("id_"):
        return "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n" % "\n".join(_rnd(70, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") for _ in range(24))
    if b.endswith(".sql"):
        return ("-- MySQL dump 10.13  Distrib 8.0.36\nINSERT INTO `users` VALUES (1,'admin','$P$B%s','admin@localhost'),(2,'backup','$P$B%s','b@localhost');\n" % (_rnd(28), _rnd(28)))
    if b.endswith(".txt"):
        return "# emergency access - do not delete\nroot       %s\ndatabase   %s\npanel      %s\n" % (_rnd(16), _rnd(16), _rnd(16))
    return "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_USER=prod\nDB_PASSWORD=%s\nSECRET_KEY=%s\n" % (_rnd(18), _rnd(40))


def proc_info(pid):
    info, chain, ssh_ip, p = {}, [], None, pid
    for _ in range(14):
        try:
            comm = open("/proc/%d/comm" % p).read().strip()
            st = open("/proc/%d/status" % p).read()
            ppid, uid = int(re.search(r"PPid:\s+(\d+)", st).group(1)), int(re.search(r"Uid:\s+(\d+)", st).group(1))
        except (OSError, AttributeError, ValueError):
            break
        if not info:
            try:
                cmd = open("/proc/%d/cmdline" % p, "rb").read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
            except OSError:
                cmd = ""
            info = {"proc": comm, "cmd": cmd[:160], "uid": uid}
        chain.append(comm)
        if not ssh_ip:
            try:
                m = re.search(rb"SSH_CONNECTION=(\S+) ", open("/proc/%d/environ" % p, "rb").read())
                ssh_ip = m.group(1).decode() if m else None
            except OSError:
                pass
        if ppid <= 1:
            break
        p = ppid
    info["chain"], info["ssh_ip"] = chain[:8], ssh_ip
    return info


class Canary:
    def __init__(self, cfg, on_event):
        self.cfg, self.on_event = cfg, on_event
        self.paths = list(cfg["canary"]["paths"]) + list(cfg["canary"].get("extra_paths", []))
        self.state_file = os.path.join(cfg["state_dir"], "canary_files.json")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.fd = self.libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_NONBLOCK, os.O_RDONLY | getattr(os, "O_LARGEFILE", 0))
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init failed (needs root and a Linux kernel with fanotify)")
        self.ids, self.last, self.known = {}, {}, set()
        try:
            self.saved = json.load(open(self.state_file))
        except (OSError, ValueError):
            self.saved = {}

    def ensure(self):
        for p in self.paths:
            if not os.path.exists(p):
                self.saved.setdefault(p, fake_content(p))
                os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
                open(p, "w").write(self.saved[p])
                os.chmod(p, 0o600)
                os.utime(p, (OLD, OLD))
                if p in self.known:
                    self.on_event({"t": int(time.time()), "id": hashlib.sha1(("%s%f" % (p, time.time())).encode()).hexdigest()[:10], "file": p, "op": "trap deleted or moved (recreated)", "proc": "", "chain": [], "ssh_ip": None})
            self.known.add(p)
            try:
                st = os.stat(p)
            except OSError:
                continue
            if (st.st_dev, st.st_ino) not in self.ids:
                if self.libc.fanotify_mark(self.fd, FAN_MARK_ADD, ctypes.c_uint64(MASK), -100, p.encode()) < 0:
                    continue
            self.ids[(st.st_dev, st.st_ino)] = p
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        json.dump(self.saved, open(self.state_file, "w"))
        os.chmod(self.state_file, 0o600)

    def drain(self):
        while True:
            try:
                buf = os.read(self.fd, 65536)
            except BlockingIOError:
                return
            off = 0
            while off + META.size <= len(buf):
                elen, _v, _r, _ml, mask, fd, pid = META.unpack_from(buf, off)
                if elen < META.size:
                    return
                off += elen
                if fd < 0:
                    continue
                perm, tag, info = bool(mask & (FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM)), None, None
                try:
                    st = os.fstat(fd)
                    tag = self.ids.get((st.st_dev, st.st_ino))
                    if tag and perm and pid != os.getpid():
                        info = proc_info(pid)   # the process is suspended right now: /proc/<pid> is still there
                finally:
                    if perm:
                        os.write(self.fd, RESP.pack(fd, FAN_ALLOW))   # always allow
                    os.close(fd)
                if tag and pid != os.getpid() and time.time() - self.last.get(tag, 0) > 8:
                    self.last[tag] = time.time()
                    e = {"t": int(time.time()), "id": hashlib.sha1(("%s%f" % (tag, time.time())).encode()).hexdigest()[:10], "file": tag,
                         "op": next(n for m, n in OPS if mask & m), "pid": pid}
                    e.update(info or {})
                    self.on_event(e)

    def run(self, stop=lambda: False):
        last = 0
        while not stop():
            if time.time() - last > 60:
                last = time.time()
                self.ensure()
            r, _, _ = select.select([self.fd], [], [], 1)
            if r:
                self.drain()
