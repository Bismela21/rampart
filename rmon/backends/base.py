import os
import subprocess


class NullBackend:
    """No web server integration: bans are only recorded (use `rmon bans`) and optionally enforced by the firewall backend."""
    name = "none"

    def __init__(self, cfg):
        self.cfg = cfg

    def render(self, snap):
        return ""

    def apply(self, snap):
        return True


def write_if_changed(path, text, mode=0o644):
    try:
        if open(path, encoding="utf-8").read() == text:
            return False
    except OSError:
        pass
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def cel_quote(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


FP_FIELDS = (("ua", "User-Agent"), ("al", "Accept-Language"), ("ae", "Accept-Encoding"), ("sua", "Sec-Ch-Ua"), ("sup", "Sec-Ch-Ua-Platform"))


def writable_fp(comps):
    """A fingerprint can only be enforced when every field is plain printable ASCII without backtick, quote-breaking braces or backslash tricks."""
    return all(isinstance(comps.get(k), str) and len(comps[k]) <= 300 and all(32 <= ord(c) < 127 and c not in "`{}" for c in comps[k]) for k, _ in FP_FIELDS)
