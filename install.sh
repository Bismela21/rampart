#!/bin/sh
# RMON installer: downloads the latest .deb from GitHub Releases, verifies its SHA-256, installs it with apt.
#   curl -fsSL https://raw.githubusercontent.com/OWNER/rmon/main/install.sh | sudo RMON_REPO=OWNER/rmon bash
# Nothing else is downloaded or executed; read this file first if you prefer.
set -eu

REPO="${RMON_REPO:-OWNER/rmon}"
VERSION="${RMON_VERSION:-latest}"

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
command -v apt-get >/dev/null 2>&1 || { echo "This installer is for Debian/Ubuntu (apt). Install from source: see docs/INSTALL.md" >&2; exit 1; }
case "$REPO" in OWNER/*) echo "Set RMON_REPO=<github-user>/rmon (this copy of the installer has no repository configured)." >&2; exit 1;; esac

if [ "$VERSION" = "latest" ]; then BASE="https://github.com/$REPO/releases/latest/download"; else BASE="https://github.com/$REPO/releases/download/$VERSION"; fi
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

echo "Downloading rmon_all.deb from $BASE ..."
curl -fsSL -o rmon_all.deb "$BASE/rmon_all.deb"
curl -fsSL -o rmon_all.deb.sha256 "$BASE/rmon_all.deb.sha256"
WANT="$(cut -d' ' -f1 rmon_all.deb.sha256)"
GOT="$(sha256sum rmon_all.deb | cut -d' ' -f1)"
[ "$WANT" = "$GOT" ] || { echo "SHA-256 mismatch: refusing to install." >&2; exit 1; }
echo "SHA-256 OK."

apt-get install -y ./rmon_all.deb
echo
echo "Done. Next: sudo rmon setup"
