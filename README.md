# RMON

**A self-hosted guard for your web servers.** It reads your access log, traps scanners, scores risky behaviour, asks suspicious visitors for a one-second captcha instead of banning them, blocks attack tools by fingerprint, plants canary files on your machines and alerts you (push, Telegram, e-mail, webhook, even a phone call). Works with **Caddy** or **nginx**, on any Debian/Ubuntu server, with **no data sent anywhere** unless you turn it on.

> Français : [README.fr.md](README.fr.md)

## Why it is different

* **Zero false positives on humans, by design.** Two tiers:
  * *Certain* detections (requests for `/.env`, `/.git`, `phpinfo.php`, PHP in uploads, SQL injection, scanner user-agents...) ban at once.
  * *Ambiguous* detections (lots of 404s, failed logins, a high risk score) never ban: the visitor gets an automatic **captcha challenge** that a human passes in about a second. A bot that ignores it, or never solves it, is banned.
* **Bot probability, not a single threshold.** The challenge combines the captcha score, the browser environment (webdriver, headless, software GL), *behaviour* (trusted input events, mouse-trajectory shape) and history into one probability (readable, fixed-weight logistic model: [`rmon/rules.py`](rmon/rules.py)). Uncertain? One confirmation click. Clearly a robot? It stays blocked.
* **Fingerprinting.** Attackers rotate addresses, not tools. When the same rare fingerprint shows up behind 3 banned addresses and no ordinary visitor, the tool itself is blocked. A fingerprint seen from one of *your* trusted addresses is never blocked.
* **Honeytokens.** Fake `passwords.txt`, `.aws/credentials`, SSH keys and SQL dumps are planted on the machine. Opening one raises an alert naming the exact process and, for SSH sessions, the client address (Linux fanotify; the open is always allowed, we only watch).
* **Flexible alerts.** Telegram, [ntfy](https://ntfy.sh) (free push, no account), e-mail, webhook, and a **phone call** for critical alerts through Twilio, your own Asterisk/SIP PBX, or any command.
* **Optional AI, read-only.** Mistral, DeepSeek, OpenAI, a local Ollama or any OpenAI-compatible API can explain incidents in plain words. It can never ban, unban or run anything, and IP addresses are masked before anything is sent.
* **Yours.** Rename the bot, use your own logo and colours, English or French pages. No telemetry, no phoning home, no account.

## Quick start

```bash
# 1. install (Debian/Ubuntu)
curl -fsSL https://raw.githubusercontent.com/Bismela21/rmon/main/install.sh | sudo RMON_REPO=Bismela21/rmon bash
# (or download the .deb from the Releases page and: sudo apt install ./rmon_*_all.deb)

# 2. answer ~8 short questions (everything has a default or is detected)
sudo rmon setup

# 3. paste the one or two lines it prints into your Caddy / nginx config, then:
sudo systemctl enable --now rmon-guard rmon-challenge
sudo rmon doctor
```

`rmon setup` asks: bot name/language/logo, web server (detected), captcha provider and keys, alert channels (and phone-call driver), optional AI, canary files, your own IPs that must never be blocked, ban duration. Unattended installs: `rmon setup --answers answers.json`.

## Commands

| Command | What it does |
|---|---|
| `rmon setup` | interactive wizard (writes `/etc/rmon/config.json`, `secrets.json`, web-server snippets) |
| `rmon guard` / `challenge` / `canary` | the three services (systemd units are installed) |
| `rmon bans` | active bans, challenges and fingerprint blocks |
| `rmon unban <ip\|all>` · `rmon trust <ip>` | lift a ban · never touch this address again |
| `rmon doctor` · `rmon status` | health checks · counters |
| `rmon notify-test` | send a test alert (and ring the phone if configured) |
| `rmon explain` | ask your AI to summarise recent bans (if enabled) |

## Requirements

Debian/Ubuntu (or any Linux with systemd) and Python 3.9+. **No third-party Python packages.** Caddy 2.x or nginx. Canary files need root and a kernel with fanotify (any recent Linux). Behind Cloudflare or another proxy, make sure your server logs the *real* visitor address ([docs/CADDY.md](docs/CADDY.md), [docs/NGINX.md](docs/NGINX.md)).

## Documentation

[Install](docs/INSTALL.md) · [Configuration](docs/CONFIG.md) · [Caddy](docs/CADDY.md) · [nginx](docs/NGINX.md) · [Phone calls (VoIP)](docs/VOIP.md) · [Architecture & detections](docs/ARCHITECTURE.md) · [Privacy](docs/PRIVACY.md) · [Security policy](SECURITY.md)

## Honest limits

* A bot driving a *real* browser with stealth patches, a good captcha score and human-like mouse movement can pass. No tool detects that for certain; RMON raises the cost and removes the cheap bots.
* Behind Cloudflare the origin cannot see the TLS (JA3) fingerprint; RMON fingerprints the HTTP headers instead.
* Low captcha scores happen to real people on VPNs or privacy browsers: they get one confirmation click rather than a ban, and a low score is never punished.
* This is a defensive layer, not a WAF replacement.

## Roadmap

Android app (push + status, built with your own Firebase or via ntfy), apt repository with signed releases, Cloudflare firewall backend, optional Proxmox/hypervisor module (host-level collection, auto-isolation), WordPress sentinel plugin, more traps and detections.

## License

[GNU AGPL-3.0](LICENSE). If you run a modified version as a network service you must offer its source to your users.
