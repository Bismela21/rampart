# Install

## From the .deb (recommended)

```bash
# one line (checks the SHA-256 of the package)
curl -fsSL https://raw.githubusercontent.com/Bismela21/rmon/main/install.sh | sudo RMON_REPO=Bismela21/rmon bash

# or by hand
wget https://github.com/Bismela21/rmon/releases/latest/download/rmon_all.deb
sudo apt install ./rmon_all.deb
```

The package installs the Python code (no third-party dependency), three systemd units (`rmon-guard`, `rmon-challenge`, `rmon-canary`) and creates an unprivileged `rmon` user for the challenge server.

## From source

```bash
git clone https://github.com/Bismela21/rmon && cd rmon
python3 -m unittest discover -s tests          # 34 tests
python3 packaging/build_deb.py && sudo apt install ./dist/rmon_*_all.deb
```

## Configure

```bash
sudo rmon setup        # ~8 questions; unattended: sudo rmon setup --answers answers.json
sudo rmon doctor       # checks the log, the state directory, captcha keys, channels
sudo systemctl enable --now rmon-guard rmon-challenge      # + rmon-canary if you enabled canary files
sudo rmon notify-test
```

The wizard writes `/etc/rmon/config.json` (everything non-secret), `/etc/rmon/secrets.json` (captcha secret, bot tokens, API keys; mode 640 root:rmon) and the web-server snippets, then prints the one or two lines to add to your Caddy or nginx configuration ([Caddy](CADDY.md), [nginx](NGINX.md)).

## Unattended example (`answers.json`)

```json
{"bot_name": "Watchdog", "lang": "en", "server": "caddy", "captcha": "3", "site_key": "0x4AAAA...", "captcha_secret": "0x4AAAA...",
 "channels": "ntfy,call", "ntfy_topic": "my-long-random-topic", "call_driver": "twilio", "call_to": "+15550100",
 "twilio_sid": "AC...", "twilio_from": "+15550101", "twilio_token": "...", "ai": "2", "ai_key": "...", "canary": "y",
 "never_ban": "203.0.113.5, 198.51.100.0/24", "ban_hours": "24"}
```

Captcha menu: 1 none, 2 reCAPTCHA v3, 3 Cloudflare Turnstile, 4 hCaptcha. AI menu: 1 none, 2 Mistral, 3 DeepSeek, 4 OpenAI, 5 Ollama, 6 custom.

## Uninstall

`sudo apt remove rmon` keeps your configuration; `sudo apt purge rmon` also removes `/var/lib/rmon`. Remove the `import` / `include` lines you added to your web-server configuration.
