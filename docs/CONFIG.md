# Configuration reference (`/etc/rmon/config.json`)

Every key is optional: defaults live in [`rmon/config.py`](../rmon/config.py). Secrets never go here: they live in `/etc/rmon/secrets.json` (or `RMON_SECRET_<NAME>` environment variables): `captcha_secret`, `telegram_token`, `ntfy_token`, `smtp_password`, `twilio_token`, `ai_key`.

| Key | Default | Meaning |
|---|---|---|
| `branding.bot_name` | `RMON` | name shown in alerts and on the pages |
| `branding.logo` | `""` | path to a PNG/SVG/JPG (< 2 MB) embedded in the pages; empty = built-in shield with the bot's initial |
| `branding.accent` / `lang` | `#c2294a` / `en` | colour; `en` or `fr` |
| `web.server` | `auto` | `caddy`, `nginx` or `none` (bans only recorded) |
| `web.log_path` / `log_format` | autodetect | `caddy_json`, `nginx_json`, `nginx_combined` (no fingerprint fields with combined) |
| `guard.never_ban` | `[]` | IPs / CIDRs never banned nor challenged (private addresses and Cloudflare edges are always skipped) |
| `guard.ban_hours` | `24` | first ban; repeat offenders get `repeat_ban_days` = `[7, 30]` |
| `guard.risk_challenge` | `8.0` | risk score that triggers a challenge (404 = 0.5, failed login = 1.2, blocked request = 3, each multiplied by `1 + user-agent anomaly`, half-life 5 min) |
| `guard.login_paths` | wp-login, xmlrpc, /login ... | paths where repeated POSTs count as login attempts |
| `guard.extra_trap_paths` / `extra_trap_exact` | `[]` | your own traps: paths no real visitor requests on *your* sites |
| `guard.allow_paths` | `[]` | paths that must never be treated as traps (prefix match) |
| `guard.fingerprint` | `true` | fingerprint blocking |
| `challenge.provider` | `none` | `recaptcha_v3`, `turnstile`, `hcaptcha` or `none` (behaviour model only: one click to confirm) |
| `challenge.site_key` / `port` | `""` / `8772` | public key; local port of the challenge server |
| `challenge.challenge_minutes` / `pass_hours` | `60` / `6` | how long a challenge lasts / how long a solved one exempts soft signals |
| `canary.enabled` / `paths` / `extra_paths` | off | fake secret files to plant and watch |
| `notify.channels` | `[]` | any of `telegram ntfy email webhook call` |
| `notify.min_level` | `important` | `info`, `important`, `alert` |
| `notify.call.*` | none | phone call driver, see [VOIP.md](VOIP.md) |
| `ai.provider` | `none` | `mistral`, `deepseek`, `openai`, `ollama`, `custom` (+ `base_url`, `model`) |
| `ai.send_ips` | `false` | IPs are masked before anything is sent to a model |
| `state_dir` | `/var/lib/rmon` | bans, challenges, passes, fingerprint blocks, history |

Change a value, then `sudo systemctl restart rmon-guard rmon-challenge`.
