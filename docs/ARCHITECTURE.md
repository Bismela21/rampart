# Architecture and detections

```
 access log ──► guard (root) ──► engine ──► store (/var/lib/rmon/*.json) ◄── challenge server (user rmon, 127.0.0.1:8772)
                  │                                 │                              ▲
                  │ sync (every change, every 2 s)  │                              │ /__rmon/* proxied by Caddy / nginx
                  ▼                                 ▼                              │
        backend: caddy | nginx  ───────────► web server enforces: ban page, challenge page, fingerprint block
 canary (root, fanotify) ──► alerts (+ bans an SSH client address that opened a canary)
 notify: telegram · ntfy · email · webhook · phone call        ai: optional, read-only explanations
```

* **Privilege separation.** The internet-facing challenge server runs unprivileged and only edits state files; the root guard re-applies the web-server configuration. The challenge server can lift a ban but cannot run anything.
* **Safe reloads.** Every configuration write is validated (`caddy validate` / `nginx -t`) and rolled back on failure.
* **No lock-out.** Private ranges, Cloudflare edges, `never_ban`, `rmon trust` addresses and verified search-engine crawlers (reverse DNS then forward DNS) are never touched.

## Detections

| Kind | Examples | Action |
|---|---|---|
| Certain | trap paths (`/.env`, `/.git`, `/phpinfo.php`, backups at the root), PHP requested in uploads, SQL/path-traversal injection, scanner user-agents | ban (24 h, then 7 / 30 days) |
| Ambiguous | 20 missing pages in 30 s, 6 failed logins in 1 min, risk score >= 8 over >= 5 distinct paths | **challenge**, never a ban |
| Escalation | 40 requests while challenged, 3 unsolved challenges in 24 h, 5 rejected captcha tokens in 1 h | ban (7 days for token tampering) |
| Fingerprint | the same rare fingerprint behind >= 3 banned addresses and <= 1 normal visitor | block the fingerprint 24 h (max 20; never one seen from a trusted address, never a crawler) |

## Challenge decision

`p(robot)` combines the captcha score (reCAPTCHA v3; neutral for providers without a score), the browser environment, behaviour and history ([`rules.bot_prob`](../rmon/rules.py)). For a simple challenge: `p < 0.35` pass, `0.35-0.65` one confirmation click, above that it stays blocked. To lift a real ban the thresholds are stricter (`0.25` / `0.5`), once per 24 h per address, and serious bans (injection, php in uploads) are never lifted automatically. A low *score* alone is never punished.

## Fingerprint

`User-Agent`, `Accept-Language`, `Accept-Encoding`, `Sec-CH-UA`, `Sec-CH-UA-Platform` (what an origin sees through a CDN). Hash in the log, exact match in the web server rule.
