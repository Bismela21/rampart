# Privacy

RMON has **no telemetry, no analytics, no account and no update ping**. Nothing leaves your server unless you enable it:

| Feature | What is sent, and to whom |
|---|---|
| Captcha (optional) | when a visitor is challenged or blocked, the page loads the provider's script (Google reCAPTCHA / Cloudflare Turnstile / hCaptcha) and the provider sees that visitor's browser. The page shows the provider's privacy and terms links. `provider: none` loads nothing third-party. |
| Behaviour model | on the challenge / block page only (addresses that are already suspicious): counters of trusted input events, the *shape* of the mouse trajectory (straightness, speed variation), a few browser flags and the elapsed time. **No coordinates, keystrokes, content or identifiers.** Only the resulting decision is logged. |
| Alerts (optional) | the text of the alert (kind, address, file name) goes to the channel you configured (Telegram, ntfy, e-mail, webhook, phone call). |
| AI (optional) | a short summary of recent events goes to the API you configured; IP addresses are masked unless `ai.send_ips` is true. The model can only answer, never act. |

Access logs contain visitor IP addresses and user-agents (as any web server log). Request headers such as cookies and `Authorization` are removed from the Caddy log. Keep logs only as long as you need them and mention the guard in your privacy policy if you are subject to GDPR (legitimate interest: security).
