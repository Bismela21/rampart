# nginx

`rmon setup` writes two files in `/etc/rmon/nginx/` and an empty `rmon-state.conf`.

1. In `http { }` (e.g. `/etc/nginx/nginx.conf`):
   ```
   include /etc/rmon/nginx/rmon-http.conf;
   ```
   It defines the JSON log format `rmon_json` (with the fingerprint headers), an access log, and the state maps (`$rmon_state`: 0 free, 1 banned, 2 challenged).
2. In each `server { }` to protect:
   ```
   include /etc/rmon/nginx/rmon-guard.conf;
   ```
   It proxies `/__rmon/` to the challenge server and rewrites banned / challenged visitors to the block / challenge page.
3. `sudo nginx -t && sudo systemctl reload nginx`.

The guard rewrites `rmon-state.conf`, runs `nginx -t`, reloads, and rolls back if nginx refuses it.

## Behind Cloudflare or a proxy

Enable the realip module so `$remote_addr` is the visitor:

```
set_real_ip_from 173.245.48.0/20;   # ... and the other Cloudflare ranges
real_ip_header CF-Connecting-IP;
```

## Notes

* The state maps use `geo` (IPv4 and IPv6 /64 ranges) and one `map` of exact fingerprint strings.
* Use `rmon bans` to see what the web server currently enforces.
