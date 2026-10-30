# Caddy

`rmon setup` writes `/etc/rmon/caddy/rmon.caddy` (a snippet named `rmon_guard`) and an empty `rmon-state.conf`.

1. Put this at the **top** of `/etc/caddy/Caddyfile`:
   ```
   import /etc/rmon/caddy/rmon.caddy
   ```
2. Inside every site you want protected:
   ```
   example.com {
       import rmon_guard
       reverse_proxy 127.0.0.1:8080
   }
   ```
3. `sudo systemctl reload caddy`.

The snippet (a) writes a JSON access log without request headers, with five extra fields (`fp_ua`, `fp_al`, `fp_ae`, `fp_sua`, `fp_sup`) used for fingerprinting, (b) proxies `/__rmon/*` to the challenge server, and (c) serves the block / challenge page to banned, fingerprint-blocked and challenged visitors. The guard rewrites `rmon-state.conf` (three named matchers), runs `caddy validate`, reloads, and rolls back by itself if Caddy refuses it.

## Behind Cloudflare (or any proxy)

Caddy must log the *real* client address, otherwise RMON would see the proxy. In the global options block:

```
{
    servers {
        trusted_proxies static 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
        client_ip_headers Cf-Connecting-Ip X-Forwarded-For
    }
}
```

RMON never bans a Cloudflare edge address. Check with `rmon doctor` and by looking at one line of the log: `request.client_ip` must be a visitor, not a Cloudflare address.

## Notes

* Multiple sites: `import rmon_guard` in each; they share one log and one state.
* `log_append` accepts one placeholder per field; that is why the fingerprint uses five fields.
