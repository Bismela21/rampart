# Security policy

Please report vulnerabilities **privately** through GitHub's "Report a vulnerability" (Security tab) rather than a public issue. We aim to acknowledge within a few days.

Scope of particular interest: the challenge server (`/__rmon/unlock`), the configuration generators for Caddy / nginx, the notification drivers (command execution), and anything that could make RMON ban or unban the wrong address.

Design rules we keep: stdlib only, the internet-facing server runs unprivileged, every web-server write is validated and rolled back, user-supplied strings are never passed to a shell, secrets are never logged, and the AI helper is read-only.
