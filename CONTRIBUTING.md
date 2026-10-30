# Contributing

* `python3 -m unittest discover -s tests` must pass (stdlib only; no network needed).
* Keep the zero-dependency rule: no third-party Python packages in the core.
* Anything that can ban someone needs a test proving a normal visitor is never affected. False positives are bugs, not trade-offs.
* Never commit secrets, real domains or addresses; use `example.com` and RFC 5737 ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in tests and docs.
* New detections: add the rule in `rmon/rules.py` / `rmon/engine.py`, document it in `docs/ARCHITECTURE.md`, add tests.
* New backends / notification drivers: follow the small interfaces in `rmon/backends/` and `rmon/notify.py`.

By contributing you agree to license your work under the AGPL-3.0.
