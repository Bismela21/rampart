import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rmon import config, engine, logparse, netutil, notify, rules, store  # noqa: E402
from rmon.backends import caddy, nginx  # noqa: E402
from rmon.challenge import pages, server  # noqa: E402

CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


def mk(ip="45.9.20.1", path="/", status=200, method="GET", ua=CHROME, al="fr-FR", sua='"Chromium";v="130"', query="", fp=True):
    return logparse.Request(ip=ip, method=method, path=path, query=query, status=status, ua=ua, al=al, ae="gzip", sua=sua, sup='"Windows"', has_fp=fp)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = config.load("/nonexistent.json")
        self.cfg["state_dir"] = self.tmp.name
        self.store = store.Store(self.tmp.name)
        self.eng = engine.Engine(self.cfg, self.store)
        self.t = 1_800_000_000.0

    def tearDown(self):
        self.tmp.cleanup()

    def feed(self, req, dt=0.5):
        self.t += dt
        return self.eng.feed(req, self.t)


class TestParsers(unittest.TestCase):
    def test_caddy_json_with_fingerprint_fields(self):
        line = json.dumps({"request": {"client_ip": "8.8.4.4", "remote_ip": "172.70.1.1", "host": "a.example", "method": "GET", "uri": "/x?y=1"}, "status": 404, "size": 12,
                           "fp_ua": "curl/8", "fp_al": "", "fp_ae": "gzip", "fp_sua": "", "fp_sup": ""})
        r = logparse.parse_line(line)
        self.assertEqual((r.ip, r.path, r.query, r.status, r.ua, r.has_fp), ("8.8.4.4", "/x", "y=1", 404, "curl/8", True))

    def test_nginx_json_and_combined(self):
        r = logparse.parse_line(json.dumps({"ip": "8.8.4.4", "host": "h", "method": "POST", "uri": "/wp-login.php", "status": 200, "bytes": 5, "ua": "x", "al": "fr"}))
        self.assertEqual((r.method, r.path, r.has_fp), ("POST", "/wp-login.php", True))
        r = logparse.parse_line('8.8.4.4 - - [10/Oct/2026:13:55:36 +0000] "GET /a/b?c=d HTTP/1.1" 404 153 "-" "Mozilla/5.0 test"')
        self.assertEqual((r.ip, r.path, r.query, r.status, r.ua, r.has_fp), ("8.8.4.4", "/a/b", "c=d", 404, "Mozilla/5.0 test", False))
        self.assertIsNone(logparse.parse_line("garbage"))


class TestRules(unittest.TestCase):
    def test_traps_do_not_catch_plugin_files(self):
        self.assertTrue(rules.path_trap("/.env"))
        self.assertTrue(rules.path_trap("/phpinfo.php"))
        self.assertFalse(rules.path_trap("/wp-content/plugins/foo/info.php"))   # generic names count only as the whole path
        self.assertTrue(rules.path_trap("/backup.sql"))
        self.assertFalse(rules.path_trap("/.env", allow=("/.env",)))
        self.assertTrue(rules.path_trap("/my-secret-dir/x", extra_substr=("/my-secret-dir",)))

    def test_ua_anomaly(self):
        self.assertEqual(rules.ua_anomaly(CHROME, "fr", '"Chromium"'), 0)
        self.assertGreater(rules.ua_anomaly("python-requests/2.31"), 0.5)
        self.assertEqual(rules.ua_anomaly("Mozilla/5.0 (iPhone) CriOS/130 Mobile Safari", "fr", ""), 0)
        self.assertGreater(rules.ua_anomaly(CHROME, "fr", ""), 0)   # modern Chrome without client hints

    def test_bot_prob_orders_humans_below_bots(self):
        human = rules.bot_prob({"mc": 40, "sc": 3, "clk": 1, "mmn": 60, "mms": 0.7, "mmv": 0.6, "dt": 1400}, 0.9, 1, 0)[0]
        lazy = rules.bot_prob({"dt": 1000}, 0.9, 1, 0)[0]
        vpn1 = rules.bot_prob({"dt": 1000}, 0.5, 1, 0)[0]
        vpn2 = rules.bot_prob({"dt": 3000, "clk": 1, "mc": 12, "mmn": 12, "mms": 0.8, "mmv": 0.5}, 0.5, 2, 0)[0]
        headless = rules.bot_prob({"wd": 1, "hl": 1, "sw": 1, "dt": 900}, 0.9, 1, 0)[0]
        synth = rules.bot_prob({"ut": 5, "dt": 900}, 0.9, 1, 0)[0]
        self.assertLess(human, 0.1)
        self.assertLess(lazy, 0.35)
        self.assertTrue(0.35 <= vpn1 < 0.65)      # asked for one confirmation step...
        self.assertLess(vpn2, 0.35)               # ...which a real click resolves
        self.assertGreater(headless, 0.9)
        self.assertGreater(synth, 0.65)


class TestEngine(Base):
    def test_trap_bans_immediately_and_normal_traffic_never(self):
        for i in range(50):
            self.assertEqual(self.feed(mk("45.9.20.9", "/page%d" % (i % 3))), [])
        ev = self.feed(mk("45.9.20.1", "/.env", 404))
        self.assertEqual([e["type"] for e in ev], ["ban"])
        self.assertTrue(self.store.is_banned("45.9.20.1", self.t))

    def test_private_trusted_and_cloudflare_are_never_touched(self):
        self.cfg["guard"]["never_ban"] = ["45.9.20.7"]
        eng = engine.Engine(self.cfg, self.store)
        for ip in ("192.168.1.5", "10.0.0.2", "45.9.20.7", "172.70.1.1", "127.0.0.1"):
            self.assertEqual(eng.feed(mk(ip, "/.env", 404), self.t), [], ip)

    def test_ambiguous_signals_challenge_instead_of_ban(self):
        ev = []
        for i in range(25):
            ev += self.feed(mk("45.9.20.2", "/missing%d" % i, 404), 0.2)
        self.assertEqual([e["type"] for e in ev], ["challenge"])
        self.assertFalse(self.store.is_banned("45.9.20.2", self.t))
        self.assertIn("45.9.20.2", self.store.active("challenges", self.t))

    def test_script_user_agent_reaches_the_challenge_sooner_than_a_browser(self):
        script, browser = [], []
        for i in range(12):
            script += self.feed(mk("45.9.20.3", "/s%d" % i, 404, ua="python-requests/2.31", al="", sua=""), 5)
            browser += self.feed(mk("45.9.20.4", "/b%d" % i, 404), 5)
        self.assertEqual([e["type"] for e in script], ["challenge"])
        self.assertEqual(browser, [])

    def test_failed_logins_challenge_then_pass_stops_it(self):
        ev = []
        for i in range(8):
            ev += self.feed(mk("45.9.20.5", "/wp-login.php", 200, "POST"), 3)
        self.assertEqual([e["type"] for e in ev], ["challenge"])
        self.store.pass_challenge("45.9.20.5", self.cfg, self.t)
        self.eng._lists_t = 0
        self.t += 120
        ev = []
        for i in range(8):
            ev += self.feed(mk("45.9.20.5", "/wp-login.php", 200, "POST"), 3)
        self.assertEqual(ev, [])   # a verified human is not challenged again for soft signals

    def test_ignored_challenge_becomes_a_ban(self):
        for i in range(25):
            self.feed(mk("45.9.20.6", "/m%d" % i, 404), 0.1)
        ev = []
        for i in range(45):
            ev += self.feed(mk("45.9.20.6", "/anything%d" % i, 403), 0.1)
        self.assertEqual([e["type"] for e in ev], ["ban"])
        self.assertTrue(self.store.is_banned("45.9.20.6", self.t))

    def test_third_unsolved_challenge_in_24h_is_a_ban(self):
        types = []
        for round_ in range(3):
            self.store.unban("45.9.20.8")
            self.store.save("challenges", {})
            self.eng._lists_t = 0
            self.eng.s["recent"].clear()
            for i in range(25):
                types += [e["type"] for e in self.feed(mk("45.9.20.8", "/r%d_%d" % (round_, i), 404), 0.1)]
            self.t += 120
        self.assertEqual(types, ["challenge", "challenge", "ban"])

    def test_fingerprint_block_needs_three_banned_addresses_and_no_visitors(self):
        tool = dict(ua="EvilScanner-Toolkit/1.0 (compatible)", al="", sua="")
        types = []
        for i in range(4):
            types += [e["type"] for e in self.feed(mk("45.9.30.%d" % (i + 1), "/.env", 404, **tool))]
        self.assertEqual(types.count("fpban"), 1)
        self.assertEqual(len(self.store.active("fpbans", self.t)), 1)

    def test_browser_fingerprint_with_real_visitors_is_never_blocked(self):
        for i in range(30):   # many ordinary visitors share this exact browser fingerprint
            self.feed(mk("81.1.1.%d" % (i + 1), "/", 200))
        types = []
        for i in range(4):
            types += [e["type"] for e in self.feed(mk("45.9.31.%d" % (i + 1), "/.env", 404))]
        self.assertNotIn("fpban", types)

    def test_ordinary_browser_fingerprint_needs_much_stronger_proof(self):
        for i in range(4):   # 4 banned addresses with a plain Chrome fingerprint and one normal visitor: NOT enough to block "Chrome"
            self.feed(mk("45.9.33.%d" % (i + 1), "/.env", 404))
        self.feed(mk("81.2.2.2", "/", 200))
        self.assertEqual(self.store.active("fpbans", self.t), {})

    def test_trusted_address_protects_its_fingerprint(self):
        self.cfg["guard"]["never_ban"] = ["45.9.32.99"]
        eng = engine.Engine(self.cfg, self.store)
        tool = dict(ua="MyOwnTool-Client/2.0 (internal)", al="", sua="")
        eng.feed(mk("45.9.32.99", "/", 200, **tool), self.t)
        types = []
        for i in range(4):
            types += [e["type"] for e in eng.feed(mk("45.9.32.%d" % (i + 1), "/.env", 404, **tool), self.t + i)]
        self.assertNotIn("fpban", types)


class TestStore(Base):
    def test_recidivism_lengthens_bans(self):
        d = [self.store.ban("45.9.40.1", self.cfg, "x", self.t + i * 10) for i in range(1)]
        first = self.store.load("bans")["45.9.40.1"]
        self.assertEqual(first["until"] - first["since"], 24 * 3600)
        self.store.unban("45.9.40.1")
        self.store.ban("45.9.40.1", self.cfg, "x", self.t + 100)
        second = self.store.load("bans")["45.9.40.1"]
        self.assertEqual(second["until"] - second["since"], 7 * 86400)

    def test_ipv6_is_banned_by_its_slash_64(self):
        self.store.ban("2001:db8:1:2::5", self.cfg, "x", self.t)
        self.assertTrue(self.store.is_banned("2001:db8:1:2:ffff::1", self.t))
        self.assertFalse(self.store.is_banned("2001:db8:1:3::1", self.t))

    def test_expiry(self):
        self.store.ban("45.9.40.2", self.cfg, "x", self.t)
        self.assertTrue(self.store.expire(self.t + 25 * 3600))
        self.assertEqual(self.store.load("bans"), {})


class TestBackends(unittest.TestCase):
    SNAP = {"bans": ["45.9.20.1", "2001:db8:1:2::/64"], "challenges": ["45.9.20.2", "45.9.20.1"],
            "fpbans": [{"ua": 'Evil "Tool"/1.0', "al": "", "ae": "identity", "sua": "", "sup": ""}, {"ua": "bad`tick", "al": "", "ae": "", "sua": "", "sup": ""}]}

    def setUp(self):
        self.cfg = config.load("/nonexistent.json")

    def test_caddy_state(self):
        t = caddy.CaddyBackend(self.cfg).render(self.SNAP)
        self.assertIn("@rmon_banned client_ip 45.9.20.1 2001:db8:1:2::/64", t)
        self.assertIn("@rmon_challenge client_ip 45.9.20.2\n", t)       # an address both banned and challenged is only listed as banned
        self.assertIn('{http.request.header.User-Agent} == "Evil \\"Tool\\"/1.0"', t)
        self.assertNotIn("bad`tick", t)                                  # unwritable fingerprints are skipped, never emitted
        empty = caddy.CaddyBackend(self.cfg).render({"bans": [], "challenges": [], "fpbans": []})
        self.assertIn("192.0.2.254", empty)

    def test_nginx_state(self):
        t = nginx.NginxBackend(self.cfg).render(self.SNAP)
        self.assertIn("45.9.20.1 1;", t)
        self.assertIn("45.9.20.2 2;", t)
        self.assertIn('"Evil \\"Tool\\"/1.0|~||~|identity|~||~|" 1;', t)
        self.assertEqual(t.count("{"), t.count("}"))

    def test_static_snippets_mention_the_port(self):
        self.cfg["challenge"]["port"] = 9999
        self.assertIn("127.0.0.1:9999", caddy.snippet(self.cfg))
        self.assertIn("127.0.0.1:9999", nginx.guard_conf(self.cfg))
        self.assertIn("rmon_json", nginx.http_conf(self.cfg))


class TestChallenge(Base):
    def decider(self):
        return server.Decider(self.cfg, self.store, clock=lambda: self.t)

    def test_not_blocked_address_gets_a_neutral_message(self):
        r = self.decider().decide("45.9.50.1", {"dt": 1000}, 0.9, 1)
        self.assertFalse(r["ok"])

    def test_human_passes_a_challenge(self):
        self.store.challenge("45.9.50.2", self.cfg, "scan", self.t)
        r = self.decider().decide("45.9.50.2", {"mc": 20, "mmn": 20, "mms": 0.7, "mmv": 0.5, "dt": 1200}, 0.9, 1)
        self.assertTrue(r["ok"])
        self.assertNotIn("45.9.50.2", self.store.active("challenges", self.t))
        self.assertIn("45.9.50.2", self.store.active("passes", self.t))

    def test_headless_browser_fails(self):
        self.store.challenge("45.9.50.3", self.cfg, "scan", self.t)
        r = self.decider().decide("45.9.50.3", {"wd": 1, "hl": 1, "dt": 900}, 0.9, 1)
        self.assertFalse(r["ok"])
        self.assertIn("45.9.50.3", self.store.active("challenges", self.t))

    def test_uncertain_visitor_gets_one_confirmation_step(self):
        self.store.challenge("45.9.50.4", self.cfg, "scan", self.t)
        d = self.decider()
        r1 = d.decide("45.9.50.4", {"dt": 1000}, 0.5, 1)
        self.assertTrue(r1["step2"] and not r1["ok"])
        r2 = d.decide("45.9.50.4", {"dt": 3000, "clk": 1, "mc": 12, "mmn": 12, "mms": 0.8, "mmv": 0.5}, 0.5, 2)
        self.assertTrue(r2["ok"])

    def test_real_ban_is_stricter_and_serious_bans_are_never_lifted(self):
        self.store.ban("45.9.50.5", self.cfg, "sensitive-file probe", self.t)
        r = self.decider().decide("45.9.50.5", {"mc": 20, "mmn": 20, "mms": 0.7, "mmv": 0.5, "dt": 1200}, 0.9, 1)
        self.assertTrue(r["ok"])
        self.assertFalse(self.store.is_banned("45.9.50.5", self.t))
        again = self.decider().decide("45.9.50.5", {"dt": 1}, 0.9, 1)   # not banned any more
        self.assertFalse(again["ok"])
        self.store.ban("45.9.50.6", self.cfg, "injection / scanner", self.t)
        r = self.decider().decide("45.9.50.6", {"mc": 20, "mmn": 20, "mms": 0.7, "mmv": 0.5, "dt": 1200}, 0.99, 1)
        self.assertFalse(r["ok"])
        self.assertTrue(self.store.is_banned("45.9.50.6", self.t))

    def test_five_rejected_tokens_extend_the_ban(self):
        self.store.ban("45.9.50.7", self.cfg, "sensitive-file probe", self.t)
        d = self.decider()
        for _ in range(5):
            d.strike("45.9.50.7")
        b = self.store.load("bans")["45.9.50.7"]
        self.assertGreaterEqual(b["until"] - b["since"], 7 * 86400)

    def test_feature_sanitiser_drops_unknown_and_clamps(self):
        f = server.clean_features({"mc": 10 ** 12, "evil": "x", "wd": True, "mms": -5, "dt": "nan"})
        self.assertEqual(f, {"mc": 100000.0, "wd": 1.0, "mms": 0.0})


class TestPages(unittest.TestCase):
    def test_branding_is_configurable_and_nothing_personal_is_embedded(self):
        cfg = config.load("/nonexistent.json")
        cfg["branding"].update(bot_name="Gardien", lang="fr", accent="#112233")
        cfg["challenge"].update(provider="turnstile", site_key="0xABC")
        h = pages.render("challenge", cfg, "0xABC")
        self.assertIn("Gardien", h)
        self.assertIn("#112233", h)
        self.assertIn("challenges.cloudflare.com", h)
        self.assertIn("vérifions", h)
        self.assertNotIn("rips", h.lower())
        ban = pages.render("ban", cfg, "0xABC")
        self.assertIn('id="rcb"', ban)

    def test_default_page_for_provider_none_loads_no_third_party_script(self):
        cfg = config.load("/nonexistent.json")
        h = pages.render("ban", cfg, "")
        self.assertNotIn("google.com/recaptcha", h)
        self.assertNotIn("hcaptcha", h)


class TestBotSignals(Base):
    def kinds(self, evs):
        return [e["type"] for e in evs]

    def test_webdav_and_trace_probing_is_challenged(self):
        ev = []
        for i, m in enumerate(("TRACE", "PROPFIND", "TRACE", "PROPFIND", "CONNECT", "TRACE")):
            ev += self.feed(mk("45.9.70.1", "/p%d" % i, 405, m), 2)
        self.assertEqual(self.kinds(ev), ["challenge"])

    def test_user_enumeration_is_challenged_but_one_author_page_is_not(self):
        self.assertEqual(self.feed(mk("45.9.70.2", "/", 200, query="author=1")), [])
        ev = []
        for i in range(2, 9):
            ev += self.feed(mk("45.9.70.3", "/", 200, query="author=%d" % i), 3)
        self.assertEqual(self.kinds(ev), ["challenge"])

    def test_page_flood_is_challenged_but_a_busy_human_is_not(self):
        human = []
        for i in range(40):                       # 40 pages in 60 s is a very busy reader
            human += self.feed(mk("45.9.70.4", "/page%d" % i, 200), 1.5)
        self.assertEqual(human, [])
        bot = []
        for i in range(160):
            bot += self.feed(mk("45.9.70.5", "/item%d" % i, 200), 0.3)
        self.assertEqual(self.kinds(bot), ["challenge"])

    def test_static_assets_do_not_count_as_a_flood(self):
        ev = []
        for i in range(300):                      # one page load fetches many assets quickly
            ev += self.feed(mk("45.9.70.6", "/static/a%d.js" % i, 200), 0.05)
        self.assertEqual(ev, [])

    def test_user_agent_rotation_is_challenged(self):
        ev = []
        for i in range(12):
            ev += self.feed(mk("45.9.70.7", "/page%d" % i, 200, ua="Mozilla/5.0 (X11; Linux) Firefox/%d.0" % (100 + i)), 4)
        self.assertEqual(self.kinds(ev), ["challenge"])
        calm = []
        for i in range(12):                       # same browser, same pages: nothing
            calm += self.feed(mk("45.9.70.8", "/page%d" % i, 200), 4)
        self.assertEqual(calm, [])

    def test_a_hot_slash24_lowers_the_threshold_for_its_neighbours_only(self):
        for i in range(4):                        # four addresses of 45.9.80.0/24 caught
            self.feed(mk("45.9.80.%d" % (i + 1), "/.env", 404))
        self.eng._lists_t = 0

        def light(ip):                            # a few missing pages: harmless on its own (risk about 3.5)
            ev = []
            for i in range(8):
                ev += self.feed(mk(ip, "/m%d" % i, 404), 2)
            return ev
        self.assertEqual(self.kinds(light("45.9.80.50")), ["challenge"])
        self.assertEqual(light("45.9.90.50"), [])  # same behaviour elsewhere: left alone

    def test_credential_stuffing_wave_challenges_unverified_logins_but_not_verified_ones(self):
        for n in range(8):                         # 8 different addresses, 3 failures each = a wave
            for _ in range(3):
                self.feed(mk("45.9.71.%d" % (n + 1), "/wp-login.php", 200, "POST"), 1)
        self.eng._lists_t = 0
        ev = self.feed(mk("45.9.72.1", "/wp-login.php", 200, "POST"))
        self.assertEqual(self.kinds(ev), ["challenge"])
        self.store.pass_challenge("45.9.72.2", self.cfg, self.t)
        self.eng._lists_t = 0
        self.assertEqual(self.feed(mk("45.9.72.2", "/wp-login.php", 200, "POST")), [])
        self.assertEqual(self.feed(mk("45.9.72.3", "/wp-login.php", 302, "POST")), [])   # a successful login (redirect) is never challenged


class TestNotify(unittest.TestCase):
    def test_min_level_and_throttle(self):
        cfg = config.load("/nonexistent.json")
        cfg["notify"]["channels"] = ["webhook"]
        cfg["notify"]["webhook"]["url"] = "http://127.0.0.1:9/x"
        logs = []
        n = notify.Notifier(cfg, {}, log=logs.append, clock=lambda: 1000.0)
        self.assertEqual(n.send("info", "t", "x"), [])             # below min_level
        n2 = notify.Notifier(cfg, {}, log=logs.append, clock=lambda: 1000.0)
        n2.send("alert", "t", "x", key="k")                          # webhook unreachable: logged, never raises
        self.assertTrue(any("webhook failed" in l for l in logs))
        before = len(logs)
        n2.send("alert", "t", "x", key="k")                          # throttled
        self.assertEqual(len(logs), before)

    def test_call_only_for_alerts_and_command_runs_without_shell(self):
        cfg = config.load("/nonexistent.json")
        cfg["notify"]["call"].update(driver="command", to="123", command=sys.executable.replace("\\", "/") + " -c \"import sys;open(sys.argv[1],'w').write(sys.argv[2])\" {to}-out.txt {message}")
        cfg["notify"]["channels"] = ["call"]
        d = tempfile.mkdtemp()
        cwd = os.getcwd()
        os.chdir(d)
        try:
            n = notify.Notifier(cfg, {}, log=lambda m: None)
            n.send("important", "x", "y")
            self.assertFalse(os.path.exists("123-out.txt"))         # important does not ring
            n.send("alert", "Ban; rm -rf /", "text")
            self.assertTrue(os.path.exists("123-out.txt"))           # alert rings; the shell metacharacters stayed a plain argument
            self.assertIn("rm -rf", open("123-out.txt").read())
        finally:
            os.chdir(cwd)


class TestSetupWizard(unittest.TestCase):
    def test_unattended_setup_builds_a_generic_config(self):
        from rmon import cli
        os.environ["RMON_CONFIG"] = os.path.join(tempfile.mkdtemp(), "config.json")
        answers = {"bot_name": "Cerbere", "lang": "fr", "server": "none", "captcha": "3", "site_key": "0xSITE", "captcha_secret": "s3cret",
                   "channels": "ntfy,call", "ntfy_topic": "my-topic", "call_driver": "twilio", "call_to": "+10000000000", "twilio_sid": "ACx", "twilio_from": "+10000000001",
                   "twilio_token": "tok", "ai": "2", "ai_key": "k", "canary": "y", "never_ban": "203.0.113.5, 198.51.100.0/24", "ban_hours": "12"}
        cfg, sec = cli.setup(cli.IO(answers), config.load("/nonexistent.json"), {}, write=False)
        self.assertEqual((cfg["branding"]["bot_name"], cfg["challenge"]["provider"], cfg["guard"]["ban_hours"]), ("Cerbere", "turnstile", 12))
        self.assertEqual(cfg["notify"]["channels"], ["ntfy", "call"])
        self.assertEqual(cfg["guard"]["never_ban"], ["203.0.113.5", "198.51.100.0/24"])
        self.assertEqual((sec["captcha_secret"], sec["twilio_token"], sec["ai_key"]), ("s3cret", "tok", "k"))
        self.assertNotIn("s3cret", json.dumps(cfg))   # secrets never land in config.json
        self.assertEqual(cfg["ai"]["provider"], "mistral")


class TestNet(unittest.TestCase):
    def test_helpers(self):
        self.assertTrue(netutil.is_public("8.8.8.8"))
        self.assertFalse(netutil.is_public("192.168.0.1"))
        self.assertTrue(netutil.in_cloudflare("104.16.1.1"))
        self.assertEqual(netutil.target("2001:db8:1:2::9"), "2001:db8:1:2::/64")
        self.assertTrue(netutil.covers("2001:db8:1:2::/64", "2001:db8:1:2:aaaa::1"))


if __name__ == "__main__":
    unittest.main(verbosity=1)
