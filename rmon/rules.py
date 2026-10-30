"""Detection rules: trap paths, user-agent anomalies, and the bot-probability model used by the challenge.
Everything here is generic: nothing refers to any specific site."""
import math
import re

# --- certain detections: no real visitor ever requests these on a normal site (anything served here is a scanner) ---------------
TRAP_SUBSTR = (
    "/.env", "/.git", "/wp-config", "/phpmyadmin", "/pma/", "/vendor/phpunit", "/.aws", "/.ssh", "/id_rsa", "/adminer", "/.htpasswd", "/server-status",
    "/actuator", "/.ds_store", "/cgi-bin/", "/shell.php", "/c99.php", "/wso.php", "/.bash_history", "/.npmrc", "/.docker", "/.vscode", "/.idea", "/.svn",
    "/.hg/", "/hnap1", "/boaform", "/_profiler", "/telescope/", "/wp-content/debug.log", "/config.php.bak", "/.git-credentials", "/web.config.bak",
    "/backup-db", "/sftp-config.json", "/.circleci", "/.gitlab-ci", "/.kube/", "/.terraform", "/terraform.tfstate", "/.mysql_history", "/.zsh_history",
    "/.viminfo", "/.dockerenv", "/docker-compose", "/_ignition/", "/containers/json", "/manager/html", "/jmx-console", "/solr/", "/jenkins/",
    "/api/v1/namespaces", "/owa/auth", "/autodiscover/autodiscover.xml", "/remote/login", "/dana-na/", "/global-protect/", "/+cscoe+/", "/winnt/",
    "/web-inf/", "/config/database.yml", "/database.yml", "/appsettings.json", "/.git-rewrite", "/.hgignore", "/.bzr/", "/.cvs",
)
# Generic names only count when they are the WHOLE path (otherwise they would catch a plugin's own info.php)
TRAP_EXACT = frozenset((
    "/phpinfo.php", "/info.php", "/pi.php", "/php.php", "/i.php", "/.htaccess", "/.htpasswd", "/.user.ini", "/.profile", "/.bashrc", "/id_dsa", "/id_ecdsa",
    "/id_ed25519", "/credentials", "/.aws/credentials", "/passwords.txt", "/password.txt", "/credentials.txt", "/secrets.env", "/secrets.json", "/secret.json",
    "/backup.sh", "/adminer.php", "/shell.php", "/cmd.php",
))
TRAP_ROOTFILE = re.compile(r"^/[^/]*\.(sql|bak|old|zip|tar|tgz|gz|7z|rar)$")
PHP_UPLOADS = re.compile(r"/(wp-content/)?uploads?/.*\.(php|phtml|phar|php5|php7|pht)$")
INJECTION = re.compile(r"(?i)(union(%20|\+|\s)+(all(%20|\+|\s)+)?select|information_schema|sleep\((%20)?[0-9]|benchmark\(|load_file\(|into(%20|\+)outfile|%3cscript|<script|"
                       r"javascript:|base64_decode|eval\(|php://|data://|expect://|/etc/passwd|\.\./|%2e%2e)")
SCANNER_UA = re.compile(r"(?i)(sqlmap|nikto|nmap|masscan|acunetix|wpscan|nuclei|dirbuster|gobuster|zgrab|jaeles|havij|nessus|openvas)")

# --- ambiguous detections (a human can trigger them): they lead to a captcha challenge, never directly to a ban ---------------------
SOFT_PREFIXES = ("scan (", "force brute", "bouclier", "risk", "login")

BOT_UA = re.compile(r"(?i)(python-requests|python-urllib|aiohttp|httpx|curl/|wget/|go-http-client|okhttp|libwww|java/|apache-httpclient|axios|node-fetch|scrapy|headless|"
                    r"phantomjs|selenium|puppeteer|playwright|mechanize|httpclient|zgrab|masscan)")
GOOD_UA = re.compile(r"(?i)(googlebot|bingbot|bingpreview|applebot|duckduckbot|yandex|baiduspider|facebookexternalhit|jetpack|wordpress|uptimerobot|statuscake|pingdom|cloudflare|mj12bot)")


def is_soft(kind):
    return str(kind or "").startswith(SOFT_PREFIXES)


def path_trap(path, extra_substr=(), extra_exact=(), allow=()):
    p = path.lower()
    if any(p.startswith(a.lower()) for a in allow):
        return False
    return (any(s in p for s in TRAP_SUBSTR) or any(s.lower() in p for s in extra_substr) or bool(TRAP_ROOTFILE.match(p)) or p in TRAP_EXACT
            or p in {x.lower() for x in extra_exact})


def ua_anomaly(ua, al="", sua=""):
    """0 (ordinary browser) .. 2 (almost surely a script). Weights requests; never blocks on its own."""
    if not ua:
        return 1.0
    if BOT_UA.search(ua):
        return 0.8
    a = 0.0
    if ua.startswith("Mozilla/"):
        if not al:
            a += 0.6
        m = re.search(r"Chrome/(\d+)", ua)
        if m and int(m.group(1)) >= 90 and not sua and not re.search(r"CriOS|FxiOS|EdgiOS|; wv\)|OPR/|Googlebot|bingbot", ua):
            a += 0.5   # modern Chrome always sends client hints over HTTPS
    return min(a, 2.0)


def bot_prob(f, score, step, prior):
    """Probability (0-1) that the visitor is a robot: captcha score + browser environment + behaviour + history.
    Fixed-weight logistic regression: readable, no black box. `f` holds numbers only (counters and trajectory measures)."""
    f = f if isinstance(f, dict) else {}

    def num(k, lo, hi):
        v = f.get(k, 0)
        return min(max(float(v), lo), hi) if isinstance(v, (int, float, bool)) else 0.0

    s = min(max(float(score), 0.0), 1.0) if isinstance(score, (int, float)) else 0.5
    L = -2.0 + 4.0 * (0.9 - s)
    flags = []
    for k, w, name in (("wd", 3.0, "webdriver"), ("hl", 1.5, "headless"), ("sw", 1.2, "software_gl")):
        if num(k, 0, 1):
            L += w
            flags.append(name)
    if num("ut", 0, 1000) > 0:
        L += 3.0
        flags.append("synthetic_events")
    if num("mc", 0, 1e5) + num("tc", 0, 1e5) + num("kc", 0, 1e5) + num("sc", 0, 1e5) + num("clk", 0, 1000) == 0:
        L += 0.6
    if num("mmn", 0, 1000) >= 8:
        straight, cv = num("mms", 0, 1), num("mmv", 0, 10)
        if straight > 0.985 and cv < 0.12:
            L += 3.0
            flags.append("robotic_mouse")
        elif straight < 0.92 and cv > 0.25:
            L -= 1.0
            flags.append("human_mouse")
    if num("tc", 0, 1e5) > 0:
        L -= 0.8
    if num("kc", 0, 1e5) > 0:
        L -= 0.5
    if step >= 2 and num("clk", 0, 1000) > 0:
        L -= 1.2
        flags.append("confirmed_click")
    if 0 < num("dt", 0, 600000) < 150:
        L += 1.5
        flags.append("too_fast")
    L += 0.7 * min(max(int(prior or 0), 0), 3)
    return 1.0 / (1.0 + math.exp(-L)), flags
