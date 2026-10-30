"""IP helpers shared by the guard, the stores and the backends."""
import ipaddress

# Cloudflare edge ranges: requests arrive from these, the real client is in CF-Connecting-IP. We never ban an edge.
CLOUDFLARE = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 "
    "197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 "
    "2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32").split()]

# Search-engine crawlers' published ranges would go here; real crawlers are also verified by reverse DNS in guard.is_good_crawler().


def parse_ip(s):
    try:
        return ipaddress.ip_address(str(s).strip())
    except ValueError:
        return None


def is_public(ip):
    a = parse_ip(ip)
    return bool(a and a.is_global and not a.is_multicast)


def in_cloudflare(ip):
    a = parse_ip(ip)
    return bool(a and any(a in n for n in CLOUDFLARE if n.version == a.version))


def parse_nets(items):
    nets = []
    for x in items or []:
        try:
            nets.append(ipaddress.ip_network(str(x).strip(), strict=False))
        except ValueError:
            pass
    return nets


def in_nets(ip, nets):
    a = parse_ip(ip)
    return bool(a and any(a in n for n in nets if n.version == a.version))


def target(ip):
    """What a ban applies to: an IPv4 address, or the whole /64 of an IPv6 address (attackers rotate inside their /64)."""
    a = parse_ip(ip)
    if a is None:
        return None
    return str(ipaddress.ip_network("%s/64" % a, strict=False)) if a.version == 6 else str(a)


def covers(tgt, ip):
    a, n = parse_ip(ip), None
    try:
        n = ipaddress.ip_network(tgt, strict=False)
    except ValueError:
        return False
    return bool(a and a.version == n.version and a in n)
