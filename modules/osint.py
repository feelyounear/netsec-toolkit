#!/usr/bin/env python3
# modules/osint.py — OSINT tools

import os
import re
import socket
import concurrent.futures
import urllib.parse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from modules.utils import (
    R, DR, W, G, Y, C, GR, RS, B,
    section, ok, info, warn, err, result, pause, get_input, resolve
)


def req_check():
    if not HAS_REQUESTS:
        err("requests not installed. Run: pip install requests")
        pause()
        return False
    return True


# ─────────────────────────────────────────────
#  07  WHOIS LOOKUP
# ─────────────────────────────────────────────

WHOIS_SERVERS = {
    "com":"whois.verisign-grs.com","net":"whois.verisign-grs.com",
    "org":"whois.pir.org","io":"whois.nic.io","co":"whois.nic.co",
    "uk":"whois.nic.uk","de":"whois.denic.de","ru":"whois.tcinet.ru",
    "tr":"whois.nic.tr","nl":"whois.domain-registry.nl",
    "fr":"whois.afnic.fr","eu":"whois.eu","info":"whois.afilias.net",
}

def whois_lookup():
    section("WHOIS LOOKUP")
    target = get_input("Domain or IP")
    target = re.sub(r"^https?://", "", target).split("/")[0]

    tld    = target.split(".")[-1].lower()
    server = WHOIS_SERVERS.get(tld, "whois.iana.org")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((server, 43))
            s.sendall((target + "\r\n").encode())
            raw = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                raw += chunk

        interesting = ["domain","registrar","creation","expir","updated",
                       "name server","status","registrant","country","email",
                       "netname","org","address","abuse","nserver"]
        for line in raw.decode(errors="replace").splitlines():
            ll = line.lower()
            if any(k in ll for k in interesting) and ":" in line:
                key, _, val = line.partition(":")
                val = val.strip()
                if val:
                    result(key.strip()[:22], val[:80])
    except Exception as e:
        err(str(e))

    pause()


# ─────────────────────────────────────────────
#  08  IP GEOLOCATION
# ─────────────────────────────────────────────

def ip_geolocation():
    section("IP GEOLOCATION")
    if not req_check(): return

    target = get_input("IP address or domain")
    ip     = resolve(target)
    if not ip:
        pause(); return

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        d = r.json()
        if d.get("status") == "success":
            fields = ["query","country","regionName","city","zip","lat","lon",
                      "isp","org","as","mobile","proxy","hosting","timezone"]
            labels = ["IP","Country","Region","City","ZIP","Latitude","Longitude",
                      "ISP","Org","ASN","Mobile","Proxy","Hosting","Timezone"]
            for f, l in zip(fields, labels):
                v = d.get(f)
                if v not in (None, "", False):
                    result(l, str(v))
        else:
            err(d.get("message", "Query failed"))
    except Exception as e:
        err(str(e))

    pause()


# ─────────────────────────────────────────────
#  09  SUBDOMAIN FINDER
# ─────────────────────────────────────────────

SUBDOMAIN_WORDLIST = [
    "www","mail","ftp","smtp","pop","imap","webmail","admin","portal",
    "api","dev","staging","test","beta","vpn","remote","ssh","git",
    "gitlab","jenkins","jira","confluence","wiki","shop","store","cdn",
    "static","assets","media","img","images","video","m","mobile","app",
    "dashboard","panel","cpanel","whm","plesk","ns1","ns2","mx","mx1",
    "cloud","s3","bucket","backup","db","database","mysql","redis","mongo",
    "auth","login","sso","oauth","blog","forum","support","help","docs",
    "status","monitor","grafana","kibana","elastic","search","internal",
    "intranet","corp","network","sec","security","proxy","gateway",
    "old","new","v2","v1","api2","stage","uat","preprod","prod",
    "smtp2","mail2","smtp-out","relay","exchange","autodiscover","owa",
]

def subdomain_finder():
    section("SUBDOMAIN FINDER")
    domain = get_input("Target domain (e.g. example.com)")
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    custom = get_input("Extra wordlist file path (blank to skip)")

    words = list(SUBDOMAIN_WORDLIST)
    if custom:
        try:
            with open(custom) as f:
                words += [l.strip() for l in f if l.strip()]
        except Exception as e:
            warn(f"Could not load wordlist: {e}")

    info(f"Bruteforcing {len(words)} subdomains on {domain}")
    print()

    found = []

    def check(sub):
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            return (host, ip)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        for r in ex.map(check, words):
            if r:
                found.append(r)
                ok(f"{r[0]:<45}  {GR}{r[1]}{RS}")

    print(f"\n  \033[31m{'─'*48}\033[0m")
    ok(f"{len(found)} subdomain(s) found") if found else warn("No subdomains found")
    pause()


# ─────────────────────────────────────────────
#  10  EMAIL HEADER ANALYZER
# ─────────────────────────────────────────────

def email_header():
    section("EMAIL HEADER ANALYZER")
    print(f"  {GR}Paste email headers. Type END on a blank line when done.{RS}\n")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)
    raw = "\n".join(lines)

    if not raw.strip():
        warn("No input"); pause(); return

    patterns = {
        "From":             r"^From:\s*(.+)",
        "To":               r"^To:\s*(.+)",
        "Subject":          r"^Subject:\s*(.+)",
        "Date":             r"^Date:\s*(.+)",
        "Message-ID":       r"^Message-ID:\s*(.+)",
        "Reply-To":         r"^Reply-To:\s*(.+)",
        "X-Originating-IP": r"X-Originating-IP:\s*\[?([^\]\s]+)",
        "X-Mailer":         r"X-Mailer:\s*(.+)",
        "User-Agent":       r"User-Agent:\s*(.+)",
        "SPF":              r"spf=(\w+)",
        "DKIM":             r"dkim=(\w+)",
        "DMARC":            r"dmarc=(\w+)",
    }

    for label, pat in patterns.items():
        m = re.search(pat, raw, re.MULTILINE | re.IGNORECASE)
        if m:
            result(label, m.group(1).strip()[:80])

    private    = {"10.", "172.", "192.168.", "127.", "::1"}
    ips        = list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)))
    public_ips = [i for i in ips if not any(i.startswith(p) for p in private)]
    if public_ips:
        print(f"\n  {C}[*]{RS} Public IPs in headers:")
        for ip in public_ips:
            print(f"      {W}{ip}{RS}")

    pause()


# ─────────────────────────────────────────────
#  11  USERNAME LOOKUP
# ─────────────────────────────────────────────

USERNAME_SITES = [
    ("GitHub",     "https://github.com/{}"),
    ("GitLab",     "https://gitlab.com/{}"),
    ("Twitter/X",  "https://twitter.com/{}"),
    ("Instagram",  "https://www.instagram.com/{}"),
    ("Reddit",     "https://www.reddit.com/user/{}"),
    ("TikTok",     "https://www.tiktok.com/@{}"),
    ("YouTube",    "https://www.youtube.com/@{}"),
    ("Twitch",     "https://www.twitch.tv/{}"),
    ("Steam",      "https://steamcommunity.com/id/{}"),
    ("Pastebin",   "https://pastebin.com/u/{}"),
    ("Medium",     "https://medium.com/@{}"),
    ("Dev.to",     "https://dev.to/{}"),
    ("Keybase",    "https://keybase.io/{}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("Pinterest",  "https://www.pinterest.com/{}"),
    ("Flickr",     "https://www.flickr.com/people/{}"),
    ("Vimeo",      "https://vimeo.com/{}"),
    ("Soundcloud", "https://soundcloud.com/{}"),
    ("Replit",     "https://replit.com/@{}"),
    ("Codepen",    "https://codepen.io/{}"),
]

def username_lookup():
    section("USERNAME LOOKUP")
    if not req_check(): return

    username = get_input("Username to search")
    info(f"Searching {len(USERNAME_SITES)} platforms for '{username}'")
    print()

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    def check_site(entry):
        name, url_tmpl = entry
        url = url_tmpl.format(username)
        try:
            r = requests.get(url, headers=headers, timeout=8,
                             allow_redirects=True, verify=False)
            if r.status_code == 200:
                return (name, url, True)
            return (name, url, False)
        except Exception:
            return (name, url, None)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for name, url, found in ex.map(check_site, USERNAME_SITES):
            if found is True:
                print(f"  {G}[+]{RS}  {W}{name:<15}{RS}  {GR}{url}{RS}")
            elif found is None:
                print(f"  {Y}[?]{RS}  {GR}{name:<15}  timeout{RS}")

    pause()


# ─────────────────────────────────────────────
#  12  DORKING ENGINE
# ─────────────────────────────────────────────

DORK_TEMPLATES = {
    "1":  ("Admin panels",     "site:{0} intitle:\"admin\" OR intitle:\"login\" OR intitle:\"dashboard\""),
    "2":  ("Exposed files",    "site:{0} ext:log OR ext:sql OR ext:env OR ext:bak"),
    "3":  ("Config leaks",     "site:{0} ext:xml OR ext:conf OR ext:cnf inurl:config"),
    "4":  ("Open directories", "site:{0} intitle:\"index of\" OR intitle:\"directory listing\""),
    "5":  ("Email addresses",  "site:{0} intext:\"@{0}\""),
    "6":  ("Subdomains",       "site:*.{0}"),
    "7":  ("Cameras",          "site:{0} inurl:view/view.shtml OR inurl:ViewerFrame"),
    "8":  ("Git exposed",      "site:{0} inurl:.git OR intitle:\"index of\" \".git\""),
    "9":  ("PHP errors",       "site:{0} \"Fatal error\" OR \"Warning: include\" OR \"syntax error\""),
    "10": ("WordPress",        "site:{0} inurl:wp-content OR inurl:wp-admin"),
    "11": ("Juicy files",      "site:{0} ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx"),
    "12": ("Login pages",      "site:{0} inurl:login OR inurl:signin OR inurl:auth"),
}

def dorking_engine():
    section("DORKING ENGINE")
    domain = get_input("Target domain (e.g. example.com)")
    domain = re.sub(r"^https?://", "", domain).split("/")[0]
    print()
    for k, (name, _) in DORK_TEMPLATES.items():
        print(f"  {R}[{k:>2}]{RS} {name}")
    print()
    choice = get_input("Select dork number or 'all'")

    if choice.lower() == "all":
        targets = list(DORK_TEMPLATES.items())
    elif choice in DORK_TEMPLATES:
        targets = [(choice, DORK_TEMPLATES[choice])]
    else:
        err("Invalid choice"); pause(); return

    print()
    for k, (name, template) in targets:
        query   = template.format(domain)
        encoded = urllib.parse.quote_plus(query)
        url     = f"https://www.google.com/search?q={encoded}"
        print(f"  {C}[{name}]{RS}")
        print(f"  {GR}Query:{RS} {query}")
        print(f"  {GR}URL:  {RS} {url}")
        print()

    pause()
