#!/usr/bin/env python3
"""
ClamAV Antivirus GUI — contrôle des liens et des courriels (service système).

Les extensions (Thunderbird, Firefox, Chrome, Chromium, Edge, Brave) interrogent le service par l'hôte de messagerie
native avant d'ouvrir un lien ou d'afficher un courriel. Le service répond avec un verdict (sûr, prudence, danger) et
ses raisons :
  - listes de sites malveillants, téléchargées depuis GitHub et abuse.ch et rangées dans des index compacts
    (empreintes triées de 8 octets, ~4 Mo pour 500 000 domaines) : OpenPhish, URLhaus, Phishing.Database ;
  - heuristiques sans liste : adresse IP brute, identifiant dans l'adresse (« paypal.com@evil.ru »), punycode,
    marque connue imitée (sosie, caractères remplacés, faute de frappe, marque en sous-domaine d'un autre domaine),
    raccourcisseur d'adresse (destination résolue puis contrôlée à son tour), page de connexion sans chiffrement,
    téléchargement d'exécutable, lien dont le texte affiché est une autre adresse que la cible (courriels).
Les sites autorisés par l'utilisateur (« Toujours autoriser ») ne sont plus signalés. Rien n'est envoyé ailleurs
qu'aux serveurs des listes (téléchargement) et, pour un raccourcisseur, au raccourcisseur lui-même.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import bisect
import hashlib
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

USER_AGENT = "ClamAV-Antivirus-GUI/urlguard (+https://www.dukiwi.com)"
HASH_LEN = 8
EVENTS_MAX = 120
CLIENTS = ("thunderbird", "firefox", "chrome", "chromium", "edge", "brave")

# ── Listes de sites malveillants (GitHub, abuse.ch) ───────────────────────────
FEEDS = [
    {"name": "openphish", "label": "OpenPhish", "kind": "urls", "interval": 6 * 3600,
     "url": "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
     "home": "https://github.com/openphish/public_feed"},
    {"name": "urlhaus", "label": "URLhaus (abuse.ch)", "kind": "urls", "interval": 6 * 3600,
     "url": "https://urlhaus.abuse.ch/downloads/text_online/", "home": "https://urlhaus.abuse.ch/"},
    {"name": "phishing_db", "label": "Phishing.Database", "kind": "domains", "interval": 7 * 86400,
     "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "home": "https://github.com/Phishing-Database/Phishing.Database"},
    {"name": "phishing_db_new", "label": "Phishing.Database (nouveaux)", "kind": "domains", "interval": 6 * 3600,
     "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt",
     "home": "https://github.com/Phishing-Database/Phishing.Database"},
]

# Plates-formes partagées : seule l'adresse exacte compte (un hôte entier n'est jamais « malveillant »)
SHARED_HOSTS = {
    "cdn.discordapp.com", "discord.com", "github.com", "raw.githubusercontent.com", "gist.github.com", "drive.google.com",
    "docs.google.com", "sites.google.com", "storage.googleapis.com", "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com",
    "onedrive.live.com", "1drv.ms", "sharepoint.com", "box.com", "mega.nz", "mediafire.com", "wetransfer.com", "we.tl",
    "pastebin.com", "archive.org", "t.me", "telegram.me", "bitbucket.org", "gitlab.com", "sourceforge.net", "amazonaws.com",
    "s3.amazonaws.com", "blob.core.windows.net", "web.app", "firebaseapp.com", "pages.dev", "netlify.app", "vercel.app",
    "weebly.com", "wixsite.com", "000webhostapp.com", "github.io", "blogspot.com", "wordpress.com", "notion.site", "canva.site",
    "typedream.app", "webflow.io", "glitch.me", "repl.co", "herokuapp.com", "cloudfront.net", "r2.dev", "workers.dev",
}
SHARED_SUFFIXES = tuple("." + h for h in SHARED_HOSTS)

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "rebrand.ly", "t.ly", "s.id", "lnkd.in", "bl.ink", "short.io", "v.gd", "qrco.de", "clck.ru", "u.to", "urlz.fr",
    "lc.cx", "frama.link", "tr.im", "x.co", "snip.ly", "soo.gd", "zpr.io", "shorte.st", "adf.ly", "ouo.io", "1url.cz", "urlr.me",
}

# Marques imitées par l'hameçonnage : nom → domaines légitimes (le vrai site n'est jamais signalé)
BRANDS = {
    "paypal": ["paypalobjects.com", "paypal-communication.com", "paypal-community.com", "paypal-prepaid.com", "paypal.com", "paypal.ch", "paypal.me"],
    "microsoft": ["msftconnecttest.com", "msauth.net", "msecnd.net", "microsoftstore.com", "windows.com", "windowsupdate.com", "skype.com", "visualstudio.com", "microsoft.design", "microsoft.dev", "msftauth.net", "microsoftpersonalcontent.com", "office.net", "onenote.com", "teams.microsoft.com", "microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com", "msn.com", "azure.com", "sharepoint.com", "onedrive.com", "bing.com", "xbox.com"],
    "office365": ["office365.com", "office.com", "microsoft.com"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com"],
    "google": ["google-analytics.com", "googletagmanager.com", "googleadservices.com", "googlesyndication.com", "doubleclick.net", "googlevideo.com", "gstatic.com", "ggpht.com", "google.dev", "google.ca", "google.co.uk", "google.es", "google.nl", "google.be", "google.at", "google.com", "google.ch", "google.fr", "google.de", "google.it", "googleapis.com", "googleusercontent.com", "gmail.com", "youtube.com", "goo.gl", "g.co", "withgoogle.com"],
    "gmail": ["gmail.com", "google.com"],
    "apple": ["apple-cloudkit.com", "apple-dns.net", "mzstatic.com", "apple-mapkit.com", "apple.news", "apple-livephotoskit.com", "apple.com", "icloud.com", "apple.ch", "me.com", "mac.com"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon-adsystem.com", "media-amazon.com", "ssl-images-amazon.com", "amazonpay.com", "amazon.jobs", "amazon.es", "amazon.nl", "amazon.ca", "amazon.at", "amazon.com", "amazon.de", "amazon.fr", "amazon.it", "amazon.co.uk", "amazon.ch", "amazonaws.com", "amzn.to", "amzn.com", "primevideo.com"],
    "netflix": ["netflix.net", "netflix.com", "nflxext.com", "nflximg.net"],
    "facebook": ["fbsbx.com", "facebook.com", "fb.com", "fb.me", "fbcdn.net", "messenger.com", "meta.com"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "linkedin": ["linkedin.com", "lnkd.in", "licdn.com"],
    "twitter": ["twitter.co", "twitter.com", "x.com", "t.co", "twimg.com"],
    "dropbox": ["dropboxstatic.com", "dropbox.com", "dropboxusercontent.com", "db.tt"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobelogin.com", "typekit.net", "adobe.ly", "adobe.com", "adobe.io", "acrobat.com"],
    "zoom": ["zoomgov.com", "zoom.us", "zoom.com"],
    "dhl": ["dhl.com", "dhl.de", "dhl.ch", "dhl.fr", "dhl.it", "dhlparcel.com", "dhlexpress.com"],
    "ups": ["ups.com"],
    "fedex": ["fedex.com"],
    "laposte": ["laposte.fr", "laposte.net"],
    "chronopost": ["chronopost.fr"],
    "postfinance": ["postfinance.ch"],
    "swisspost": ["post.ch", "swisspost.ch"],
    "ubs": ["ubs.com", "ubs.ch"],
    "raiffeisen": ["raiffeisen.ch", "raiffeisen.com", "raiffeisen.at"],
    "zkb": ["zkb.ch"],
    "bcv": ["bcv.ch"],
    "creditsuisse": ["credit-suisse.com", "credit-suisse.ch"],
    "revolut": ["revolut.com"],
    "twint": ["twint.ch"],
    "swisscom": ["swisscom.ch", "swisscom.com", "bluewin.ch"],
    "bluewin": ["bluewin.ch", "swisscom.ch"],
    "sunrise": ["sunrise.ch", "sunrise.net"],
    "salt": ["salt.ch"],
    "infomaniak": ["infomaniak.com", "infomaniak.ch", "ik-server.com", "ikoula.com"],
    "sbb": ["sbb.ch"],
    "cff": ["cff.ch", "sbb.ch"],
    "migros": ["migros.ch", "migrosbank.ch"],
    "coop": ["coop.ch"],
    "digitec": ["digitec.ch", "galaxus.ch"],
    "galaxus": ["galaxus.ch", "galaxus.de", "digitec.ch"],
    "ricardo": ["ricardo.ch"],
    "zalando": ["zalando.ch", "zalando.fr", "zalando.de", "zalando.it"],
    "spotify": ["spotifycdn.com", "spotify.com", "scdn.co"],
    "steam": ["steamserver.net", "steam-chat.com", "steampowered.com", "steamcommunity.com", "steamgames.com", "steamstatic.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "ledger": ["ledger.com"],
    "metamask": ["metamask.io"],
    "github": ["github.com", "github.io", "githubusercontent.com"],
    "chatgpt": ["chatgpt.com", "openai.com"],
    "openai": ["openai.com", "chatgpt.com"],
    "wetransfer": ["wetransfer.com", "we.tl"],
    "orange": ["orange.fr", "orange.com", "orange.ch"],
    "bouygues": ["bouyguestelecom.fr", "bbox.fr"],
    "sfr": ["sfr.fr"],
    "free": ["free.fr", "freebox.fr"],
    "impots": ["impots.gouv.fr"],
    "ameli": ["ameli.fr"],
    "caf": ["caf.fr"],
    "antai": ["antai.gouv.fr"],
    "admin": ["admin.ch"],
    "ch-portal": ["ch.ch"],
}
BRAND_MIN_LEN = 4
# Touches voisines (QWERTZ, QWERTY et AZERTY confondus) et lettres visuellement proches : « amazom », « paypai »
KEY_NEIGHBOURS = {"q": "wasz", "w": "qeasdzx", "e": "wrsdf", "r": "etdfg", "t": "ryfgh", "y": "tughj", "u": "yihjk", "i": "uojkl", "o": "ipkl",
                  "p": "ol", "a": "qwszx", "s": "awedzxc", "d": "serfxcv", "f": "drtgcvb", "g": "ftyhvbn", "h": "gyujbnm", "j": "huiknm",
                  "k": "jiolm", "l": "kopm", "z": "asxwy", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njkl"}
LOOKALIKES = {"i": "lj1y", "l": "i1j", "o": "0ae", "e": "3ao", "a": "4eo", "s": "5z", "t": "7f", "b": "8d", "g": "9q", "u": "vn", "v": "u",
              "n": "mu", "m": "n", "c": "e", "d": "b", "q": "g", "y": "i", "z": "s", "k": "x"}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "|": "l", "$": "s"})
LOGIN_RE = re.compile(r"(login|log-in|signin|sign-in|logon|verify|verification|secure|security|account|wallet|password|passwd|"
                      r"update|confirm|billing|invoice|payment|unlock|suspend|validate|auth|session|recover|identity|kyc)", re.I)
EXE_RE = re.compile(r"\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|msi|msp|hta|jar|apk|dll|cpl|lnk|iso|img|vhd|reg|sh|run|deb|rpm|appimage)(\?|$)", re.I)
SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "work", "click", "link", "icu", "cam", "rest",
                   "monster", "quest", "buzz", "sbs", "cfd", "bond", "lol", "fun", "live", "online", "site", "website", "space",
                   "club", "pw", "cc", "ws", "su", "ru", "cn", "ir", "kp"}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "gouv", "or", "ne", "go", "mil"}
URL_LIKE_RE = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#]|$)", re.I)


def _iso(ts=None):
    return datetime.fromtimestamp(ts or time.time()).isoformat(timespec="seconds")


def _parse_iso(s):
    try:
        return datetime.fromisoformat(s).timestamp()
    except (TypeError, ValueError):
        return 0.0


def hash8(text):
    return hashlib.sha1(text.encode("utf-8", errors="replace")).digest()[:HASH_LEN]


class HashIndex:
    """Ensemble compact de chaînes : empreintes de 8 octets triées, recherche dichotomique (4 Mo pour 500 000 entrées)."""

    def __init__(self, blob=b""):
        self.blob = blob
        self.count = len(blob) // HASH_LEN

    @classmethod
    def build(cls, items):
        hashes = sorted({hash8(i) for i in items})
        return cls(b"".join(hashes))

    def __contains__(self, text):
        if not self.count:
            return False
        h = hash8(text)
        lo, hi = 0, self.count
        while lo < hi:
            mid = (lo + hi) // 2
            cur = self.blob[mid * HASH_LEN:(mid + 1) * HASH_LEN]
            if cur < h:
                lo = mid + 1
            elif cur > h:
                hi = mid
            else:
                return True
        return False

    def __len__(self):
        return self.count


# ── Analyse d'une adresse ─────────────────────────────────────────────────────
def registered_domain(host):
    """Domaine enregistré approché : deux étiquettes, trois si la deuxième est un second niveau (co.uk, com.au, gouv.fr)."""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if labels[-2] in SECOND_LEVEL and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _typo_of(candidate, brand):
    """Faute de frappe typique d'un sosie : une lettre substituée (jamais la première : « finance » n'est pas
    « binance »), ou une lettre doublée en plus ou en moins (« paypall », « gooogle », « goggle »)."""
    if candidate == brand:
        return False
    la, lb = len(candidate), len(brand)
    if la == lb:
        diffs = [i for i, (x, y) in enumerate(zip(candidate, brand)) if x != y]
        if len(diffs) != 1 or diffs[0] == 0:
            return False
        got, want = candidate[diffs[0]], brand[diffs[0]]
        return got in KEY_NEIGHBOURS.get(want, "") or got in LOOKALIKES.get(want, "")      # touche voisine ou lettre proche
    if abs(la - lb) != 1:
        return False
    longer, shorter = (candidate, brand) if la > lb else (brand, candidate)
    for i in range(len(longer)):
        if longer[:i] + longer[i + 1:] == shorter:
            return (i > 0 and longer[i] == longer[i - 1]) or (i + 1 < len(longer) and longer[i] == longer[i + 1])
    return False


BRAND_KEYWORDS = ("login", "secure", "support", "verify", "account", "update", "help", "service", "team", "pay", "wallet", "id",
                  "auth", "signin", "mail", "billing", "alert", "security", "center", "online", "portal", "customer", "client")


def brand_check(host):
    """Imitation d'une marque connue → (raison, marque) ou None. Le vrai domaine de la marque n'est jamais signalé.
    Danger direct : domaine légitime placé en tête d'un autre hôte (« paypal.com.secure-login.ru ») et caractères
    remplacés (« paypa1 », « rnicrosoft ») ; les autres imitations sont de la prudence, danger avec une page de connexion."""
    reg = registered_domain(host)
    labels = host.split(".")
    for brand, legit in BRANDS.items():
        if reg in legit or any(host == d or host.endswith("." + d) for d in legit):
            return None
    dotted = f".{host}."
    for brand, legit in BRANDS.items():
        if any(f".{d}." in dotted and not host.endswith(d) for d in legit):
            return "brand_domain_prefix", brand                   # paypal.com.secure-login.ru, help.steampowered.com.im
    sld = reg.split(".")[0]
    normalized = sld.translate(HOMOGLYPHS).replace("rn", "m").replace("vv", "w")
    shared = reg in SHARED_HOSTS
    for brand, legit in BRANDS.items():
        if len(brand) < BRAND_MIN_LEN:
            continue
        if sld == brand and not shared:
            return "brand_other_tld", brand                        # paypal.xyz
        if normalized == brand and sld != brand:
            return "homoglyph", brand                              # paypa1.com, rnicrosoft.com
        if len(brand) >= 6 and _typo_of(sld, brand) and not shared:
            return "typosquat", brand                              # paypall.com, amazom.com
        subs = labels[:-len(reg.split("."))]
        if not shared and any(label == brand or label.startswith(brand + "-") or label.endswith("-" + brand) for label in subs):
            return "brand_in_subdomain", brand                     # paypal.evil.com, login-paypal.evil.com
        if sld != brand and (sld.startswith(brand + "-") or sld.endswith("-" + brand)
                             or any(sld in (brand + k, k + brand, f"{brand}-{k}", f"{k}-{brand}") for k in BRAND_KEYWORDS)):
            return "brand_combo", brand                            # paypal-secure.com, applesupport.net
    return None


def _host_of(url):
    try:
        p = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return "", None
    host = (p.hostname or "").lower().rstrip(".")
    return host, p


def norm_url_variants(url):
    """Formes comparées aux listes : sans schéma, avec/sans www., avec/sans barre finale, sans fragment."""
    try:
        p = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return []
    host = (p.hostname or "").lower()
    if not host:
        return []
    port = f":{p.port}" if p.port and p.port not in (80, 443) else ""
    path = p.path or "/"
    query = f"?{p.query}" if p.query else ""
    out = set()
    for h in {host, host[4:] if host.startswith("www.") else "www." + host}:
        base = f"{h}{port}{path}{query}"
        out.add(base)
        out.add(base.rstrip("/") if path != "/" or query else base)
        if path == "/" and not query:
            out.add(f"{h}{port}")
    return [v for v in out if v]


def analyze(url, context=None):
    """Heuristiques sans liste → (reasons, meta). context : {text, sender} (courriels)."""
    reasons = []
    meta = {}
    host, p = _host_of(url)
    if p is None:
        return ["malformed"], meta
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        if scheme in ("javascript", "data", "vbscript", "file"):
            reasons.append("dangerous_scheme")
        return reasons, meta
    if not host:
        return ["malformed"], meta
    meta["host"] = host
    if p.username is not None or "@" in (p.netloc or ""):
        reasons.append("userinfo")
    try:
        ipaddress.ip_address(host)
        reasons.append("ip_host")
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip:
        labels = host.split(".")
        if any(label.startswith("xn--") for label in labels):
            reasons.append("punycode")
        if len(labels) >= 6:
            reasons.append("many_subdomains")
        tld = labels[-1]
        if tld in SUSPICIOUS_TLDS:
            meta["suspicious_tld"] = tld
        bc = brand_check(host)
        if bc:
            reasons.append(bc[0])
            meta["brand"] = bc[1]
        if registered_domain(host) in SHORTENERS or host in SHORTENERS:
            reasons.append("shortener")
    path_q = f"{p.path}?{p.query}"
    if EXE_RE.search(p.path or ""):
        reasons.append("executable_download")
    login = bool(LOGIN_RE.search(path_q))
    if login and scheme == "http":
        reasons.append("insecure_login")
    if login and (meta.get("suspicious_tld") or is_ip):
        reasons.append("phishing_pattern")
    if login and not is_ip and not meta.get("brand"):
        # marque citée dans le chemin ou les paramètres d'un domaine qui n'est pas le sien : « /paypal/login »
        low = path_q.lower()
        for brand, legit in BRANDS.items():
            if len(brand) >= 5 and brand in low and not any(host == d or host.endswith("." + d) for d in legit):
                reasons.append("brand_in_path")
                meta["brand"] = brand
                break
    ctx = context or {}
    text = str(ctx.get("text") or "").strip()
    m = URL_LIKE_RE.match(text)
    if m and not is_ip:
        shown = m.group(1).lower()
        if registered_domain(shown) != registered_domain(host) and "." in shown:
            reasons.append("masked_link")
            meta["shown_host"] = shown
    return reasons, meta


DANGER_REASONS = {"dangerous_scheme", "userinfo", "homoglyph", "brand_domain_prefix", "masked_link", "phishing_pattern",
                  "list_phishing", "list_malware", "shortener_danger", "brand_login"}
BRAND_WARN = {"typosquat", "brand_in_subdomain", "brand_other_tld", "brand_combo", "brand_in_path"}
WARN_REASONS = {"ip_host", "punycode", "many_subdomains", "shortener", "insecure_login", "executable_download", "list_malware_host",
                "malformed"} | BRAND_WARN


class UrlGuard:
    """Index des listes + heuristiques + journal. `daemon` fournit state, settings, write_log, publish_alert, broadcast."""

    def __init__(self, daemon, data_dir, log=print):
        self.daemon = daemon
        self.dir = data_dir
        self.log = log
        self.lock = threading.Lock()
        self.indexes = {}            # name → HashIndex
        self.hosts = {}              # name → HashIndex des hôtes (listes d'adresses)
        self.meta = {}               # name → {count, fetched_at, error, etag, last_modified, hosts}
        self.refreshing = False
        self.last_attempt = {}
        saved = daemon.state.get("urlguard") or {}
        self.events = list(saved.get("events") or [])[:EVENTS_MAX]
        self.clients = dict(saved.get("clients") or {})
        self.counters = dict(saved.get("counters") or {})
        self.allowed = dict(saved.get("allowed") or {})       # host → {t, by}
        os.makedirs(self.dir, exist_ok=True)
        self._load_indexes()

    # ── Index sur disque ─────────────────────────────────────────────────
    def _paths(self, name):
        return os.path.join(self.dir, f"{name}.idx"), os.path.join(self.dir, f"{name}.hosts.idx"), os.path.join(self.dir, f"{name}.json")

    def _load_indexes(self):
        for feed in FEEDS:
            idx, hidx, meta = self._paths(feed["name"])
            try:
                with open(meta, encoding="utf-8") as f:
                    self.meta[feed["name"]] = json.load(f)
                with open(idx, "rb") as f:
                    self.indexes[feed["name"]] = HashIndex(f.read())
                if os.path.exists(hidx):
                    with open(hidx, "rb") as f:
                        self.hosts[feed["name"]] = HashIndex(f.read())
            except (OSError, ValueError):
                self.meta.setdefault(feed["name"], {"count": 0, "fetched_at": None, "error": ""})

    def feeds_stale(self):
        now = time.time()
        for feed in FEEDS:
            m = self.meta.get(feed["name"]) or {}
            if now - _parse_iso(m.get("fetched_at")) > feed["interval"] and now - self.last_attempt.get(feed["name"], 0) > 1800:
                return True
        return False

    def refresh(self, force=False):
        """Télécharge les listes dont l'intervalle est écoulé (requêtes conditionnelles ETag / Last-Modified)."""
        if self.refreshing:
            return self.feed_status()
        self.refreshing = True
        try:
            now = time.time()
            for feed in FEEDS:
                name = feed["name"]
                m = dict(self.meta.get(name) or {})
                if not force and now - _parse_iso(m.get("fetched_at")) < feed["interval"]:
                    continue
                if not force and now - self.last_attempt.get(name, 0) < 1800:
                    continue
                self.last_attempt[name] = now
                headers = {"User-Agent": USER_AGENT}
                if m.get("etag"):
                    headers["If-None-Match"] = m["etag"]
                if m.get("last_modified"):
                    headers["If-Modified-Since"] = m["last_modified"]
                try:
                    req = urllib.request.Request(feed["url"], headers=headers)
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        data = resp.read()
                        etag = resp.headers.get("ETag", "")
                        last_mod = resp.headers.get("Last-Modified", "")
                except urllib.error.HTTPError as e:
                    if e.code == 304:
                        m["fetched_at"] = _iso(now)
                        m["error"] = ""
                        self._save_meta(name, m)
                        continue
                    m["error"] = f"HTTP {e.code}"
                    self._save_meta(name, m)
                    self.log(f"Liste {name} : HTTP {e.code}")
                    continue
                except (OSError, ValueError) as e:
                    m["error"] = str(e)[:120]
                    self._save_meta(name, m)
                    self.log(f"Liste {name} : {e}")
                    continue
                entries, hosts = self._parse_feed(feed, data)
                index = HashIndex.build(entries)
                hindex = HashIndex.build(hosts) if hosts else None
                idx, hidx, _ = self._paths(name)
                try:
                    with open(idx + ".tmp", "wb") as f:
                        f.write(index.blob)
                    os.replace(idx + ".tmp", idx)
                    if hindex:
                        with open(hidx + ".tmp", "wb") as f:
                            f.write(hindex.blob)
                        os.replace(hidx + ".tmp", hidx)
                except OSError as e:
                    self.log(f"Liste {name} : écriture : {e}")
                with self.lock:
                    self.indexes[name] = index
                    if hindex:
                        self.hosts[name] = hindex
                m.update({"count": len(index), "hosts": len(hindex) if hindex else 0, "fetched_at": _iso(now), "error": "",
                          "etag": etag, "last_modified": last_mod, "bytes": len(data)})
                self._save_meta(name, m)
                self.log(f"Liste {feed['label']} : {len(index)} entrées ({len(data) // 1024} Kio)")
            self._persist()
        finally:
            self.refreshing = False
        return self.feed_status()

    def _save_meta(self, name, m):
        self.meta[name] = m
        _, _, path = self._paths(name)
        try:
            with open(path + ".tmp", "w", encoding="utf-8") as f:
                json.dump(m, f)
            os.replace(path + ".tmp", path)
        except OSError:
            pass

    @staticmethod
    def _parse_feed(feed, data):
        text = data.decode("utf-8", errors="replace")
        entries, hosts = set(), set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if feed["kind"] == "domains":
                entries.add(line.lower().rstrip("."))
            else:
                for v in norm_url_variants(line if "://" in line else "http://" + line):
                    entries.add(v)
                host, _ = _host_of(line if "://" in line else "http://" + line)
                if host:
                    hosts.add(host)
        return entries, hosts

    # ── Vérification ─────────────────────────────────────────────────────
    def _list_match(self, url, host):
        """Correspondance dans les listes → (raison, nom de liste) ou None."""
        variants = norm_url_variants(url)
        with self.lock:
            idx = dict(self.indexes)
            hidx = dict(self.hosts)
        for feed in FEEDS:
            name = feed["name"]
            index = idx.get(name)
            if not index:
                continue
            if feed["kind"] == "domains":
                labels = host.split(".")
                for i in range(0, max(1, len(labels) - 1)):
                    cand = ".".join(labels[i:])
                    if cand in index:
                        return "list_phishing", feed["label"]
            else:
                if any(v in index for v in variants):
                    return ("list_phishing" if name == "openphish" else "list_malware"), feed["label"]
        for feed in FEEDS:
            name = feed["name"]
            h = hidx.get(name)
            if h and host in h and host not in SHARED_HOSTS and not host.endswith(SHARED_SUFFIXES):
                return ("list_phishing" if name == "openphish" else "list_malware_host"), feed["label"]
        return None

    def expand(self, url, hops=3):
        """Destination finale d'un raccourcisseur (HEAD sans suivre, puis GET léger), sans télécharger la page."""
        cur = url
        chain = []
        for _ in range(hops):
            try:
                req = urllib.request.Request(cur, method="HEAD", headers={"User-Agent": USER_AGENT})
                opener = urllib.request.build_opener(_NoRedirect())
                with opener.open(req, timeout=6) as resp:
                    loc = resp.headers.get("Location")
            except urllib.error.HTTPError as e:
                loc = e.headers.get("Location") if e.code in (301, 302, 303, 307, 308) else None
            except (OSError, ValueError):
                return cur, chain
            if not loc:
                return cur, chain
            nxt = urllib.parse.urljoin(cur, loc)
            chain.append(nxt)
            cur = nxt
            host, _ = _host_of(cur)
            if registered_domain(host) not in SHORTENERS and host not in SHORTENERS:
                break
        return cur, chain

    def check(self, url, context=None, source="", resolve=True):
        url = str(url or "").strip()
        reasons, meta = analyze(url, context)
        host = meta.get("host", "")
        listed = self._list_match(url, host) if host else None
        if listed:
            reasons.append(listed[0])
            meta["list"] = listed[1]
        if host and self._allowed(host):
            return {"url": url, "host": host, "verdict": "safe", "reasons": ["user_allowed"], "meta": meta}
        if "shortener" in reasons and resolve and self.daemon.settings.get("url_guard_resolve") is not False:
            final, chain = self.expand(url)
            if chain:
                meta["final_url"] = final
                sub = self.check(final, None, source, resolve=False)
                if sub["verdict"] == "danger":
                    reasons.append("shortener_danger")
                    meta["final_reasons"] = sub["reasons"]
                    meta.update({k: v for k, v in sub.get("meta", {}).items() if k in ("brand", "list")})
                elif sub["verdict"] == "warn":
                    reasons.extend(r for r in sub["reasons"] if r not in reasons)
        # Une imitation de marque (faute de frappe, sous-domaine, combinaison…) avec une page de connexion, un domaine
        # douteux ou du punycode : danger ; seule, c'est de la prudence (« stream » n'est pas « steam »)
        _, parsed = _host_of(url)
        path_q = f"{parsed.path}?{parsed.query}" if parsed is not None else ""
        if any(r in BRAND_WARN for r in reasons) and (LOGIN_RE.search(path_q) or meta.get("suspicious_tld") or "punycode" in reasons):
            reasons.append("brand_login")
        verdict = "safe"
        if any(r in DANGER_REASONS for r in reasons):
            verdict = "danger"
        elif any(r in WARN_REASONS for r in reasons):
            verdict = "warn"
        return {"url": url, "host": host, "verdict": verdict, "reasons": reasons, "meta": meta}

    def check_many(self, urls, context=None, source=""):
        results = []
        for item in urls[:200]:
            if isinstance(item, dict):
                u, ctx = item.get("url") or item.get("href") or "", dict(context or {}, **{k: v for k, v in item.items() if k in ("text", "sender")})
            else:
                u, ctx = item, context
            results.append(self.check(u, ctx, source))
        n = len(results)
        with self.lock:
            self.counters["checked"] = self.counters.get("checked", 0) + n
            self.counters["danger"] = self.counters.get("danger", 0) + sum(1 for r in results if r["verdict"] == "danger")
            self.counters["warn"] = self.counters.get("warn", 0) + sum(1 for r in results if r["verdict"] == "warn")
        for r in results:
            if r["verdict"] != "safe":
                self.record({"t": _iso(), "source": source, "url": r["url"][:300], "host": r["host"], "verdict": r["verdict"],
                             "reasons": r["reasons"][:6], "action": "checked"})
        return results

    # ── Autorisations, journal, clients ───────────────────────────────────
    def _allowed(self, host):
        with self.lock:
            allowed = dict(self.allowed)
        return host in allowed or registered_domain(host) in allowed

    def allow(self, host, remove=False, by=""):
        host = str(host or "").strip().lower()
        if not host or " " in host:
            return False
        with self.lock:
            if remove:
                self.allowed.pop(host, None)
            else:
                self.allowed[host] = {"t": _iso(), "by": by}
        self._persist()
        return True

    def record(self, event):
        with self.lock:
            # une même adresse « checked » puis « blocked » / « opened » : on garde la dernière action
            self.events = [e for e in self.events if not (e.get("url") == event.get("url") and e.get("action") == "checked")]
            self.events.insert(0, event)
            del self.events[EVENTS_MAX:]
        self._persist()

    def report(self, url, verdict, action, source=""):
        host, _ = _host_of(url)
        self.record({"t": _iso(), "source": source, "url": str(url)[:300], "host": host, "verdict": verdict, "action": action})
        with self.lock:
            if action == "blocked":
                self.counters["blocked"] = self.counters.get("blocked", 0) + 1
            elif action == "opened":
                self.counters["opened"] = self.counters.get("opened", 0) + 1

    def hello(self, app, version, uid):
        app = app if app in CLIENTS else "other"
        with self.lock:
            self.clients[app] = {"version": str(version)[:20], "last": _iso(), "uid": int(uid)}
        self._persist()

    def _persist(self):
        with self.lock:
            data = {"events": self.events[:EVENTS_MAX], "clients": dict(self.clients), "counters": dict(self.counters),
                    "allowed": dict(self.allowed)}
        try:
            self.daemon.state.update(urlguard=data)
        except Exception as e:  # noqa: BLE001
            self.log(f"Contrôle des liens : enregistrement : {e}")

    # ── État ─────────────────────────────────────────────────────────────
    def feed_status(self):
        out = []
        for feed in FEEDS:
            m = self.meta.get(feed["name"]) or {}
            out.append({"name": feed["name"], "label": feed["label"], "kind": feed["kind"], "home": feed["home"],
                        "count": m.get("count", 0), "hosts": m.get("hosts", 0), "fetched_at": m.get("fetched_at"),
                        "error": m.get("error", ""), "interval": feed["interval"]})
        return out

    def summary(self):
        with self.lock:
            clients = dict(self.clients)
            counters = dict(self.counters)
            last = self.events[0] if self.events else None
        feeds = self.feed_status()
        return {"enabled": self.daemon.settings.get("url_guard") is not False, "feeds_ok": sum(1 for f in feeds if f["count"]),
                "feeds": len(feeds), "entries": sum(f["count"] for f in feeds), "clients": clients, "counters": counters,
                "last": last, "refreshing": self.refreshing}

    def snapshot(self):
        with self.lock:
            events = list(self.events[:60])
            allowed = dict(self.allowed)
        s = self.summary()
        s.update({"feeds": self.feed_status(), "events": events, "allowed": allowed, "mail_scan": self.daemon.settings.get("mail_scan_attachments") is not False})
        return s


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


if __name__ == "__main__":      # test en ligne de commande : python3 clamav_urlguard.py <url> [texte affiché]
    import sys

    class _S:
        def get(self, k):
            return True

    class _State:
        def get(self, k, d=None):
            return d

        def update(self, **kw):
            pass

    class _D:
        settings = _S()
        state = _State()
    g = UrlGuard(_D(), "/tmp/clamav-urlguard-cli")
    for u in sys.argv[1:2]:
        print(json.dumps(g.check(u, {"text": sys.argv[2]} if len(sys.argv) > 2 else None), indent=2, ensure_ascii=False))
