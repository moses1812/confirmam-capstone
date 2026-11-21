"""Rule-based URL analysis (strict mode). The AI model and threat feeds are layered on top in checker.py."""
import difflib
import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import tldextract

from .scoring import Signal

DATA = Path(__file__).resolve().parent.parent.parent / "data"
_tld = tldextract.TLDExtract(suffix_list_urls=())  # bundled suffix list, no network call

# Brands that scammers imitate. Add more as your team sees them in reports.
BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook", "instagram", "whatsapp", "telegram",
    "binance", "coinbase", "metamask", "phantom", "gtbank", "gtb", "gtco", "zenithbank", "zenith", "accessbank",
    "firstbank", "fidelitybank", "stanbic", "sterlingbank", "wemabank", "unionbank", "ecobank", "uba", "opay", "palmpay",
    "moniepoint", "kuda", "paystack", "flutterwave", "cbn", "efcc", "nimc", "firs", "jamb", "jumia", "konga", "dhl",
    "fedex", "mtn", "airtel", "glo", "nnpc", "dstv", "bet9ja", "sportybet",
]
RISKY_TLDS = {"xyz", "top", "click", "icu", "buzz", "live", "shop", "online", "site", "club", "work", "tk", "ml", "ga", "cf",
              "gq", "cfd", "sbs", "rest", "monster", "link", "lol", "fit", "cyou", "bond", "mom", "support", "loan", "win",
              "bid", "stream", "download", "review", "zip", "mov"}
FREE_HOSTING = ("000webhostapp", "weebly", "weeblysite", "wixsite", "blogspot", "github.io", "netlify.app", "vercel.app",
                "pages.dev", "web.app", "firebaseapp", "glitch.me", "herokuapp", "ngrok", "repl.co", "godaddysites",
                "webflow.io", "framer.app", "workers.dev", "appspot.com", "myshopify", "yolasite", "jimdosite",
                "mystrikingly", "sites.google", "carrd.co", "square.site", "000webhost", "infinityfreeapp", "epizy")
HOST_KEYWORDS = ["login", "signin", "secure", "verify", "update", "account", "bvn", "otp", "wallet", "bonus", "giveaway",
                 "invest", "profit", "claim", "reward", "recover", "confirm", "suspend", "kyc", "unlock", "refund", "winner",
                 "double", "airdrop", "grant", "loan", "promo", "payment", "billing", "support", "alert", "validate"]
PATH_KEYWORDS = ["login", "signin", "verify", "secure", "update", "account", "confirm", "wallet", "claim", "reward",
                 "recover", "unlock", "otp", "bvn", "banking", "password", "payment", "invest", "bonus", "kyc"]
GENERIC_BRANDS = {"apple", "amazon", "glo", "google", "kuda", "uba", "dhl", "paypal"}  # common words/brands: slightly lower weight
LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
REDIRECT_PARAMS = ("url", "redirect", "redirect_uri", "next", "continue", "return", "goto", "target", "dest", "link")


@lru_cache(maxsize=1)
def trusted_domains() -> frozenset[str]:
    path = DATA / "ng_trusted_seed.txt"
    if not path.exists():
        return frozenset()
    return frozenset(l.strip().lower() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#"))


def normalise_url(raw: str) -> str:
    raw = raw.strip()
    return raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else "http://" + raw


def host_of(url: str) -> str:
    return (urlparse(normalise_url(url)).hostname or "").lower()


def registered_domain(url_or_domain: str) -> str:
    host = host_of(url_or_domain)
    ext = _tld(host)
    return ext.top_domain_under_public_suffix or host


def is_trusted(url_or_domain: str) -> bool:
    host = host_of(url_or_domain)
    ext = _tld(host)
    if ext.suffix in {"gov.ng", "edu.ng", "mil.ng", "gov", "edu", "gov.uk", "gov.za"}:
        return True
    return (ext.top_domain_under_public_suffix or host) in trusted_domains()


def _entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


def _brand_signal(label: str, sub: str, suffix: str, path: str) -> Signal | None:
    flat = label.replace("-", "")
    tokens = {t for t in re.split(r"[-_.\d]+", label) if t}
    for brand in BRANDS:
        if flat == brand:
            if suffix.split(".")[-1] in RISKY_TLDS:
                return Signal("brand_impersonation", 40, f"Uses the name '{brand}' on a suspicious domain ending (.{suffix})")
            continue  # looks like the brand's own domain label
        if brand in tokens or (len(brand) >= 5 and brand in flat):
            w = 25 if brand in GENERIC_BRANDS else 40
            return Signal("brand_impersonation", w, f"Domain imitates '{brand}' but is not its official site")
        if brand in sub.replace("-", ""):
            return Signal("brand_impersonation", 40, f"'{brand}' appears as a subdomain of an unrelated site")
    for brand in BRANDS:  # look-alike spelling (paypa1, g00gle, zenithbnk)
        if len(brand) < 5:
            continue
        parts = [flat] + [x for x in label.split("-") if x]
        cands = set()
        for part in parts:
            tr = part.translate(LEET)
            cands |= {part, tr, tr.replace("1", "l"), tr.replace("1", "i")}
        for cand in cands:
            if (cand == brand and flat != brand) or (cand != brand and difflib.SequenceMatcher(None, cand, brand).ratio() >= 0.84):
                return Signal("brand_impersonation", 40, f"Domain looks like a misspelling of '{brand}'")
    low = path.lower()
    for brand in BRANDS:
        if len(brand) >= 4 and brand in low:
            return Signal("brand_in_path", 12, f"Page path mentions '{brand}' on an unrelated domain")
    return None


def analyse_url(url: str, bare: bool = False) -> list[Signal]:
    """bare=True: the user typed no http(s):// so we must not blame the site for 'no HTTPS'."""
    url = normalise_url(url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    ext = _tld(host)
    signals: list[Signal] = []
    path_q = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    if parsed.scheme != "https" and not bare:
        signals.append(Signal("no_https", 10, "Site does not use HTTPS"))
    try:
        ipaddress.ip_address(host)
        signals.append(Signal("ip_host", 30, "URL uses a raw IP address instead of a domain name"))
        return signals
    except ValueError:
        pass
    if "xn--" in host:
        signals.append(Signal("punycode", 25, "Internationalised (punycode) domain, often used for look-alikes"))
    if "@" in parsed.netloc:
        signals.append(Signal("at_symbol", 20, "URL contains '@', which can hide the real destination"))
    if len(url) > 75:
        signals.append(Signal("long_url", 8, f"Unusually long URL ({len(url)} characters)"))
    if host.count(".") >= 4:
        signals.append(Signal("many_subdomains", 12, "Excessive number of subdomains"))
    if ext.domain.count("-") >= 2:
        signals.append(Signal("many_hyphens", 10, "Several hyphens in the domain name"))
    suffix_last = ext.suffix.split(".")[-1] if ext.suffix else ""
    if suffix_last in RISKY_TLDS:
        signals.append(Signal("risky_tld", 15, f"Domain ending .{ext.suffix} is heavily abused by scammers"))
    if any(f in host for f in FREE_HOSTING):
        signals.append(Signal("free_hosting", 15, "Hosted on a free website/hosting service (common for throw-away scam sites)"))

    hits = [k for k in HOST_KEYWORDS if k in host]
    if hits:
        signals.append(Signal("scam_keywords", min(6 * len(hits), 24), f"Suspicious words in the domain: {', '.join(hits[:5])}"))
    path_hits = [k for k in PATH_KEYWORDS if k in path_q.lower()]
    if path_hits and not hits:
        signals.append(Signal("path_keywords", min(4 * len(path_hits), 12), f"Suspicious words in the page address: {', '.join(path_hits[:4])}"))

    b = _brand_signal(ext.domain.lower(), ext.subdomain.lower(), ext.suffix, path_q)
    if b:
        signals.append(b)

    label = ext.domain
    if sum(c.isdigit() for c in label) >= 3 and len(label) >= 8:
        signals.append(Signal("digits_in_domain", 8, "Domain name contains a long run of random digits"))
    if len(label) >= 12 and _entropy(label) > 3.5 and "-" not in label:
        signals.append(Signal("random_looking_domain", 8, "Domain name looks randomly generated"))
    if re.search(r"/(wp-content|wp-includes|wp-admin)/", path_q, re.I):
        signals.append(Signal("compromised_site_path", 8, "Page lives inside a WordPress folder (often a hacked site hosting a fake page)"))
    if re.search(r"\.(php|asp|aspx|html?)\?", path_q, re.I) and path_hits:
        signals.append(Signal("script_login_page", 6, "Login-style page served by a script with parameters"))
    if len(re.findall(r"%[0-9a-f]{2}", url, re.I)) >= 4:
        signals.append(Signal("encoded_chars", 8, "Heavily encoded URL, often used to hide the real address"))
    qs = parse_qs(parsed.query)
    if any(k.lower() in REDIRECT_PARAMS and any(v.lower().startswith(("http", "//")) for v in vs) for k, vs in qs.items()):
        signals.append(Signal("open_redirect", 15, "Link redirects to another website via a parameter"))
    if "//" in (parsed.path or ""):
        signals.append(Signal("double_slash_path", 5, "Odd double slash in the page address"))
    return signals


def domain_age_signal(age_days: int | None) -> Signal | None:
    if age_days is None:
        return None
    if age_days < 30:
        return Signal("new_domain", 30, f"Domain registered only {age_days} days ago", "rdap")
    if age_days < 180:
        return Signal("young_domain", 15, f"Domain is only {age_days} days old", "rdap")
    return None
