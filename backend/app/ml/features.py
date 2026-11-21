"""Feature engineering shared by training (train/*.py) and live prediction (app/ml/*.py).
Keep these functions importable at module level: the saved .joblib models refer to them by name."""
import math
import re

import numpy as np

RISKY_TLDS = {"xyz", "top", "click", "icu", "buzz", "live", "shop", "online", "site", "club", "work", "tk", "ml", "ga", "cf",
              "gq", "cfd", "sbs", "rest", "monster", "link", "lol", "fit", "cyou", "bond", "mom"}
FREE_HOSTING = ("000webhostapp", "weebly", "weeblysite", "wixsite", "blogspot", "github.io", "netlify.app", "vercel.app",
                "pages.dev", "web.app", "firebaseapp", "glitch.me", "herokuapp", "ngrok", "repl.co", "godaddysites",
                "webflow.io", "framer.app", "workers.dev", "appspot.com", "myshopify", "wordpress.com", "square.site",
                "carrd.co", "yolasite", "jimdosite", "mystrikingly", "sites.google")
KEYWORDS = ("login", "signin", "secure", "verify", "update", "account", "bvn", "otp", "wallet", "bonus", "giveaway",
            "invest", "profit", "claim", "reward", "recover", "confirm", "suspend", "bank", "support", "free", "promo",
            "cbn", "efcc", "loan", "crypto", "airdrop", "payment", "billing", "unlock", "kyc", "refund", "winner", "double")
BRANDS = ("paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook", "instagram", "whatsapp", "binance",
          "coinbase", "gtbank", "gtb", "zenith", "access", "firstbank", "uba", "fidelity", "stanbic", "opay", "palmpay",
          "moniepoint", "kuda", "paystack", "flutterwave", "cbn", "efcc", "nimc", "firs", "jumia", "dhl", "fedex", "mtn", "airtel")
VOWELS = set("aeiou")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(v / len(s) * math.log2(v / len(s)) for v in counts.values())


def _max_consonant_run(s: str) -> int:
    best = run = 0
    for ch in s:
        run = run + 1 if ch.isalpha() and ch not in VOWELS else 0
        best = max(best, run)
    return best


def host_numeric(host: str) -> list[float]:
    host = (host or "").lower()
    labels = host.split(".")
    tld = labels[-1] if labels else ""
    main = labels[-2] if len(labels) >= 2 else host
    n = max(len(host), 1)
    digits = sum(c.isdigit() for c in host)
    alpha = sum(c.isalpha() for c in host)
    return [
        len(host), len(labels), host.count("-"), digits, digits / n, alpha / n, _entropy(host), _entropy(main),
        len(main), max((len(l) for l in labels), default=0), _max_consonant_run(host),
        sum(c in VOWELS for c in host) / max(alpha, 1),
        float("xn--" in host), float(tld in RISKY_TLDS), float(any(f in host for f in FREE_HOSTING)),
        sum(k in host for k in KEYWORDS), sum(b in host for b in BRANDS),
        float(bool(re.search(r"\d{4,}", host))), float(bool(re.fullmatch(r"[\d.]+", host))),
        float(host.count("-") >= 2), float(len(labels) >= 4),
    ]


def batch_numeric(hosts) -> np.ndarray:
    return np.array([host_numeric(h) for h in hosts], dtype=np.float64)


URL_RE = re.compile(r"(?:https?://|www\.)\S+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|ng|net|org|xyz|top|click|info|co|site|online|link|shop|icu|live|club|cfd)\b\S*", re.I)
PHONE_RE = re.compile(r"(?:\+?234|\b0)[789][01]\d{8}\b")
LONGNUM_RE = re.compile(r"\b\d{10,}\b")


def normalize_message(text: str) -> str:
    """Lower-case and collapse URLs / phone / account numbers into tokens so the model learns patterns, not specifics."""
    t = (text or "").lower()
    def _url(m):
        u = m.group(0)
        tag = " urltok"
        if re.search(r"\.(xyz|top|click|icu|online|site|shop|club|live|cfd|link)\b", u):
            tag += " riskytldtok"
        if re.search(r"bit\.ly|tinyurl|cutt\.ly|rb\.gy|t\.ly|is\.gd", u):
            tag += " shorturltok"
        if u.startswith("http://"):
            tag += " httptok"
        return tag + " "
    t = URL_RE.sub(_url, t)
    t = PHONE_RE.sub(" phonetok ", t)
    t = LONGNUM_RE.sub(" accttok ", t)
    t = re.sub(r"\d", "0", t)
    return t
