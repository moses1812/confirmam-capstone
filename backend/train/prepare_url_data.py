"""Rebuilds data/benign_hosts.txt and data/phishing_hosts.txt from public lists.
(Already done and shipped in data/. Only run this if you want fresh data. Needs internet.)

Positives : Phishing.Database ACTIVE domains  (github.com/mitchellkrogza/Phishing.Database)
Negatives : Chrome UX Report global top sites (github.com/zakird/crux-top-lists) + a hand-made list of well-known
            Nigerian brands/institutions (data/ng_trusted_seed.txt)
Both lists are reduced to bare hostnames (no scheme, no leading www.) so the model cannot learn dataset artefacts.
"""
import csv
import gzip
import io
import random
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

DATA = Path(__file__).resolve().parent.parent / "data"
PHISH = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
CRUX = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz"
random.seed(7)


def get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def clean(h: str) -> str:
    h = h.strip().lower().rstrip(".")
    return h[4:] if h.startswith("www.") else h


def main():
    phish = sorted({clean(l) for l in get(PHISH).decode(errors="ignore").splitlines() if l.strip() and not l.startswith("#")})
    random.shuffle(phish)
    benign, ng = set(), set()
    reader = csv.reader(io.StringIO(gzip.decompress(get(CRUX)).decode(errors="ignore")))
    next(reader)
    for origin, rank in reader:
        host = clean(urlparse(origin).hostname or "")
        if not host:
            continue
        if int(rank) <= 100000:
            benign.add(host)
        if host.endswith(".ng"):
            ng.add(host)
    seed = {clean(l) for l in (DATA / "ng_trusted_seed.txt").read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")}
    benign |= ng | seed
    (DATA / "phishing_hosts.txt").write_text("\n".join(phish[:110000]))
    (DATA / "benign_hosts.txt").write_text("\n".join(sorted(benign)))
    with gzip.open(DATA / "feeds" / "phishing_domains_seed.txt.gz", "wt") as f:
        f.write("\n".join(phish))
    print(len(phish), "phishing,", len(benign), "benign")


if __name__ == "__main__":
    main()
