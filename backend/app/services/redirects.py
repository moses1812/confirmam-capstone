"""Follow shortened links to their real destination, safely (SSRF-protected)."""
import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

from pathlib import Path

import httpx

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "rebrand.ly", "s.id", "t.ly", "v.gd", "lnkd.in", "linktr.ee", "linkurlpro.com",
}


_file = Path(__file__).resolve().parent.parent.parent / "data" / "shorteners.txt"
if _file.exists():  # ~1,450 known shortener domains (github.com/PeterDaveHello/url-shorteners)
    SHORTENERS |= {l.strip().lower() for l in _file.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip() and not l.startswith("#")}


def is_shortener(host: str) -> bool:
    host = host.lower().removeprefix("www.")
    return host in SHORTENERS


def _is_public(host: str) -> bool:
    """Block internal addresses so the checker can't be abused to probe our own network."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True


async def expand(url: str, max_hops: int = 5) -> list[str]:
    """Return the redirect chain [original, hop1, ..., final]. Chain of length 1 means it could not be followed."""
    chain, current = [url], url
    async with httpx.AsyncClient(timeout=5, follow_redirects=False, headers={"User-Agent": "Mozilla/5.0 ConfirmAm"}) as c:
        for _ in range(max_hops):
            p = urlparse(current)
            if p.scheme not in ("http", "https") or not p.hostname:
                break
            if not await asyncio.to_thread(_is_public, p.hostname):
                break
            try:
                async with c.stream("GET", current) as r:  # headers only, body is never read
                    loc = r.headers.get("location")
                    if r.status_code in (301, 302, 303, 307, 308) and loc:
                        current = urljoin(current, loc)
                        chain.append(current)
                        continue
            except httpx.HTTPError:
                pass
            break
    return chain
