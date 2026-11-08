from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from app.ssrf import is_blocked

HOP_TIMEOUT = 5.0
MAX_HOPS = 5
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass
class ChainResult:
    chain: list[str]
    problem: str | None


def _probe(url: str, client: httpx.Client) -> str | None:
    """Return the redirect target of url, or None. Reads status and headers only, never the body."""
    # GET, not HEAD: phishing sites cloak against HEAD.
    with client.stream("GET", url, timeout=HOP_TIMEOUT, follow_redirects=False) as response:
        location = response.headers.get("location")
        if response.status_code in REDIRECT_STATUSES and location:
            return urljoin(url, location)
    return None


def _rejection(target: str) -> str | None:
    """Problem that stops the chain before target is fetched, if any."""
    if urlsplit(target).scheme not in ("http", "https"):
        return "error"
    if is_blocked(target):
        return "blocked"
    return None


def follow_chain(url: str, client: httpx.Client) -> ChainResult:
    chain = [url]
    try:
        while True:
            target = _probe(chain[-1], client)
            if target is None:
                return ChainResult(chain, None)
            if len(chain) > MAX_HOPS:
                return ChainResult(chain, "too_many_hops")
            problem = _rejection(target)
            if problem:
                return ChainResult(chain, problem)
            looped = target in chain
            chain.append(target)
            if looped:
                return ChainResult(chain, "loop")
    except httpx.TimeoutException:
        return ChainResult(chain, "timeout")
    except (httpx.HTTPError, httpx.InvalidURL, ValueError):  # ValueError: urljoin/urlsplit on a malformed Location
        return ChainResult(chain, "error")
