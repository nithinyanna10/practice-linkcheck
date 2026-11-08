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
    # TODO(timeout): HOP_TIMEOUT is an httpx per-operation timeout (connect/read/write/pool), not a
    # wall-clock limit per hop, and DNS lookups (here via is_blocked, and inside httpx) have no timeout.
    # A hostile server that sends one byte every <5s, or a slow DNS server, can hold a request thread
    # for a very long time; ~40 such URLs exhaust Starlette's threadpool and stall the whole service.
    # Fix: async httpx.AsyncClient + async endpoint + asyncio.timeout(HOP_TIMEOUT) around each hop,
    # with the is_blocked DNS lookup inside the same deadline, and a test with a stalling stream.
    # Until then, do not expose this service to untrusted traffic.
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
