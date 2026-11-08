import re
from urllib.parse import urlsplit

FREE_HOSTS = ("workers.dev", "r2.dev", "firebaseapp.com", "web.app")
BRANDS = ("microsoft", "paypal", "google", "apple", "amazon")

_PROBLEM_REASONS = {
    "loop": "redirect loop detected",
    "too_many_hops": "more than 5 redirects",
    "timeout": "request timed out",
    "error": "request failed",
    "blocked": "redirect target is a blocked address",
}
# "1" can pass for either "l" or "i", so try both tables.
_LOOKALIKES = (str.maketrans("0135", "oles"), str.maketrans("0135", "oies"))


def _host(url: str) -> str:
    # shortcut: no public-suffix list, so a.example.com vs b.example.com counts as different, upgrade to tldextract if that's too noisy.
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    return host.removeprefix("www.")


def _is_free_host(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in FREE_HOSTS)


def _brand_lookalike(host: str) -> str | None:
    for part in re.split(r"[.-]", host):
        if part in BRANDS:
            continue
        for table in _LOOKALIKES:
            if (fixed := part.translate(table)) in BRANDS:
                return fixed
    return None


def evaluate(chain: list[str], problem: str | None) -> list[str]:
    reasons = [_PROBLEM_REASONS[problem]] if problem else []
    hosts = [_host(u) for u in chain]
    hops = len(chain) - 1
    if hops > 2:
        reasons.append(f"more than 2 redirects ({hops})")
    if hosts[0] != hosts[-1]:
        reasons.append(f"final domain differs from original ({hosts[0]} -> {hosts[-1]})")
    if _is_free_host(hosts[-1]):
        reasons.append(f"final domain is on free hosting ({hosts[-1]})")
    for host in dict.fromkeys(hosts):
        if brand := _brand_lookalike(host):
            reasons.append(f"possible brand impersonation: {host} looks like {brand}")
    return reasons
