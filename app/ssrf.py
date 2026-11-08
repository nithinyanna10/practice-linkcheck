import ipaddress
import socket
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _addresses(host: str) -> list[IPAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    # shortcut: DNS is resolved here and again by httpx at connect time, so DNS rebinding can still beat it, upgrade by pinning the resolved IP in a custom transport.
    infos = socket.getaddrinfo(host, None)
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def _ip_blocked(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


def is_blocked(url: str) -> bool:
    """True if the URL has no host or any address it points at is non-public (fail closed)."""
    try:
        host = urlsplit(url).hostname
        if not host:
            return True
        return any(_ip_blocked(ip) for ip in _addresses(host))
    except (socket.gaierror, ValueError):
        return True
