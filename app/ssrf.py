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


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_V4_COMPATIBLE = ipaddress.ip_network("::/96")


def _ip_blocked(ip: IPAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in _NAT64 or ip in _V4_COMPATIBLE:
            # Embedded IPv4 (NAT64 or deprecated v4-compatible): judge the IPv4 address it reaches.
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
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
