import socket

import pytest

from app.ssrf import is_blocked


def resolve_to(monkeypatch: pytest.MonkeyPatch, *addrs: str) -> None:
    monkeypatch.setattr(
        "app.ssrf.socket.getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", (ip, 0)) for ip in addrs],
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://10.0.0.5/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
        "http://[::ffff:127.0.0.1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://224.0.0.1/",
        "http://[::]/",
        "http://[64:ff9b::a00:1]/",
        "http://[64:ff9b::7f00:1]/",
        "http://[::127.0.0.1]/",
    ],
)
def test_blocked_ip_literals(url: str) -> None:
    assert is_blocked(url) is True


@pytest.mark.parametrize("url", ["http://8.8.8.8/", "http://[64:ff9b::808:808]/"])
def test_public_ip_literal_allowed(url: str) -> None:
    assert is_blocked(url) is False


def test_hostname_resolving_to_loopback_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    resolve_to(monkeypatch, "127.0.0.1")
    assert is_blocked("http://localhost/") is True


def test_numeric_host_form_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    resolve_to(monkeypatch, "127.0.0.1")
    assert is_blocked("http://2130706433/") is True


def test_mixed_answers_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    resolve_to(monkeypatch, "93.184.216.34", "10.0.0.1")
    assert is_blocked("http://mixed.example/") is True


def test_public_v4_with_private_v6_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    resolve_to(monkeypatch, "93.184.216.34", "fd00::1")
    assert is_blocked("http://dual.example/") is True


def test_resolution_failure_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*a: object, **k: object) -> list:
        raise socket.gaierror("nope")

    monkeypatch.setattr("app.ssrf.socket.getaddrinfo", fail)
    assert is_blocked("http://nonexistent.example/") is True


def test_public_hostname_allowed() -> None:
    assert is_blocked("https://example.com/") is False


def test_no_hostname_blocked() -> None:
    assert is_blocked("http://") is True


def test_malformed_url_blocked() -> None:
    assert is_blocked("http://[::1/") is True
