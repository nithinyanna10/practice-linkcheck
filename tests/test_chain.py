import httpx
import pytest

from app.chain import follow_chain

A, B, C = "http://a.com/", "http://b.com/", "http://c.com/"


def make_client(
    routes: dict[str, httpx.Response | Exception],
) -> tuple[httpx.Client, list[tuple[str, str]]]:
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, str(request.url)))
        result = routes[str(request.url)]
        if isinstance(result, Exception):
            raise result
        return result

    return httpx.Client(transport=httpx.MockTransport(handler)), seen


def redirect(to: str, status: int = 302) -> httpx.Response:
    return httpx.Response(status, headers={"Location": to})


def hops(n: int, end: httpx.Response | None) -> dict[str, httpx.Response | Exception]:
    routes: dict[str, httpx.Response | Exception] = {
        f"http://h{i}.com/": redirect(f"http://h{i + 1}.com/") for i in range(n)
    }
    if end is not None:
        routes[f"http://h{n}.com/"] = end
    return routes


def test_no_redirect() -> None:
    client, _ = make_client({A: httpx.Response(200)})
    result = follow_chain(A, client)
    assert result.chain == [A] and result.problem is None


def test_follows_redirects() -> None:
    client, _ = make_client({A: redirect(B), B: redirect(C, 301), C: httpx.Response(200)})
    result = follow_chain(A, client)
    assert result.chain == [A, B, C] and result.problem is None


def test_relative_location_is_resolved() -> None:
    a = "http://x.com/a"
    client, _ = make_client({a: redirect("/next"), "http://x.com/next": httpx.Response(200)})
    assert follow_chain(a, client).chain == [a, "http://x.com/next"]


def test_redirect_without_location_ends_chain() -> None:
    client, _ = make_client({A: httpx.Response(302)})
    result = follow_chain(A, client)
    assert result.chain == [A] and result.problem is None


def test_five_hops_ok() -> None:
    client, _ = make_client(hops(5, httpx.Response(200)))
    result = follow_chain("http://h0.com/", client)
    assert len(result.chain) == 6 and result.problem is None


def test_sixth_hop_stops() -> None:
    client, seen = make_client(hops(10, None))
    result = follow_chain("http://h0.com/", client)
    assert len(result.chain) == 6 and result.problem == "too_many_hops"
    assert len(seen) == 6


def test_loop_detected() -> None:
    client, _ = make_client({A: redirect(B), B: redirect(A)})
    result = follow_chain(A, client)
    assert result.chain == [A, B, A] and result.problem == "loop"


def test_timeout() -> None:
    client, _ = make_client({A: redirect(B), B: httpx.ReadTimeout("x")})
    result = follow_chain(A, client)
    assert result.chain == [A, B] and result.problem == "timeout"


def test_connect_error() -> None:
    client, _ = make_client({A: httpx.ConnectError("x")})
    assert follow_chain(A, client).problem == "error"


def test_non_http_redirect_target() -> None:
    client, _ = make_client({A: redirect("ftp://x.com/f")})
    result = follow_chain(A, client)
    assert result.chain == [A] and result.problem == "error"


def test_per_hop_timeout_is_5s() -> None:
    timeouts: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    follow_chain(A, client)
    assert timeouts[0]["read"] == 5.0 and timeouts[0]["connect"] == 5.0


def test_uses_get_and_never_reads_body() -> None:
    read: list[bool] = []

    class Body(httpx.SyncByteStream):
        def __iter__(self):
            read.append(True)
            yield b"secret"

    client, seen = make_client({A: httpx.Response(200, stream=Body())})
    follow_chain(A, client)
    assert seen == [("GET", A)] and not read


def test_redirect_to_private_ip_blocked() -> None:
    bad = "http://169.254.169.254/"
    client, seen = make_client({A: redirect(bad)})
    result = follow_chain(A, client)
    assert result.chain == [A] and result.problem == "blocked"
    assert all(url != bad for _, url in seen)


def test_redirect_to_internal_hostname_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    def resolve(host: str, *a: object, **k: object) -> list:
        ip = "10.0.0.1" if host == "internal.corp" else "93.184.216.34"
        return [(2, 1, 6, "", (ip, 0))]

    monkeypatch.setattr("app.ssrf.socket.getaddrinfo", resolve)
    client, _ = make_client({A: redirect("http://internal.corp/")})
    result = follow_chain(A, client)
    assert result.chain == [A] and result.problem == "blocked"
