import warnings
from collections.abc import Callable, Iterator

import httpx
import pytest

with warnings.catch_warnings():
    # shortcut: silences starlette's "install httpx2" notice at import, upgrade by switching to httpx2 in requirements.txt.
    warnings.filterwarnings("ignore", message="Using `httpx` with `starlette.testclient`")
    from fastapi.testclient import TestClient

from app.main import app, get_client

Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def requested() -> list[str]:
    return []


@pytest.fixture
def serve(requested: list[str]) -> Iterator[Callable[[Handler], None]]:
    """Install a mock-transport client whose handler records every requested host."""

    def install(handler: Handler) -> None:
        def recording(request: httpx.Request) -> httpx.Response:
            requested.append(request.url.host)
            return handler(request)

        app.dependency_overrides[get_client] = lambda: httpx.Client(
            transport=httpx.MockTransport(recording)
        )

    yield install
    app.dependency_overrides.clear()


@pytest.fixture
def api() -> TestClient:
    return TestClient(app)


def _ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200)


def _redirect(location: str) -> httpx.Response:
    return httpx.Response(302, headers={"location": location})


def test_safe_link(api: TestClient, serve: Callable[[Handler], None]) -> None:
    serve(_ok)
    response = api.post("/links/check", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json() == {
        "verdict": "safe",
        "chain": ["https://example.com"],
        "reasons": [],
    }


def test_suspicious_domain_change(api: TestClient, serve: Callable[[Handler], None]) -> None:
    serve(lambda r: _redirect("https://b.com") if r.url.host == "a.com" else _ok(r))
    body = api.post("/links/check", json={"url": "https://a.com"}).json()
    assert body["verdict"] == "suspicious"
    assert len(body["chain"]) == 2
    assert body["reasons"] == ["final domain differs from original (a.com -> b.com)"]


def test_loop_is_suspicious(api: TestClient, serve: Callable[[Handler], None]) -> None:
    serve(lambda r: _redirect("https://b.com") if r.url.host == "a.com" else _redirect("https://a.com"))
    body = api.post("/links/check", json={"url": "https://a.com"}).json()
    assert body["verdict"] == "suspicious"
    assert "redirect loop detected" in body["reasons"]


def test_timeout_is_200_suspicious(api: TestClient, serve: Callable[[Handler], None]) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("x")

    serve(timeout)
    response = api.post("/links/check", json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json()["verdict"] == "suspicious"
    assert "request timed out" in response.json()["reasons"]


def test_brand_swap_input(api: TestClient, serve: Callable[[Handler], None]) -> None:
    serve(_ok)
    body = api.post("/links/check", json={"url": "https://paypa1.com"}).json()
    assert body["verdict"] == "suspicious"
    assert any("paypal" in reason for reason in body["reasons"])


@pytest.mark.parametrize(
    "url",
    ["not a url", "ftp://example.com", "javascript:alert(1)", "http://", "", "http://[::1/"],
)
def test_invalid_urls_422(api: TestClient, serve: Callable[[Handler], None], requested: list[str], url: str) -> None:
    serve(_ok)
    assert api.post("/links/check", json={"url": url}).status_code == 422
    assert requested == []


def test_missing_url_422(api: TestClient) -> None:
    assert api.post("/links/check", json={}).status_code == 422


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://169.254.169.254/",
        "http://10.0.0.1/",
        "http://[::1]/",
        "http://localhost/",
    ],
)
def test_blocked_input_urls_422(
    api: TestClient,
    serve: Callable[[Handler], None],
    requested: list[str],
    monkeypatch: pytest.MonkeyPatch,
    url: str,
) -> None:
    monkeypatch.setattr(
        "app.ssrf.socket.getaddrinfo",
        lambda host, *a, **k: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    serve(_ok)
    assert api.post("/links/check", json={"url": url}).status_code == 422
    assert requested == []


def test_blocked_redirect_is_suspicious(
    api: TestClient, serve: Callable[[Handler], None], requested: list[str]
) -> None:
    serve(lambda r: _redirect("http://10.0.0.1/admin"))
    response = api.post("/links/check", json={"url": "https://a.com"})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "suspicious"
    assert body["chain"] == ["https://a.com"]
    assert "redirect target is a blocked address" in body["reasons"]
    assert "10.0.0.1" not in requested


def test_real_client_does_not_follow_redirects() -> None:
    # follow_chain checks every hop itself; httpx following redirects would bypass that.
    dependency = get_client()
    client = next(dependency)
    try:
        assert client.follow_redirects is False
    finally:
        dependency.close()
    assert client.is_closed
