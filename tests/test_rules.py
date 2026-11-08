import pytest

from app.rules import evaluate


def test_single_url_is_safe() -> None:
    assert evaluate(["https://example.com"], None) == []


def test_two_hops_ok() -> None:
    chain = ["https://a.com", "https://a.com/1", "https://a.com/2"]
    assert evaluate(chain, None) == []


def test_three_hops_flagged() -> None:
    chain = ["https://a.com", "https://a.com/1", "https://a.com/2", "https://a.com/3"]
    assert "more than 2 redirects (3)" in evaluate(chain, None)


def test_final_domain_differs() -> None:
    assert evaluate(["https://a.com", "https://b.com"], None) == [
        "final domain differs from original (a.com -> b.com)"
    ]


def test_host_normalisation() -> None:
    chain = ["HTTP://Example.COM:8080/x", "https://www.example.com/y"]
    assert evaluate(chain, None) == []


@pytest.mark.parametrize("suffix", ["workers.dev", "r2.dev", "firebaseapp.com", "web.app"])
def test_free_hosting(suffix: str) -> None:
    host = f"my-site.{suffix}"
    reasons = evaluate(["https://a.com", f"https://{host}"], None)
    assert f"final domain is on free hosting ({host})" in reasons


def test_free_hosting_suffix_must_match_on_label_boundary() -> None:
    reasons = evaluate(["https://a.com", "https://notworkers.dev"], None)
    assert not any("free hosting" in r for r in reasons)


def test_bare_free_hosting_suffix_flagged() -> None:
    reasons = evaluate(["https://a.com", "https://workers.dev"], None)
    assert "final domain is on free hosting (workers.dev)" in reasons


def test_free_hosting_only_checks_final() -> None:
    chain = ["https://a.com", "https://x.workers.dev", "https://a.com"]
    assert not any("free hosting" in r for r in evaluate(chain, None))


@pytest.mark.parametrize(
    ("host", "brand"),
    [
        ("micros0ft.com", "microsoft"),
        ("paypa1.com", "paypal"),
        ("micros0ft-support.com", "microsoft"),
        ("g00gle.com", "google"),
        ("app1e.com", "apple"),
        ("amaz0n.com", "amazon"),
    ],
)
def test_brand_swap(host: str, brand: str) -> None:
    reasons = evaluate([f"https://{host}"], None)
    assert f"possible brand impersonation: {host} looks like {brand}" in reasons


def test_brand_swap_in_middle_hop_flagged() -> None:
    chain = ["https://a.com", "https://paypa1.com", "https://a.com"]
    assert "possible brand impersonation: paypa1.com looks like paypal" in evaluate(chain, None)


def test_brand_reason_once_per_host() -> None:
    chain = ["https://paypa1.com", "https://paypa1.com/x", "https://paypa1.com/y"]
    reasons = [r for r in evaluate(chain, None) if "impersonation" in r]
    assert reasons == ["possible brand impersonation: paypa1.com looks like paypal"]


@pytest.mark.parametrize(
    "url",
    [
        "https://www.microsoft.com",
        "https://paypal.com",
        "https://login.microsoftonline.com",
    ],
)
def test_real_brands_not_flagged(url: str) -> None:
    assert evaluate([url], None) == []


@pytest.mark.parametrize(
    ("problem", "reason"),
    [
        ("loop", "redirect loop detected"),
        ("timeout", "request timed out"),
        ("error", "request failed"),
        ("blocked", "redirect target is a blocked address"),
    ],
)
def test_problems_map_to_reasons(problem: str, reason: str) -> None:
    assert evaluate(["https://a.com"], problem) == [reason]


def test_too_many_hops_problem() -> None:
    assert "more than 5 redirects" in evaluate(["https://a.com"], "too_many_hops")


def test_reason_order() -> None:
    chain = ["https://a.com", "https://b.com", "https://c.com", "https://paypa1.workers.dev"]
    assert evaluate(chain, "loop") == [
        "redirect loop detected",
        "more than 2 redirects (3)",
        "final domain differs from original (a.com -> paypa1.workers.dev)",
        "final domain is on free hosting (paypa1.workers.dev)",
        "possible brand impersonation: paypa1.workers.dev looks like paypal",
    ]
