# Link Checker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A FastAPI service whose `POST /links/check` follows a URL's redirect chain and returns a safe/suspicious verdict with reasons, without ever fetching internal addresses.

**Architecture:** Four small modules. `ssrf.py` says whether a URL is safe to fetch. `chain.py` follows redirects hop by hop through an injected `httpx.Client` (manual redirects, so loops/hop limit/per-hop timeout/SSRF checks are ours). `rules.py` is pure: chain + problem in, list of reason strings out. `main.py` wires them to the endpoint; verdict is `suspicious` iff there is at least one reason. Tests inject `httpx.MockTransport` through a FastAPI dependency override and monkeypatch DNS, so no real network happens.

**Tech Stack:** Python 3.12, FastAPI, httpx, pytest (all already in `.venv`).

**Spec:** The user's messages in this session (no spec file). Restated in Global Constraints below.

## Global Constraints

- Endpoint: `POST /links/check`, body `{"url": "..."}`
- Response: `{"verdict": "safe" | "suspicious", "chain": [...urls], "reasons": [...]}`
- Max 5 hops; detect redirect loops; 5s timeout per hop
- Suspicious if ANY of: more than 2 hops; final domain differs from the first; final domain on free hosting (`workers.dev`, `r2.dev`, `firebaseapp.com`, `web.app`); domain looks like a known brand with swapped characters (`micros0ft`, `paypa1`)
- SSRF: reject input URLs and redirect targets that resolve to localhost or private IP ranges
- Probe each hop with `GET`, streamed, body never read (phishing sites often cloak against `HEAD`)
- pytest tests with the network mocked (HTTP and DNS); no real network in tests
- Repo rules (`CLAUDE.md`): Python 3, type hints, small functions, pytest for every behavior; commit after every task, small commits, no `Co-Authored-By` lines

## Decisions the spec leaves open (locked here)

- "Hop" = one redirect followed. `chain` = original URL + every redirect target, so `len(chain) - 1` = hops. "More than 2 hops" means `len(chain) - 1 > 2`.
- Hop limit: after 5 redirects followed, if the last response is still a redirect, stop with problem `too_many_hops`.
- Loop: a redirect target already in `chain` is appended to `chain`, then we stop with problem `loop`.
- Probe with `client.stream("GET", url, timeout=HOP_TIMEOUT)`; only status and headers are used, the body is never read and the connection is closed on exit.
- Timeout/connect failure/non-http(s) redirect target: stop, problem `timeout` / `error`, verdict suspicious (can't verify), HTTP 200 (never a 500).
- SSRF, `app/ssrf.py: is_blocked(url: str) -> bool`: True when the URL has no hostname, or when the hostname (an IP literal parsed with `ipaddress`, otherwise resolved with `socket.getaddrinfo`) yields ANY address where, after unwrapping IPv4-mapped IPv6 (`.ipv4_mapped`), `not ip.is_global or ip.is_multicast`. That covers 127/8, `::1`, 10/8, 172.16/12, 192.168/16, 169.254/16 (cloud metadata), 100.64/10, `0.0.0.0`, `fc00::/7`, `fe80::/10`. `localhost` and numeric forms like `2130706433` are caught because they resolve to loopback. Resolution failure counts as blocked (fail closed). `shortcut: DNS is resolved here and again by httpx at connect time, so DNS rebinding can still beat it, upgrade by pinning the resolved IP in a custom transport.`
- Blocked input URL → HTTP 422. Blocked redirect target → target is not fetched and not added to `chain`, problem `blocked`, verdict suspicious.
- Domain comparison: lowercased hostname, port ignored, a leading `www.` ignored. `shortcut: no public-suffix list, so a.example.com vs b.example.com counts as different, upgrade to tldextract if that's too noisy.`
- Brand check runs on every hostname in the chain. Brands: `microsoft`, `paypal`, `google`, `apple`, `amazon`. Hostname is split on `.` and `-`; a part is flagged if it is not itself a brand but becomes one after replacing `0→o`, `1→l` or `1→i`, `3→e`, `5→s`.
- Free hosting match: hostname equals the suffix or ends with `.` + suffix (`notworkers.dev` does not match).
- Reason strings are exact (tests assert them):
  - `"more than 2 redirects (N)"` with N = hop count
  - `"final domain differs from original (A -> B)"`
  - `"final domain is on free hosting (HOST)"`
  - `"possible brand impersonation: HOST looks like BRAND"`
  - `"redirect loop detected"`, `"more than 5 redirects"`, `"request timed out"`, `"request failed"`, `"redirect target is a blocked address"`

## Review Focus

Input classes the spec implies but doesn't state, most likely first. Each is pinned by a test in the named task.

1. Relative `Location` header (`/next`) — resolved against the current URL (Task 1).
2. 3xx with no `Location` — chain ends there, treated as final, not an error (Task 1).
3. Timeout / connection error mid-chain — suspicious verdict with a reason, HTTP 200 not 500 (Tasks 1 and 3).
4. Non-http input: `ftp://x`, `not a url`, `javascript:` in a `Location` — request body gets 422; a bad redirect target gets problem `error` (Tasks 1 and 3).
5. Host spelling: `HTTP://Example.COM:8080` vs `www.example.com` is not "different domain"; legit `microsoft.com`/`paypal.com` and `notworkers.dev` are not flagged (Task 2).

## Execution layout (per `CLAUDE.md`)

- Integration branch `feat/link-checker` lives in its own git worktree; nothing is built on `main`. Task 0 and this plan are committed there first.
- Task 1 and Task 2 share no files, so each runs in its own worktree/branch cut from `feat/link-checker` (`feat/link-checker-chain`, `feat/link-checker-rules`), in parallel, each with a review after the task. Both are merged into `feat/link-checker`; the full suite is run after the merge.
- Task 3 runs on `feat/link-checker` after both merges. Then `superpowers:finishing-a-development-branch`: run all tests, merge into `main`.

---

### Task 0: Project scaffolding

**Files:**
- Create: `requirements.txt` (`fastapi`, `httpx`, `uvicorn`, `pytest`), `pyproject.toml` (only `[tool.pytest.ini_options]` with `pythonpath = ["."]`), `app/__init__.py` (empty), `tests/__init__.py` (empty)
- Modify: `.gitignore` (add `__pycache__/`, `.pytest_cache/`)

**Interfaces:** Produces the importable `app` package and pytest config that Tasks 1–3 rely on.

- [ ] **Step 1: Create the files above.**
- [ ] **Step 2: Verify.** Run: `.venv/bin/python -m pytest` → "no tests ran", exit code 5, no import errors.
- [ ] **Step 3: Commit** `chore: project scaffolding`

---

### Task 1: SSRF guard and redirect chain follower

**Files:**
- Create: `app/ssrf.py`, `app/chain.py`, `tests/conftest.py`, `tests/test_ssrf.py`, `tests/test_chain.py`

**Interfaces:**
- Produces, in `app/ssrf.py`: `is_blocked(url: str) -> bool` (semantics in Decisions). Resolves via `socket.getaddrinfo` referenced as `socket.getaddrinfo` inside the module so tests can patch `app.ssrf.socket.getaddrinfo`.
- Produces, in `app/chain.py`:
  - `HOP_TIMEOUT = 5.0`, `MAX_HOPS = 5`
  - `@dataclass ChainResult` with `chain: list[str]` and `problem: str | None` (one of `None`, `"loop"`, `"too_many_hops"`, `"timeout"`, `"error"`, `"blocked"`)
  - `follow_chain(url: str, client: httpx.Client) -> ChainResult` — checks `is_blocked` on redirect targets only; the caller checks the input URL.
- Produces, in `tests/conftest.py`: autouse fixture `public_dns` patching `app.ssrf.socket.getaddrinfo` to return the single public address `93.184.216.34` for any host, so no test performs real DNS. Tests that need other answers re-patch with `monkeypatch`.

- [ ] **Step 1: Write failing SSRF tests in `tests/test_ssrf.py`.**
  - `test_blocked_ip_literals` (parametrized): `http://127.0.0.1/`, `http://[::1]/`, `http://10.0.0.5/`, `http://172.16.0.1/`, `http://192.168.1.1/`, `http://169.254.169.254/latest/meta-data`, `http://100.64.0.1/`, `http://0.0.0.0/`, `http://[::ffff:127.0.0.1]/`, `http://[fc00::1]/`, `http://[fe80::1]/` → `is_blocked` is True.
  - `test_public_ip_literal_allowed`: `http://8.8.8.8/` → False.
  - `test_hostname_resolving_to_loopback_blocked`: patch resolver to return `127.0.0.1`; `http://localhost/` → True.
  - `test_numeric_host_form_blocked`: patch resolver to return `127.0.0.1`; `http://2130706433/` → True.
  - `test_mixed_answers_blocked`: resolver returns one public and one private address → True.
  - `test_resolution_failure_blocked`: resolver raises `socket.gaierror` → True.
  - `test_public_hostname_allowed`: default fixture; `https://example.com/` → False.
  - `test_no_hostname_blocked`: `"http://"` → True.

- [ ] **Step 2: Write failing chain tests in `tests/test_chain.py`.** Use a helper `make_client(routes: dict[str, httpx.Response | Exception])` whose handler records `(request.method, str(request.url))` in a list, looks up `str(request.url)`, and raises the value if it is an Exception; return the client and the list. Tests:
  - `test_no_redirect`: `a` → 200 gives `chain == [a]`, `problem is None`.
  - `test_follows_redirects`: `a`→302→`b`→301→`c`→200 gives `chain == [a, b, c]`.
  - `test_relative_location_is_resolved`: `http://x.com/a` → `Location: /next` gives `chain == ["http://x.com/a", "http://x.com/next"]`.
  - `test_redirect_without_location_ends_chain`: 302 with no Location gives `chain == [a]`, `problem is None`.
  - `test_five_hops_ok`: 5 redirects then 200 gives `len(chain) == 6`, `problem is None`.
  - `test_sixth_hop_stops`: endless redirect chain of distinct URLs gives `len(chain) == 6`, `problem == "too_many_hops"`.
  - `test_loop_detected`: `a`→`b`→`a` gives `chain == [a, b, a]`, `problem == "loop"`.
  - `test_timeout`: second hop raises `httpx.ReadTimeout("x")` gives `chain == [a, b]`, `problem == "timeout"`.
  - `test_connect_error`: hop raises `httpx.ConnectError("x")` gives `problem == "error"`.
  - `test_non_http_redirect_target`: `Location: ftp://x.com/f` gives `chain == [a]`, `problem == "error"`.
  - `test_per_hop_timeout_is_5s`: handler records `request.extensions["timeout"]`; assert `["read"] == 5.0` and `["connect"] == 5.0`.
  - `test_uses_get_and_never_reads_body`: response built with `stream=` a `httpx.SyncByteStream` subclass whose `__iter__` sets a flag; after `follow_chain`, recorded method is `"GET"` and the flag is unset.
  - `test_redirect_to_private_ip_blocked`: `a`→302 `Location: http://169.254.169.254/` gives `chain == [a]`, `problem == "blocked"`, and the blocked URL never appears in the recorded requests.
  - `test_redirect_to_internal_hostname_blocked`: patch resolver to return `10.0.0.1` for host `internal.corp` only (public for others); redirect to `http://internal.corp/` gives `problem == "blocked"`, `chain == [a]`.

- [ ] **Step 3: Run to verify failure.**
  Run: `.venv/bin/python -m pytest tests/test_ssrf.py tests/test_chain.py -v`
  Expected: collection errors, `app.ssrf` / `app.chain` not found.

- [ ] **Step 4: Implement `is_blocked` in `app/ssrf.py`** per the signature and Decisions. Small helpers: `_addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]` (IP literal first, else `getaddrinfo`), `_ip_blocked(ip) -> bool`.

- [ ] **Step 5: Run SSRF tests.** Run: `.venv/bin/python -m pytest tests/test_ssrf.py -v` → all pass.

- [ ] **Step 6: Implement `follow_chain` in `app/chain.py`** with the signature above. Loop: `with client.stream("GET", current, timeout=HOP_TIMEOUT) as r:` read only `r.status_code` and `r.headers`; on a status in `{301,302,303,307,308}` with a `Location`, resolve with `urllib.parse.urljoin`; reject non-http(s) targets (`error`), `is_blocked` targets (`blocked`, not appended), targets already in `chain` (appended, then `loop`); stop with `too_many_hops` if `MAX_HOPS` redirects were already followed and another is required. Catch `httpx.TimeoutException` → `timeout`, other `httpx.HTTPError` → `error`.

- [ ] **Step 7: Run to verify pass.**
  Run: `.venv/bin/python -m pytest -v`
  Expected: all tests pass.

- [ ] **Step 8: Commit** (small commits are fine, e.g. one for `ssrf.py`, one for `chain.py`): `feat: add SSRF guard for private and loopback addresses`, `feat: add redirect chain follower with loop and hop limits`

---

### Task 2: Suspicion rules

**Files:**
- Create: `app/rules.py`, `tests/test_rules.py`

**Interfaces:**
- Consumes: `chain: list[str]` and `problem: str | None` with problem values `None`, `"loop"`, `"too_many_hops"`, `"timeout"`, `"error"`, `"blocked"` (produced by Task 1's `ChainResult`; Task 2 imports nothing from Task 1).
- Produces: `evaluate(chain: list[str], problem: str | None) -> list[str]` returning reason strings exactly as listed in "Decisions" (empty list = safe). Pure, no I/O.

- [ ] **Step 1: Write failing tests in `tests/test_rules.py`.** Each calls `evaluate([...], None)` unless noted:
  - `test_single_url_is_safe`: `["https://example.com"]` → `[]`.
  - `test_two_hops_ok`: three same-domain URLs → `[]`; three hops (four URLs) → contains `"more than 2 redirects (3)"`.
  - `test_final_domain_differs`: `["https://a.com", "https://b.com"]` → `["final domain differs from original (a.com -> b.com)"]`.
  - `test_host_normalisation`: `["HTTP://Example.COM:8080/x", "https://www.example.com/y"]` → `[]`.
  - `test_free_hosting`: for each of `workers.dev`, `r2.dev`, `firebaseapp.com`, `web.app`, final `https://my-site.<suffix>` after first `https://a.com` includes `"final domain is on free hosting (my-site.<suffix>)"`; `https://notworkers.dev` as final is not flagged for hosting; bare `https://workers.dev` is flagged.
  - `test_free_hosting_only_checks_final`: chain `[a.com, x.workers.dev, a.com]` → no hosting reason.
  - `test_brand_swap`: `https://micros0ft.com` → contains `"possible brand impersonation: micros0ft.com looks like microsoft"`; `https://paypa1.com` → `... paypa1.com looks like paypal`; `https://micros0ft-support.com` flagged; brand swap in a middle hop (not final) is flagged too.
  - `test_real_brands_not_flagged`: `https://www.microsoft.com`, `https://paypal.com`, `https://login.microsoftonline.com` → `[]`.
  - `test_problems_map_to_reasons`: `evaluate([a], "loop")` → `["redirect loop detected"]`; `"too_many_hops"` → contains `"more than 5 redirects"`; `"timeout"` → `["request timed out"]`; `"error"` → `["request failed"]`; `"blocked"` → `["redirect target is a blocked address"]`.

- [ ] **Step 2: Run to verify failure.**
  Run: `.venv/bin/python -m pytest tests/test_rules.py -v`
  Expected: FAIL, `app.rules` not found.

- [ ] **Step 3: Implement `evaluate` in `app/rules.py`.** Module constants `FREE_HOSTS` (the four suffixes) and `BRANDS` (five names); small private helpers `_host(url) -> str` (lowercase `urlsplit(url).hostname`, strip leading `www.`) and `_brand_lookalike(host) -> str | None`. Reason order: problem, hop count, domain differs, free hosting, brand (one per offending host, chain order, no duplicates).

- [ ] **Step 4: Run to verify pass.**
  Run: `.venv/bin/python -m pytest tests/test_rules.py -v`
  Expected: all passed.

- [ ] **Step 5: Commit** `feat: add suspicion rules for redirect chains`

---

### Task 3: `POST /links/check` endpoint

**Files:**
- Create: `app/main.py`, `tests/test_api.py`

**Interfaces:**
- Consumes: `follow_chain(url, client) -> ChainResult` (Task 1), `is_blocked(url) -> bool` (Task 1), `evaluate(chain, problem) -> list[str]` (Task 2), the `public_dns` autouse fixture (Task 1 `tests/conftest.py`).
- Produces, in `app/main.py`:
  - `app: FastAPI`
  - `get_client() -> Iterator[httpx.Client]`: FastAPI dependency yielding `httpx.Client(follow_redirects=False)`, closed afterwards. Tests replace it via `app.dependency_overrides[get_client]`.
  - `CheckRequest(url: str)`, rejecting anything whose scheme isn't `http`/`https` or that has no hostname (pydantic validator, yields 422).
  - Endpoint `check(body: CheckRequest, client = Depends(get_client)) -> dict` (plain `def`, sync): raises `HTTPException(422)` if `is_blocked(body.url)`; otherwise returns `{"verdict", "chain", "reasons"}` with `verdict = "suspicious" if reasons else "safe"`.

- [ ] **Step 1: Write failing tests in `tests/test_api.py`.** Fixture builds a `TestClient(app)` with `get_client` overridden to a mock-transport client whose handler records requested URLs; it must clear `app.dependency_overrides` afterwards. Tests:
  - `test_safe_link`: 200 at `https://example.com` → 200 response `{"verdict": "safe", "chain": ["https://example.com"], "reasons": []}`.
  - `test_suspicious_domain_change`: `https://a.com`→302→`https://b.com`→200 → verdict `suspicious`, chain of two, reasons `["final domain differs from original (a.com -> b.com)"]`.
  - `test_loop_is_suspicious`: `a`→`b`→`a` → verdict `suspicious`, reasons contain `"redirect loop detected"`.
  - `test_timeout_is_200_suspicious`: handler raises `httpx.ReadTimeout("x")` → status 200, verdict `suspicious`, reasons contain `"request timed out"`.
  - `test_brand_swap_input`: `https://paypa1.com` → 200 → suspicious, reason mentions `paypal`.
  - `test_invalid_urls_422`: parametrize `"not a url"`, `"ftp://example.com"`, `"javascript:alert(1)"`, `"http://"`, `""` → 422; also missing `url` key → 422.
  - `test_blocked_input_urls_422` (parametrized): `http://127.0.0.1/`, `http://169.254.169.254/`, `http://10.0.0.1/`, `http://[::1]/`, and `http://localhost/` (patch resolver to `127.0.0.1`) → 422 and the recorded request list is empty.
  - `test_blocked_redirect_is_suspicious`: `https://a.com`→302 `Location: http://10.0.0.1/admin` → 200, verdict `suspicious`, chain `["https://a.com"]`, reasons contain `"redirect target is a blocked address"`, `10.0.0.1` never requested.

- [ ] **Step 2: Run to verify failure.**
  Run: `.venv/bin/python -m pytest tests/test_api.py -v`
  Expected: FAIL, `app.main` not found.

- [ ] **Step 3: Implement `app/main.py`** per the Interfaces block.

- [ ] **Step 4: Run the whole suite.**
  Run: `.venv/bin/python -m pytest -v`
  Expected: all tests across all files pass.

- [ ] **Step 5: Commit** `feat: add POST /links/check endpoint`

---

## Self-Review

- **Spec coverage:** endpoint + body/response shape → Task 3; 5 hops, loop, 5s per hop, streamed GET → Task 1; four suspicion rules → Task 2; SSRF on input (Task 3, 422) and redirect targets (Task 1, problem `blocked`; Task 2 maps it to a reason); network-mocked pytest (HTTP via `MockTransport`, DNS via `public_dns` fixture) → all tasks.
- **Type consistency:** `ChainResult.chain/problem` and `evaluate(chain, problem)` use the same names and problem strings (`loop`, `too_many_hops`, `timeout`, `error`, `blocked`) in Tasks 1–3. Task 2 and Task 1 share no files, so they can run in parallel.
- **Not built, on purpose:** DNS-rebinding defense (IP pinning), auth/rate limiting, caching, async client, public-suffix-aware domain comparison.
