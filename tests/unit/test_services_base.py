"""Unit tests for ShibbolethSPService's generic get/post/request + KULASIS SJIS override."""

from __future__ import annotations

import httpx
import pytest

from kuauth.auth import KyotoUAuth
from kuauth.exceptions import AuthenticationError, ConsentRequiredError, SPAccessError
from kuauth.services._base import ShibbolethSPService
from kuauth.services.kulasis import KULASIS


class _FakeService(ShibbolethSPService):
    BASE_URL = "https://example.test"
    ENTRY_PATH = "/entry"


class _SubdomainService(ShibbolethSPService):
    BASE_URL = "https://app.example.test"
    ENTRY_PATH = "/entry"


def _auth_with_mock(responses: dict[tuple[str, str], httpx.Response]) -> KyotoUAuth:
    def handler(req: httpx.Request) -> httpx.Response:
        key = (req.method, str(req.url))
        if key not in responses:
            return httpx.Response(404, text="unmatched " + repr(key))
        return responses[key]

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, base_url="https://example.test")
    return KyotoUAuth("u", "p", http=client)


def _ready_service(cls, responses) -> ShibbolethSPService:
    auth = _auth_with_mock(responses)
    svc = cls(auth)
    svc._sp_ready = True
    return svc


def test_resolve_absolute_passes_through():
    svc = _FakeService(_auth_with_mock({}))
    assert svc._resolve("https://other.example/x") == "https://other.example/x"
    assert svc._resolve("http://other.example/x") == "http://other.example/x"


def test_resolve_relative_prepends_base():
    svc = _FakeService(_auth_with_mock({}))
    assert svc._resolve("/foo") == "https://example.test/foo"


def test_resolve_relative_without_leading_slash_is_prefixed():
    # Missing leading slash must not host-glue into "https://hostfoo".
    svc = _FakeService(_auth_with_mock({}))
    assert svc._resolve("foo") == "https://example.test/foo"
    assert svc._resolve("foo/bar") == "https://example.test/foo/bar"


def test_resolve_empty_yields_base_with_trailing_slash():
    # Degenerate input: pin the current behavior so a future refactor
    # doesn't silently flip between BASE_URL and BASE_URL + "/".
    svc = _FakeService(_auth_with_mock({}))
    assert svc._resolve("") == "https://example.test/"


def test_get_hits_resolved_url():
    svc = _ready_service(
        _FakeService,
        {("GET", "https://example.test/ping"): httpx.Response(200, text="pong")},
    )
    r = svc.get("/ping")
    assert r.status_code == 200 and r.text == "pong"


def test_post_forwards_body():
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        captured["body"] = req.content
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth = KyotoUAuth("u", "p", http=client)
    svc = _FakeService(auth)
    svc._sp_ready = True

    r = svc.post("/submit", data={"k": "v"})
    assert r.status_code == 200
    assert captured["url"] == "https://example.test/submit"
    assert b"k=v" in captured["body"]


def test_request_supports_arbitrary_method():
    svc = _ready_service(
        _FakeService,
        {("PUT", "https://example.test/x"): httpx.Response(204)},
    )
    r = svc.request("PUT", "/x")
    assert r.status_code == 204


def test_get_accepts_absolute_url():
    svc = _ready_service(
        _FakeService,
        {("GET", "https://other.example/z"): httpx.Response(200, text="z")},
    )
    r = svc.get("https://other.example/z")
    assert r.text == "z"


def test_cookies_returns_service_scoped_detached_jar():
    svc = _ready_service(_SubdomainService, {})
    svc.http.cookies.set("subdomain", "SUB", domain="app.example.test", path="/")
    svc.http.cookies.set("parent", "PARENT", domain="example.test", path="/")
    svc.http.cookies.set("other", "OTHER", domain="other.example.test", path="/")
    svc.http.cookies.set("idp", "IDP", domain="auth.example.test", path="/")

    cookies = svc.cookies()

    assert dict(cookies.items()) == {
        "subdomain": "SUB",
        "parent": "PARENT",
    }
    cookies.set("local", "ONLY_COPY", domain="app.example.test", path="/")
    assert "local" not in dict(svc.http.cookies.items())


def test_kulasis_get_decodes_sjis():
    sjis_bytes = "京大".encode("cp932")
    svc = _ready_service(
        KULASIS,
        {
            (
                "GET",
                "https://www.k.kyoto-u.ac.jp/student/la/top",
            ): httpx.Response(200, content=sjis_bytes)
        },
    )
    r = svc.get("/student/la/top")
    assert r.encoding == "cp932"
    assert r.text == "京大"
    assert r.content == sjis_bytes


def test_get_triggers_ensure_session_when_not_ready(monkeypatch):
    svc = _FakeService(
        _auth_with_mock({("GET", "https://example.test/x"): httpx.Response(200, text="ok")})
    )
    calls = {"n": 0}

    def fake_ensure(self):
        calls["n"] += 1
        self._sp_ready = True

    monkeypatch.setattr(_FakeService, "_ensure_session", fake_ensure)
    svc.get("/x")
    assert calls["n"] == 1
    # Second call is a no-op (already ready), ensure_session still called (but sees _sp_ready)
    svc.get("/x")
    assert calls["n"] == 2


def test_cookies_triggers_ensure_session_when_not_ready(monkeypatch):
    svc = _FakeService(_auth_with_mock({}))
    calls = {"n": 0}

    def fake_ensure(self):
        calls["n"] += 1
        self.http.cookies.set("session", "READY", domain="example.test", path="/")
        self._sp_ready = True

    monkeypatch.setattr(_FakeService, "_ensure_session", fake_ensure)

    cookies = svc.cookies()

    assert calls["n"] == 1
    assert dict(cookies.items()) == {"session": "READY"}


# --- Guard-path coverage for _advance_through_idp ---
#
# Each test below pins one of the explicit raise paths in the IdP walk so a
# regression that silently latches ``_sp_ready=True`` on an unauthenticated
# page would fail loudly here, rather than waiting for the daily live cron.

_LOGIN_FORM_HTML = """
<html><body>
<form id="login" method="post" action="login.cgi">
  <input name="username">
  <input type="password" name="password">
  <input type="hidden" name="op" value="login">
  <input type="hidden" name="sessid" value="TEST_SESSID">
</form>
</body></html>
"""

_OTP_FORM_HTML = """
<html><body>
<form id="login" method="post" action="otplogin.cgi">
  <input name="username">
  <input type="password" name="password">
  <input type="hidden" name="op" value="login">
  <input type="hidden" name="sessid" value="TEST_SESSID_OTP">
</form>
</body></html>
"""

_SHIB_IDP_LOGIN_HTML = """
<html><body>
<form method="post" action="/idp/profile/SAML2/Redirect/SSO?execution=e1s1">
  <input name="j_username">
  <input type="password" name="j_password">
  <input type="hidden" name="csrf_token" value="TEST_CSRF">
</form>
</body></html>
"""

_LOCALSTORAGE_FORM_HTML = """
<html><body>
<form method="post" action="/idp/profile/SAML2/Redirect/SSO?execution=e1s2">
  <input type="hidden" name="csrf_token" value="TEST_CSRF">
  <input type="hidden" name="shib_idp_ls_exception.shib_idp_persistent_ss" value="">
  <input type="hidden" name="shib_idp_ls_success.shib_idp_persistent_ss" value="">
</form>
</body></html>
"""

_CONSENT_HTML = """
<html><body>
<form method="post" action="/idp/profile/SAML2/Redirect/SSO?execution=e1s3">
  <input type="hidden" name="csrf_token" value="TEST_CSRF">
  <input type="checkbox" name="_shib_idp_consentIds" value="uid" checked>
  <input type="checkbox" name="_shib_idp_consentOptions" value="_shib_idp_rememberConsent">
</form>
</body></html>
"""


class _RequiresConsentService(ShibbolethSPService):
    BASE_URL = "https://example.test"
    ENTRY_PATH = "/entry"
    REQUIRES_CONSENT = True


def _persistent_form_handler(html: str):
    """Return a MockTransport handler that serves the same HTML for any URL.

    Used to simulate a credential-rejection loop: the IdP keeps returning
    the same form because the submit didn't take.
    """

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html)

    return handler


def _client_with_handler(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_password_rejected_raises_authentication_error():
    """Login form persists after POST → password was rejected, raise immediately
    (don't retry — Kyoto-U lockout threshold is low)."""
    client = _client_with_handler(_persistent_form_handler(_LOGIN_FORM_HTML))
    auth = KyotoUAuth("u", "wrong", totp_secret="JBSWY3DPEHPK3PXP", http=client)
    svc = _FakeService(auth)
    with pytest.raises(AuthenticationError, match="password rejected"):
        svc.get("/anything")


def test_otp_rejected_raises_authentication_error():
    """OTP form persists after POST → OTP was rejected, raise immediately."""
    client = _client_with_handler(_persistent_form_handler(_OTP_FORM_HTML))
    auth = KyotoUAuth("u", "p", onetime_password="000000", http=client)
    svc = _FakeService(auth)
    with pytest.raises(AuthenticationError, match="OTP rejected"):
        svc.get("/anything")


def test_shib_idp_login_rejected_raises_authentication_error():
    """j_username form persists after POST → Java Shib IdP rejected creds."""
    client = _client_with_handler(_persistent_form_handler(_SHIB_IDP_LOGIN_HTML))
    auth = KyotoUAuth("u", "wrong", http=client)
    svc = _FakeService(auth)
    with pytest.raises(AuthenticationError, match="Shib IdP rejected"):
        svc.get("/anything")


def test_hop_budget_exceeded_raises_sp_access_error():
    """If the IdP keeps returning an interstitial form past the 20-hop budget,
    raise SPAccessError rather than spinning forever or settling on it."""
    # Localstorage form has no early-rejection check, so the loop just
    # consumes its hop budget and exits, triggering the post-loop guard.
    client = _client_with_handler(_persistent_form_handler(_LOCALSTORAGE_FORM_HTML))
    auth = KyotoUAuth("u", "p", http=client)
    svc = _FakeService(auth)
    with pytest.raises(SPAccessError, match="did not complete within 20 hops"):
        svc.get("/anything")


def test_default_walk_consent_flow_raises():
    """A subclass with REQUIRES_CONSENT=True but no _walk_consent_flow override
    must raise ConsentRequiredError rather than silently skipping the page."""
    client = _client_with_handler(_persistent_form_handler(_CONSENT_HTML))
    auth = KyotoUAuth("u", "p", http=client)
    svc = _RequiresConsentService(auth)
    with pytest.raises(ConsentRequiredError):
        svc.get("/anything")


def test_follow_meta_refresh_hop_budget_exceeded():
    """A meta-refresh chain that never settles must raise SPAccessError after
    max_hops, not spin until httpx times out. Real failure mode: an IdP in
    maintenance returning a redirect-loop refresh page."""
    refresh_html = '<html><head><meta http-equiv="refresh" content="0; url=/next"></head></html>'
    client = _client_with_handler(_persistent_form_handler(refresh_html))
    auth = KyotoUAuth("u", "p", http=client)
    svc = _FakeService(auth)

    initial = httpx.Response(
        200,
        text=refresh_html,
        request=httpx.Request("GET", "https://example.test/start"),
    )
    with pytest.raises(SPAccessError, match="meta-refresh chain did not settle"):
        svc._follow_meta_refresh(initial)


class TestCookieMatchesHost:
    """Cookie-domain → host scoping for ``_shibsession_*`` matching.

    Pure function with subtle correctness traps (off-by-one in suffix
    matching, leading-dot handling, substring spoofing). Cheap to test
    because there are only two args; testing the negative cases is the
    whole point — exact-match-only would silently lose Domain=parent
    cookies, while substring matching would let ``fakekyoto-u.ac.jp``
    accept a ``.kyoto-u.ac.jp`` cookie.
    """

    def test_exact_match(self):
        assert ShibbolethSPService._cookie_matches_host(
            "www.k.kyoto-u.ac.jp", "www.k.kyoto-u.ac.jp"
        )

    def test_leading_dot_stripped(self):
        # ``Set-Cookie: Domain=.kyoto-u.ac.jp`` → cookie_host = "kyoto-u.ac.jp",
        # which must still match the exact-host case.
        assert ShibbolethSPService._cookie_matches_host(".kyoto-u.ac.jp", "kyoto-u.ac.jp")

    def test_parent_domain_matches_subdomain(self):
        # Domain=.kyoto-u.ac.jp cookie is sent to www.k.kyoto-u.ac.jp per
        # RFC 6265 — the suffix path must accept it.
        assert ShibbolethSPService._cookie_matches_host(".kyoto-u.ac.jp", "www.k.kyoto-u.ac.jp")

    def test_substring_spoofing_rejected(self):
        # Critical: ``fakekyoto-u.ac.jp`` ends with ``kyoto-u.ac.jp`` as a
        # plain string, but is a different registrable domain. The dot
        # separator in ``"." + cookie_host`` is what blocks this.
        assert not ShibbolethSPService._cookie_matches_host(".kyoto-u.ac.jp", "fakekyoto-u.ac.jp")

    def test_unrelated_domain_rejected(self):
        assert not ShibbolethSPService._cookie_matches_host(".other.ac.jp", "www.k.kyoto-u.ac.jp")

    def test_sibling_subdomain_rejected(self):
        # A cookie scoped to a specific host must not bleed to a sibling.
        assert not ShibbolethSPService._cookie_matches_host(
            "kuline.kulib.kyoto-u.ac.jp", "www.k.kyoto-u.ac.jp"
        )

    def test_empty_inputs_rejected(self):
        # Defense in depth: cookie jars can carry blank domains
        # (host-only cookies on some libraries) — refuse rather than
        # matching everything.
        assert not ShibbolethSPService._cookie_matches_host("", "host.example")
        assert not ShibbolethSPService._cookie_matches_host(".kyoto-u.ac.jp", "")
        assert not ShibbolethSPService._cookie_matches_host("", "")
