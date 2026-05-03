"""Replay tests for MyKULINE (authidp1 IdP: j_username + consent + localStorage + EPPN).

MyKULINE is Kyoto-U's only SP that routes through ``authidp1.iimc.kyoto-u.ac.jp``
rather than ``auth.iimc.kyoto-u.ac.jp``, so the walk is j_username +
consent + localStorage + SAML instead of login.cgi + otplogin.cgi + SAML.
Crucially, **no OTP** is required — the whole point of the lazy-login
refactor is that MyKULINE-only users don't need ``totp_secret``.

The cassette serves the interstitials at the SP host (kuline.kulib...)
rather than the real authidp1 host, but this is functionally identical
for exercising the IdP-walk loop branches: ``_submit_shib_idp_login``,
``parse_shib_idp_login_form``, the consent handler, and the localStorage
handler all run in order.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.services.mykuline import MyKULINE
from tests.replay._router import build_authidp1_idp_router, load_text

SP_HOST = "kuline.kulib.kyoto-u.ac.jp"
SP_BASE = f"https://{SP_HOST}"
SP_ENTRY_PATH = "/opac/opac_secure/opac_search/"
SP_ENTRY_URL = SP_BASE + SP_ENTRY_PATH
SP_ACS = SP_BASE + "/Shibboleth.sso/SAML2/POST"


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def _wire_mykuline_flow(mock: respx.Router, fixtures_dir) -> None:
    """Wire j_username → consent → localStorage → SAML → SP entry."""
    build_authidp1_idp_router(
        mock,
        fixtures_dir,
        sp_host=SP_HOST,
        sp_saml_acs_url=SP_ACS,
        sp_redirect_location=SP_ENTRY_URL,
        saml_autosubmit_fixture="saml_autosubmit_mykuline.html",
        shibsession_cookie_name="_shibsession_MYKULINE",
    )


def _entry_responses(fixtures_dir) -> list[httpx.Response]:
    """The two GETs the SP entry receives during a full walk: first the
    j_username form (which kicks off the IdP walk), then the EPPN form
    after the SAML POST 302s back."""
    j_login_html = load_text(fixtures_dir, "shib_idp_login.html")
    eppn_html = load_text(fixtures_dir, "mykuline_eppn.html")
    return [
        httpx.Response(200, text=j_login_html),
        httpx.Response(200, text=eppn_html),
    ]


def test_search_top_full_consent_flow(fixtures_dir, http_client):
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)
        mock.get(SP_ENTRY_URL).mock(side_effect=_entry_responses(fixtures_dir))
        mock.post(f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )
        mock.get(f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )

        # No totp_secret — MyKULINE doesn't route through the OTP IdP.
        auth = KyotoUAuth("u", "p", http=http_client)
        html = MyKULINE(auth).get("/opac/opac_search/").text

    assert "MyKULINE" in html


def test_widget_returns_html(fixtures_dir, http_client):
    widget_html = load_text(fixtures_dir, "mykuline_widget.html")
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)
        mock.get(SP_ENTRY_URL).mock(side_effect=_entry_responses(fixtures_dir))
        mock.post(f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )
        mock.get(url__regex=rf"^{SP_BASE}/opac/myopac/loan/widget/.*").mock(
            return_value=httpx.Response(200, text=widget_html)
        )

        auth = KyotoUAuth("u", "p", http=http_client)
        html = (
            MyKULINE(auth)
            .get("/opac/myopac/loan/widget/", params={"lang": 0, "countercd": 106000})
            .text
        )

    assert "loan" in html or "TEST_BOOK_A" in html


def test_works_without_totp_secret(fixtures_dir, http_client):
    """Pins the whole refactor: MyKULINE must not demand a ``totp_secret``.

    Pre-refactor, ``_ensure_session`` called ``auth.login()`` which went
    through auth.iimc and raised ``OTPRequiredError`` when ``totp_secret``
    was omitted. Post-refactor, MyKULINE's IdP never reaches otplogin.cgi,
    so ``_resolve_otp`` is never called.
    """
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)
        mock.get(SP_ENTRY_URL).mock(side_effect=_entry_responses(fixtures_dir))
        mock.post(f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )
        mock.get(f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )

        auth = KyotoUAuth("u", "p", http=http_client)  # deliberately no OTP
        r = MyKULINE(auth).get("/opac/opac_search/")

    assert r.status_code == 200
    assert any(c.name.startswith("_shibsession_") for c in http_client.cookies.jar)


def test_post_and_request_go_through_securelogin_wrapper(fixtures_dir, http_client):
    """``MyKULINE.post`` and ``MyKULINE.request`` wrap responses through
    ``_follow_securelogin`` exactly like ``.get`` does. Without these
    overrides, a POST that lands on a securelogin shell page would never
    follow through to real content."""
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)
        mock.get(SP_ENTRY_URL).mock(side_effect=_entry_responses(fixtures_dir))
        # Both the user-issued POST and the user-issued PATCH (via
        # .request) hit the same target. Returning real content means
        # _follow_securelogin's hop-zero short-circuit is taken — that's
        # the path users hit when there's no securelogin shell.
        mock.post(f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )
        mock.route(method="PATCH", url=f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )

        auth = KyotoUAuth("u", "p", http=http_client)
        svc = MyKULINE(auth)

        post_resp = svc.post("/opac/opac_search/", data={"q": "test"})
        assert post_resp.status_code == 200
        assert "MyKULINE" in post_resp.text

        # ``request`` must work for arbitrary methods, not just GET/POST.
        patch_resp = svc.request("PATCH", "/opac/opac_search/", data={"q": "test"})
        assert patch_resp.status_code == 200


def test_post_raises_on_securelogin_shell_with_empty_rurl(fixtures_dir, http_client):
    """If a POST lands on a securelogin shell whose ``rurl`` is empty,
    replaying it would self-loop forever. ``_follow_securelogin`` must
    detect this and raise rather than spinning."""
    from kuauth.exceptions import SPAccessError

    shell_html = """
    <html><body>
    <form id="securelogin" action="./" method="post">
      <input type="hidden" name="csrfmiddlewaretoken" value="TEST_CSRF">
      <input type="hidden" name="loginMode" value="login">
      <input type="hidden" name="EPPN" value="test-eppn@example.test">
      <input type="hidden" name="rurl" value="">
      <input type="hidden" name="opkey" value="">
    </form>
    </body></html>
    """

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)
        mock.get(SP_ENTRY_URL).mock(side_effect=_entry_responses(fixtures_dir))
        mock.post(f"{SP_BASE}/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=shell_html)
        )

        auth = KyotoUAuth("u", "p", http=http_client)
        with pytest.raises(SPAccessError, match="empty rurl"):
            MyKULINE(auth).post("/opac/opac_search/", data={"q": "x"})
