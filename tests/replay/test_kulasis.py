"""Replay tests for KULASIS — full SimpleSAMLphp walk + Shift_JIS decoding."""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.exceptions import OTPRequiredError, SPAccessError
from kuauth.services.kulasis import KULASIS
from tests.replay._router import (
    build_simplesaml_idp_router,
    load_bytes,
    sp_entry_redirect_response,
)

SP_ENTRY = "https://www.k.kyoto-u.ac.jp/student/la/top"
SP_ACS = "https://www.k.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def test_top_returns_sjis_decoded_html(fixtures_dir, http_client):
    body_sjis = load_bytes(fixtures_dir, "kulasis_top.html.sjis")
    sjis_response = httpx.Response(
        200,
        headers={"Content-Type": "text/html; charset=Shift_JIS"},
        content=body_sjis,
    )

    with respx.mock(assert_all_called=False) as mock:
        build_simplesaml_idp_router(
            mock,
            fixtures_dir,
            saml_autosubmit_fixture="saml_autosubmit_kulasis.html",
            sp_saml_acs_url=SP_ACS,
            sp_redirect_location=SP_ENTRY,
            shibsession_host="www.k.kyoto-u.ac.jp",
            shibsession_cookie_name="_shibsession_KULASIS",
        )
        # SP entry is hit twice: first to kick off SSO, second after SAML
        # 302 redirects back. The user's explicit .get() is the third.
        mock.get(SP_ENTRY).mock(
            side_effect=[
                sp_entry_redirect_response(),
                sjis_response,
                sjis_response,
            ]
        )

        auth = KyotoUAuth("u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client)
        html = KULASIS(auth).get("/student/la/top").text

    assert "\u6559\u52d9\u60c5\u5831\u30b7\u30b9\u30c6\u30e0" in html  # 教務情報システム
    assert "TEST_COURSE_A" in html


def test_first_access_walks_simplesaml_and_sets_shibsession(fixtures_dir, http_client):
    """Pins: the full SimpleSAMLphp chain runs lazily on first SP access
    and lands a _shibsession_* cookie in the shared jar (what used to be
    KyotoUAuth.login()'s responsibility).
    """
    body_sjis = load_bytes(fixtures_dir, "kulasis_top.html.sjis")
    sjis_response = httpx.Response(
        200,
        headers={"Content-Type": "text/html; charset=Shift_JIS"},
        content=body_sjis,
    )

    with respx.mock(assert_all_called=False) as mock:
        build_simplesaml_idp_router(
            mock,
            fixtures_dir,
            saml_autosubmit_fixture="saml_autosubmit_kulasis.html",
            sp_saml_acs_url=SP_ACS,
            sp_redirect_location=SP_ENTRY,
            shibsession_host="www.k.kyoto-u.ac.jp",
            shibsession_cookie_name="_shibsession_KULASIS",
        )
        mock.get(SP_ENTRY).mock(
            side_effect=[
                sp_entry_redirect_response(),
                sjis_response,
                sjis_response,
            ]
        )

        auth = KyotoUAuth("u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client)
        assert not any(c.name.startswith("_shibsession_") for c in http_client.cookies.jar)
        KULASIS(auth).get("/student/la/top")
        assert any(c.name.startswith("_shibsession_") for c in http_client.cookies.jar)


def test_ensure_session_runs_once(fixtures_dir, http_client):
    """Second .get() on the same service instance must not re-walk the IdP."""
    body_sjis = load_bytes(fixtures_dir, "kulasis_top.html.sjis")
    sjis_response = httpx.Response(
        200,
        headers={"Content-Type": "text/html; charset=Shift_JIS"},
        content=body_sjis,
    )

    with respx.mock(assert_all_called=False) as mock:
        build_simplesaml_idp_router(
            mock,
            fixtures_dir,
            saml_autosubmit_fixture="saml_autosubmit_kulasis.html",
            sp_saml_acs_url=SP_ACS,
            sp_redirect_location=SP_ENTRY,
            shibsession_host="www.k.kyoto-u.ac.jp",
            shibsession_cookie_name="_shibsession_KULASIS",
        )
        mock.get(SP_ENTRY).mock(
            side_effect=[
                sp_entry_redirect_response(),
                sjis_response,
                sjis_response,
                sjis_response,
            ]
        )

        auth = KyotoUAuth("u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client)
        svc = KULASIS(auth)
        svc.get("/student/la/top")
        login_cgi_calls = len([r for r in mock.calls if "/pub/login.cgi" in str(r.request.url)])
        svc.get("/student/la/top")
        login_cgi_calls_after = len(
            [r for r in mock.calls if "/pub/login.cgi" in str(r.request.url)]
        )
        # No new IdP walk on the second call.
        assert login_cgi_calls == login_cgi_calls_after


def test_no_totp_raises_on_otp_form(fixtures_dir, http_client):
    """Without any OTP source, reaching otplogin.cgi raises OTPRequiredError
    from inside .get() (not at KyotoUAuth construction).
    """
    with respx.mock(assert_all_called=False) as mock:
        build_simplesaml_idp_router(
            mock,
            fixtures_dir,
            saml_autosubmit_fixture="saml_autosubmit_kulasis.html",
            sp_saml_acs_url=SP_ACS,
            sp_redirect_location=SP_ENTRY,
            shibsession_host="www.k.kyoto-u.ac.jp",
            shibsession_cookie_name="_shibsession_KULASIS",
        )
        mock.get(SP_ENTRY).mock(return_value=sp_entry_redirect_response())

        auth = KyotoUAuth("u", "p", http=http_client)  # no totp_secret
        with pytest.raises(OTPRequiredError):
            KULASIS(auth).get("/student/la/top")


def test_missing_shibsession_raises(fixtures_dir, http_client):
    """If the SAML POST settles with 200 but no _shibsession_* cookie,
    _ensure_session must raise SPAccessError rather than latching
    _sp_ready=True on an unauthenticated page.
    """
    body_sjis = load_bytes(fixtures_dir, "kulasis_top.html.sjis")
    with respx.mock(assert_all_called=False) as mock:
        build_simplesaml_idp_router(
            mock,
            fixtures_dir,
            saml_autosubmit_fixture="saml_autosubmit_kulasis.html",
            sp_saml_acs_url=SP_ACS,
            sp_redirect_location=SP_ENTRY,
            shibsession_host="www.k.kyoto-u.ac.jp",
            shibsession_cookie_name="_shibsession_KULASIS",
        )
        # Override SAML POST to return 200 without Set-Cookie.
        mock.post(SP_ACS).mock(return_value=httpx.Response(200, text="<html></html>"))
        mock.get(SP_ENTRY).mock(
            side_effect=[
                sp_entry_redirect_response(),
                httpx.Response(
                    200,
                    headers={"Content-Type": "text/html; charset=Shift_JIS"},
                    content=body_sjis,
                ),
            ]
        )

        auth = KyotoUAuth("u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client)
        with pytest.raises(SPAccessError, match="no _shibsession_"):
            KULASIS(auth).get("/student/la/top")


def test_post_and_request_set_sjis_encoding(fixtures_dir, http_client):
    """``KULASIS.post`` and ``KULASIS.request`` override ``response.encoding``
    to cp932 just like ``.get`` does. Without these overrides, httpx's
    charset auto-detection would mis-decode any SJIS body returned by a
    POST/PUT (e.g., a course-registration submit). Pin the override
    explicitly — autodetection on a body without a Content-Type charset
    silently falls back to UTF-8."""
    body_sjis = "登録完了".encode("cp932")  # registration complete
    sjis_response_factory = lambda: httpx.Response(  # noqa: E731
        200,
        # No charset in Content-Type — forces httpx to guess. The override
        # is what makes ``.text`` decode correctly.
        headers={"Content-Type": "text/html"},
        content=body_sjis,
    )

    with respx.mock(assert_all_called=False) as mock:
        build_simplesaml_idp_router(
            mock,
            fixtures_dir,
            saml_autosubmit_fixture="saml_autosubmit_kulasis.html",
            sp_saml_acs_url=SP_ACS,
            sp_redirect_location=SP_ENTRY,
            shibsession_host="www.k.kyoto-u.ac.jp",
            shibsession_cookie_name="_shibsession_KULASIS",
        )
        mock.get(SP_ENTRY).mock(
            side_effect=[
                sp_entry_redirect_response(),
                sjis_response_factory(),
            ]
        )
        mock.post("https://www.k.kyoto-u.ac.jp/student/la/submit").mock(
            return_value=sjis_response_factory()
        )
        mock.route(method="PUT", url="https://www.k.kyoto-u.ac.jp/student/la/update").mock(
            return_value=sjis_response_factory()
        )

        auth = KyotoUAuth("u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client)
        svc = KULASIS(auth)

        post_resp = svc.post("/student/la/submit", data={"course": "X"})
        assert post_resp.encoding == "cp932"
        assert post_resp.text == "登録完了"

        put_resp = svc.request("PUT", "/student/la/update", data={"k": "v"})
        assert put_resp.encoding == "cp932"
        assert put_resp.text == "登録完了"


def test_shibsession_from_sibling_sp_does_not_pass_guard(fixtures_dir, http_client):
    """Regression: the shibsession guard must be scoped to THIS SP's host.

    A shared ``KyotoUAuth`` may already carry ``_shibsession_*`` for a
    sibling SP (e.g. MyKULINE on kuline.kulib.kyoto-u.ac.jp). If KULASIS's
    own ACS then fails to set a cookie, the guard must still raise —
    otherwise we'd latch ``_sp_ready=True`` and the next request would
    silently be unauthenticated against KULASIS.
    """
    body_sjis = load_bytes(fixtures_dir, "kulasis_top.html.sjis")
    with respx.mock(assert_all_called=False) as mock:
        build_simplesaml_idp_router(
            mock,
            fixtures_dir,
            saml_autosubmit_fixture="saml_autosubmit_kulasis.html",
            sp_saml_acs_url=SP_ACS,
            sp_redirect_location=SP_ENTRY,
            shibsession_host="www.k.kyoto-u.ac.jp",
            shibsession_cookie_name="_shibsession_KULASIS",
        )
        mock.post(SP_ACS).mock(return_value=httpx.Response(200, text="<html></html>"))
        mock.get(SP_ENTRY).mock(
            side_effect=[
                sp_entry_redirect_response(),
                httpx.Response(
                    200,
                    headers={"Content-Type": "text/html; charset=Shift_JIS"},
                    content=body_sjis,
                ),
            ]
        )

        # Pre-seed a sibling SP's shibsession into the shared jar.
        http_client.cookies.set(
            "_shibsession_MYKULINE",
            "SIBLING_VALUE",
            domain="kuline.kulib.kyoto-u.ac.jp",
            path="/",
        )

        auth = KyotoUAuth("u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client)
        with pytest.raises(SPAccessError, match="no _shibsession_"):
            KULASIS(auth).get("/student/la/top")
