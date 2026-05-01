"""Replay tests for MyKULINE (authidp1 IdP: consent + localStorage + EPPN).

MyKULINE is Kyoto-U's only SP that routes through ``authidp1.iimc.kyoto-u.ac.jp``
rather than ``auth.iimc.kyoto-u.ac.jp``, so the walk is j_username +
consent + localStorage + SAML instead of login.cgi + otplogin.cgi + SAML.
Crucially, **no OTP** is required — the whole point of the lazy-login
refactor is that MyKULINE-only users don't need ``totp_secret``.

These cassettes short-circuit the j_username step (entry → consent
directly); the real authidp1 walk starts with j_username, but the SP
fixture simulates the interstitials as served at the SP host, which is
functionally equivalent for exercising the loop branches after consent.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.services.mykuline import MyKULINE
from tests.replay._router import load_text


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def _wire_mykuline_flow(mock: respx.Router, fixtures_dir) -> None:
    """Wire the consent → localStorage → SAML → EPPN chain."""
    consent_html = load_text(fixtures_dir, "shib_consent.html")
    ls_html = load_text(fixtures_dir, "shib_localstorage.html")
    saml_html = load_text(fixtures_dir, "saml_autosubmit_mykuline.html")
    eppn_html = load_text(fixtures_dir, "mykuline_eppn.html")

    mock.post(
        url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/idp/profile/SAML2/Redirect/SSO.*execution=e1s1.*"
    ).mock(return_value=httpx.Response(200, text=ls_html))
    mock.post(
        url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/idp/profile/SAML2/Redirect/SSO.*execution=e1s2.*"
    ).mock(return_value=httpx.Response(200, text=saml_html))
    mock.post("https://kuline.kulib.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST").mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/",
                "Set-Cookie": (
                    "_shibsession_MYKULINE=TEST; Path=/; Domain=kuline.kulib.kyoto-u.ac.jp; Secure"
                ),
            },
        )
    )

    # consent_html for the initial entry; eppn_html for the post-SAML
    # 302 GET back to the entry path.
    _ = consent_html, eppn_html  # referenced via side_effect in each test


def test_search_top_full_consent_flow(fixtures_dir, http_client):
    consent_html = load_text(fixtures_dir, "shib_consent.html")
    eppn_html = load_text(fixtures_dir, "mykuline_eppn.html")
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)

        mock.get("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/").mock(
            side_effect=[
                httpx.Response(200, text=consent_html),
                httpx.Response(200, text=eppn_html),
            ]
        )
        mock.post("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )
        mock.get("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )

        # No totp_secret — MyKULINE doesn't route through the OTP IdP.
        auth = KyotoUAuth("u", "p", http=http_client)
        html = MyKULINE(auth).get("/opac/opac_search/").text

    assert "MyKULINE" in html


def test_widget_returns_html(fixtures_dir, http_client):
    consent_html = load_text(fixtures_dir, "shib_consent.html")
    eppn_html = load_text(fixtures_dir, "mykuline_eppn.html")
    widget_html = load_text(fixtures_dir, "mykuline_widget.html")
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)

        mock.get("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/").mock(
            side_effect=[
                httpx.Response(200, text=consent_html),
                httpx.Response(200, text=eppn_html),
            ]
        )
        mock.post("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )
        mock.get(
            url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/opac/myopac/loan/widget/.*"
        ).mock(return_value=httpx.Response(200, text=widget_html))

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
    consent_html = load_text(fixtures_dir, "shib_consent.html")
    eppn_html = load_text(fixtures_dir, "mykuline_eppn.html")
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        _wire_mykuline_flow(mock, fixtures_dir)
        mock.get("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/").mock(
            side_effect=[
                httpx.Response(200, text=consent_html),
                httpx.Response(200, text=eppn_html),
            ]
        )
        mock.post("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )
        mock.get("https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/").mock(
            return_value=httpx.Response(200, text=search_html)
        )

        auth = KyotoUAuth("u", "p", http=http_client)  # deliberately no OTP
        r = MyKULINE(auth).get("/opac/opac_search/")

    assert r.status_code == 200
    assert any(c.name.startswith("_shibsession_") for c in http_client.cookies.jar)
