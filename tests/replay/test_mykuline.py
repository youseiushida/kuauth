"""Replay test for MyKULINE (consent + localStorage + EPPN exchange)."""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.services.mykuline import MyKULINE

from tests.replay._router import build_login_router, load_text


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def test_search_top_full_consent_flow(fixtures_dir, http_client):
    consent_html = load_text(fixtures_dir, "shib_consent.html")
    ls_html = load_text(fixtures_dir, "shib_localstorage.html")
    saml_html = load_text(fixtures_dir, "saml_autosubmit_mykuline.html")
    eppn_html = load_text(fixtures_dir, "mykuline_eppn.html")
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)

        # Entry path → consent page
        mock.get(
            "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/"
        ).mock(return_value=httpx.Response(200, text=consent_html))

        # POST consent → localStorage form
        mock.post(
            url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/idp/profile/SAML2/Redirect/SSO.*execution=e1s1.*"
        ).mock(return_value=httpx.Response(200, text=ls_html))

        # POST localStorage → SAML autosubmit
        mock.post(
            url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/idp/profile/SAML2/Redirect/SSO.*execution=e1s2.*"
        ).mock(return_value=httpx.Response(200, text=saml_html))

        # POST SAML → EPPN form (via 302 with shibsession cookie)
        mock.post(
            "https://kuline.kulib.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
        ).mock(
            return_value=httpx.Response(
                302,
                headers={
                    "Location": "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/",
                    "Set-Cookie": (
                        "_shibsession_MYKULINE=TEST; "
                        "Path=/; Domain=kuline.kulib.kyoto-u.ac.jp; Secure"
                    ),
                },
            )
        )
        # Follow-up GET after SAML returns EPPN form
        mock.get(
            "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/"
        ).mock(return_value=httpx.Response(200, text=eppn_html))

        # POST EPPN form → search top landing
        mock.post(
            "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/"
        ).mock(return_value=httpx.Response(200, text=search_html))

        # search_top() GET after session is ready
        mock.get(
            "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/"
        ).mock(return_value=httpx.Response(200, text=search_html))

        auth = KyotoUAuth(
            "u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client
        )
        mk = MyKULINE(auth.login())
        html = mk.get("/opac/opac_search/").text

    assert "MyKULINE" in html


def test_widget_returns_html(fixtures_dir, http_client):
    consent_html = load_text(fixtures_dir, "shib_consent.html")
    ls_html = load_text(fixtures_dir, "shib_localstorage.html")
    saml_html = load_text(fixtures_dir, "saml_autosubmit_mykuline.html")
    eppn_html = load_text(fixtures_dir, "mykuline_eppn.html")
    widget_html = load_text(fixtures_dir, "mykuline_widget.html")
    search_html = load_text(fixtures_dir, "mykuline_search_top.html")

    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)

        mock.get(
            "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/"
        ).mock(side_effect=[
            httpx.Response(200, text=consent_html),
            httpx.Response(200, text=eppn_html),
        ])
        mock.post(
            url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/idp/profile/SAML2/Redirect/SSO.*execution=e1s1.*"
        ).mock(return_value=httpx.Response(200, text=ls_html))
        mock.post(
            url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/idp/profile/SAML2/Redirect/SSO.*execution=e1s2.*"
        ).mock(return_value=httpx.Response(200, text=saml_html))
        mock.post(
            "https://kuline.kulib.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
        ).mock(
            return_value=httpx.Response(
                302,
                headers={
                    "Location": "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_secure/opac_search/",
                    "Set-Cookie": "_shibsession_MYKULINE=TEST; Path=/; Secure",
                },
            )
        )
        mock.post(
            "https://kuline.kulib.kyoto-u.ac.jp/opac/opac_search/"
        ).mock(return_value=httpx.Response(200, text=search_html))
        mock.get(
            url__regex=r"^https://kuline\.kulib\.kyoto-u\.ac\.jp/opac/myopac/loan/widget/.*"
        ).mock(return_value=httpx.Response(200, text=widget_html))

        auth = KyotoUAuth(
            "u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client
        )
        html = MyKULINE(auth.login()).get(
            "/opac/myopac/loan/widget/", params={"lang": 0, "countercd": 106000}
        ).text

    assert "loan" in html or "TEST_BOOK_A" in html
