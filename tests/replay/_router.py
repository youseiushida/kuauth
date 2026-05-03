"""Helpers for registering respx routes that replay the Kyoto-U SSO chain.

Two builders map to the two Shibboleth IdP arms in use:

- ``build_simplesaml_idp_router`` — ``auth.iimc.kyoto-u.ac.jp`` SimpleSAMLphp
  (login.cgi + authselect.php + otplogin.cgi). Used by KULASIS/KULMS tests.
- ``build_authidp1_idp_router`` — ``authidp1.iimc.kyoto-u.ac.jp`` Java Shib
  IdP (j_username + consent + localStorage). Used by MyKULINE tests.

Both end with a SAML autosubmit POST to the SP's ACS, which 302s with a
``_shibsession_*`` cookie to the SP content URL. Callers mock the SP
entry (to 302 into the IdP) and the final content GET.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import respx


def load_text(fixtures_dir: Path, name: str) -> str:
    return (fixtures_dir / name).read_text(encoding="utf-8")


def load_bytes(fixtures_dir: Path, name: str) -> bytes:
    return (fixtures_dir / name).read_bytes()


def build_simplesaml_idp_router(
    router: respx.Router,
    fixtures_dir: Path,
    *,
    saml_autosubmit_fixture: str,
    sp_saml_acs_url: str,
    sp_redirect_location: str,
    shibsession_host: str,
    shibsession_cookie_name: str = "_shibsession_TEST",
) -> None:
    """Register the SimpleSAMLphp (auth.iimc) chain for a Shibboleth SP.

    Chain simulated:

    1. ``GET .../SSOService.php`` → 302 to /pub/login.cgi
    2. ``GET /pub/login.cgi`` → 200 login form
    3. ``POST /pub/login.cgi`` → 302 to /user/authselect.php
    4. ``GET /user/authselect.php`` → 200 method-picker page (with otplogin link)
    5. ``GET /pub/otplogin.cgi`` (link followed) → 200 OTP form
    6. ``POST /pub/otplogin.cgi`` → 200 SAML auto-submit HTML
    7. ``POST sp_saml_acs_url`` → 302 to ``sp_redirect_location`` with cookie

    Caller is responsible for:

    - Mocking the SP entry URL to 302 → .../SSOService.php (with SAMLRequest)
    - Mocking ``sp_redirect_location`` for the post-SAML content GET
    """
    login_html = load_text(fixtures_dir, "idp_login_form.html")
    authselect_html = load_text(fixtures_dir, "authselect.html")
    otp_html = load_text(fixtures_dir, "idp_otp_form.html")
    saml_html = load_text(fixtures_dir, saml_autosubmit_fixture)

    router.get(
        url__regex=r"^https://auth\.iimc\.kyoto-u\.ac\.jp/saml/saml2/idp/SSOService\.php.*"
    ).mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://auth.iimc.kyoto-u.ac.jp/pub/login.cgi?back=TEST"},
        )
    )
    router.get(url__regex=r"^https://auth\.iimc\.kyoto-u\.ac\.jp/pub/login\.cgi.*").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=login_html,
        )
    )
    # POST login.cgi now lands on the method-picker page rather than going
    # straight to otplogin.cgi — that's the real wire order, and it lets
    # ``_follow_authselect`` get exercised by the replay suite.
    router.post("https://auth.iimc.kyoto-u.ac.jp/pub/login.cgi").mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://auth.iimc.kyoto-u.ac.jp/user/authselect.php?back=TEST"},
        )
    )
    router.get(url__regex=r"^https://auth\.iimc\.kyoto-u\.ac\.jp/user/authselect\.php.*").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=authselect_html,
        )
    )
    router.get(url__regex=r"^https://auth\.iimc\.kyoto-u\.ac\.jp/pub/otplogin\.cgi.*").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=otp_html,
        )
    )
    router.post("https://auth.iimc.kyoto-u.ac.jp/pub/otplogin.cgi").mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=saml_html,
        )
    )
    router.post(sp_saml_acs_url).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": sp_redirect_location,
                "Set-Cookie": (
                    f"{shibsession_cookie_name}=TEST_SHIBSESSION_VALUE; "
                    f"Path=/; Domain={shibsession_host}; Secure"
                ),
            },
        )
    )


def build_authidp1_idp_router(
    router: respx.Router,
    fixtures_dir: Path,
    *,
    sp_host: str,
    sp_saml_acs_url: str,
    sp_redirect_location: str,
    saml_autosubmit_fixture: str,
    shibsession_cookie_name: str,
) -> None:
    """Register the Java Shib IdP (authidp1) chain for a Shibboleth SP.

    Chain simulated (interstitials served at the SP host, mirroring how
    the existing MyKULINE fixtures were recorded — the real authidp1 host
    is ``authidp1.iimc.kyoto-u.ac.jp`` but functionally identical for
    testing the IdP-walk loop branches):

    1. ``GET sp entry`` → 200 j_username login form (caller wires entry GET)
    2. ``POST .../execution=e1s0`` → 200 consent page
    3. ``POST .../execution=e1s1`` → 200 localStorage-sync form
    4. ``POST .../execution=e1s2`` → 200 SAML auto-submit HTML
    5. ``POST sp_saml_acs_url`` → 302 to ``sp_redirect_location`` with cookie

    The execution-step numbering matches the form ``action=`` values in
    the fixtures (``shib_idp_login.html`` → e1s0, ``shib_consent.html`` →
    e1s1, ``shib_localstorage.html`` → e1s2). Bumping any fixture's
    execution token requires a matching update here.
    """
    consent_html = load_text(fixtures_dir, "shib_consent.html")
    ls_html = load_text(fixtures_dir, "shib_localstorage.html")
    saml_html = load_text(fixtures_dir, saml_autosubmit_fixture)

    sso_url_re = (
        r"^https://" + re.escape(sp_host) + r"/idp/profile/SAML2/Redirect/SSO\?execution=e1s"
    )
    router.post(url__regex=sso_url_re + r"0.*").mock(
        return_value=httpx.Response(200, text=consent_html)
    )
    router.post(url__regex=sso_url_re + r"1.*").mock(return_value=httpx.Response(200, text=ls_html))
    router.post(url__regex=sso_url_re + r"2.*").mock(
        return_value=httpx.Response(200, text=saml_html)
    )
    router.post(sp_saml_acs_url).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": sp_redirect_location,
                "Set-Cookie": (
                    f"{shibsession_cookie_name}=TEST_SHIBSESSION_VALUE; "
                    f"Path=/; Domain={sp_host}; Secure"
                ),
            },
        )
    )


_SP_ENTRY_SSO_REDIRECT = (
    "https://auth.iimc.kyoto-u.ac.jp/saml/saml2/idp/SSOService.php?SAMLRequest=TEST&RelayState=TEST"
)


def sp_entry_redirect_response() -> httpx.Response:
    """302 response that kicks off a SimpleSAMLphp SSO flow from an SP entry."""
    return httpx.Response(302, headers={"Location": _SP_ENTRY_SSO_REDIRECT})
