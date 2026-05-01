"""Helpers for registering respx routes that replay the Kyoto-U SSO chain.

Two builders map to the two Shibboleth IdP arms in use:

- ``build_simplesaml_idp_router`` — ``auth.iimc.kyoto-u.ac.jp`` SimpleSAMLphp
  (login.cgi + authselect + otplogin.cgi). Used by KULASIS/KULMS tests.
- MyKULINE goes through ``authidp1.iimc.kyoto-u.ac.jp`` (j_username +
  consent + localStorage). Its test cassette inlines the whole chain
  directly in the test because the interstitials are served at the SP
  host in the simulation (the existing fixtures were recorded that way).

Both end with a SAML autosubmit POST to the SP's ACS, which 302s with a
``_shibsession_*`` cookie to the SP content URL. Callers mock the SP
entry (to 302 into the IdP) and the final content GET.
"""

from __future__ import annotations

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
    3. ``POST /pub/login.cgi`` → 302 to /pub/otplogin.cgi
    4. ``GET /pub/otplogin.cgi`` → 200 OTP form
    5. ``POST /pub/otplogin.cgi`` → 200 SAML auto-submit HTML
    6. ``POST sp_saml_acs_url`` → 302 to ``sp_redirect_location`` with cookie

    Caller is responsible for:

    - Mocking the SP entry URL to 302 → .../SSOService.php (with SAMLRequest)
    - Mocking ``sp_redirect_location`` for the post-SAML content GET
    """
    login_html = load_text(fixtures_dir, "idp_login_form.html")
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
    router.post("https://auth.iimc.kyoto-u.ac.jp/pub/login.cgi").mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://auth.iimc.kyoto-u.ac.jp/pub/otplogin.cgi?back=TEST"},
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


_SP_ENTRY_SSO_REDIRECT = (
    "https://auth.iimc.kyoto-u.ac.jp/saml/saml2/idp/SSOService.php?SAMLRequest=TEST&RelayState=TEST"
)


def sp_entry_redirect_response() -> httpx.Response:
    """302 response that kicks off a SimpleSAMLphp SSO flow from an SP entry."""
    return httpx.Response(302, headers={"Location": _SP_ENTRY_SSO_REDIRECT})
