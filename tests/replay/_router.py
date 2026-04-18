"""Helpers for registering respx routes that replay the Kyoto-U SSO chain."""

from __future__ import annotations

from pathlib import Path

import httpx
import respx


def load_text(fixtures_dir: Path, name: str) -> str:
    return (fixtures_dir / name).read_text(encoding="utf-8")


def load_bytes(fixtures_dir: Path, name: str) -> bytes:
    return (fixtures_dir / name).read_bytes()


def build_login_router(
    router: respx.Router,
    fixtures_dir: Path,
    *,
    final_location: str = "https://student.iimc.kyoto-u.ac.jp/list.html",
    shibsession_host: str = "student.iimc.kyoto-u.ac.jp",
    saml_action_host: str = "student.iimc.kyoto-u.ac.jp",
) -> None:
    """Register the IdP password + OTP chain up to the SP's SAML consumer.

    The chain simulated (follow-redirects friendly):

    1. ``GET https://student.iimc.kyoto-u.ac.jp/login.html`` → 302 to IdP SSO
    2. ``GET .../SSOService.php`` → 302 to /pub/login.cgi
    3. ``GET /pub/login.cgi`` → 200 login form
    4. ``POST /pub/login.cgi`` → 302 to /pub/otplogin.cgi
    5. ``GET /pub/otplogin.cgi`` → 200 OTP form
    6. ``POST /pub/otplogin.cgi`` → 200 SAML auto-submit HTML
    7. ``POST .../Shibboleth.sso/SAML2/POST`` → 302 with _shibsession_ cookie
    8. ``GET final_location`` → 200 landing page
    """
    login_html = load_text(fixtures_dir, "idp_login_form.html")
    otp_html = load_text(fixtures_dir, "idp_otp_form.html")
    saml_html = load_text(fixtures_dir, "saml_autosubmit_student.html")

    router.get("https://student.iimc.kyoto-u.ac.jp/login.html").mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": "https://auth.iimc.kyoto-u.ac.jp/saml/saml2/idp/SSOService.php?SAMLRequest=TEST"
            },
        )
    )
    router.get(
        url__regex=r"^https://auth\.iimc\.kyoto-u\.ac\.jp/saml/saml2/idp/SSOService\.php.*"
    ).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": "https://auth.iimc.kyoto-u.ac.jp/pub/login.cgi?back=TEST"
            },
        )
    )
    router.get(
        url__regex=r"^https://auth\.iimc\.kyoto-u\.ac\.jp/pub/login\.cgi.*"
    ).mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text=login_html,
        )
    )
    router.post("https://auth.iimc.kyoto-u.ac.jp/pub/login.cgi").mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": "https://auth.iimc.kyoto-u.ac.jp/pub/otplogin.cgi?back=TEST"
            },
        )
    )
    router.get(
        url__regex=r"^https://auth\.iimc\.kyoto-u\.ac\.jp/pub/otplogin\.cgi.*"
    ).mock(
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
    router.post(
        f"https://{saml_action_host}/Shibboleth.sso/SAML2/POST"
    ).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": final_location,
                "Set-Cookie": (
                    f"_shibsession_TEST=TEST_SHIBSESSION_VALUE; "
                    f"Path=/; Domain={shibsession_host}; Secure"
                ),
            },
        )
    )
    router.get(final_location).mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text="<html><body>Portal landing</body></html>",
        )
    )
