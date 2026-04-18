"""Replay test for KULMS (Sakai LMS) service."""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.services.kulms import KULMS

from tests.replay._router import build_login_router, load_text


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def _set_up_sakai_entry(mock: respx.Router, fixtures_dir) -> None:
    """Wire up the SP SAML exchange for KULMS."""
    saml_html = load_text(fixtures_dir, "saml_autosubmit_kulms.html")
    portal_html = load_text(fixtures_dir, "kulms_portal.html")
    mock.get(
        "https://lms.gakusei.kyoto-u.ac.jp/sakai-login-tool/container"
    ).mock(return_value=httpx.Response(200, text=saml_html))
    mock.post(
        "https://lms.gakusei.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
    ).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": "https://lms.gakusei.kyoto-u.ac.jp/portal",
                "Set-Cookie": (
                    "_shibsession_KULMS=TEST; "
                    "Path=/; Domain=lms.gakusei.kyoto-u.ac.jp; Secure"
                ),
            },
        )
    )
    mock.get("https://lms.gakusei.kyoto-u.ac.jp/portal").mock(
        return_value=httpx.Response(200, text=portal_html)
    )


def test_portal_returns_html(fixtures_dir, http_client):
    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)
        _set_up_sakai_entry(mock, fixtures_dir)

        auth = KyotoUAuth(
            "u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client
        )
        html = KULMS(auth.login()).get("/portal").text

    assert "Sakai" in html
    assert "test-site-id" in html


def test_notifications_returns_json(fixtures_dir, http_client):
    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)
        _set_up_sakai_entry(mock, fixtures_dir)
        mock.get(
            "https://lms.gakusei.kyoto-u.ac.jp/api/users/me/notifications"
        ).mock(
            return_value=httpx.Response(
                200,
                json={"notifications": [{"id": "n1", "read": False}], "unread": 1},
            )
        )

        auth = KyotoUAuth(
            "u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client
        )
        data = KULMS(auth.login()).get("/api/users/me/notifications").json()

    assert data["unread"] == 1
    assert data["notifications"][0]["id"] == "n1"
