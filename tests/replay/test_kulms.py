"""Replay tests for KULMS (Sakai LMS via SimpleSAMLphp IdP)."""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.services.kulms import KULMS

from tests.replay._router import (
    build_simplesaml_idp_router,
    load_text,
    sp_entry_redirect_response,
)


SP_ENTRY = "https://lms.gakusei.kyoto-u.ac.jp/sakai-login-tool/container"
SP_ACS = "https://lms.gakusei.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
PORTAL_URL = "https://lms.gakusei.kyoto-u.ac.jp/portal"


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def _wire_full_flow(mock: respx.Router, fixtures_dir) -> None:
    build_simplesaml_idp_router(
        mock,
        fixtures_dir,
        saml_autosubmit_fixture="saml_autosubmit_kulms.html",
        sp_saml_acs_url=SP_ACS,
        sp_redirect_location=PORTAL_URL,
        shibsession_host="lms.gakusei.kyoto-u.ac.jp",
        shibsession_cookie_name="_shibsession_KULMS",
    )
    mock.get(SP_ENTRY).mock(return_value=sp_entry_redirect_response())


def test_portal_returns_html(fixtures_dir, http_client):
    portal_html = load_text(fixtures_dir, "kulms_portal.html")
    with respx.mock(assert_all_called=False) as mock:
        _wire_full_flow(mock, fixtures_dir)
        mock.get(PORTAL_URL).mock(
            return_value=httpx.Response(200, text=portal_html)
        )

        auth = KyotoUAuth(
            "u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client
        )
        html = KULMS(auth).get("/portal").text

    assert "Sakai" in html
    assert "test-site-id" in html


def test_notifications_returns_json(fixtures_dir, http_client):
    portal_html = load_text(fixtures_dir, "kulms_portal.html")
    with respx.mock(assert_all_called=False) as mock:
        _wire_full_flow(mock, fixtures_dir)
        # _ensure_session's post-SAML 302 lands on /portal once; then the
        # user's actual call is to /api/users/me/notifications.
        mock.get(PORTAL_URL).mock(
            return_value=httpx.Response(200, text=portal_html)
        )
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
        data = KULMS(auth).get("/api/users/me/notifications").json()

    assert data["unread"] == 1
    assert data["notifications"][0]["id"] == "n1"
