"""End-to-end replay of KyotoUAuth.login() via respx."""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.exceptions import AuthenticationError

from tests.replay._router import build_login_router


@pytest.fixture
def http_client() -> httpx.Client:
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def test_login_full_flow(fixtures_dir, http_client):
    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)
        auth = KyotoUAuth(
            "testuser",
            "testpass",
            totp_secret="JBSWY3DPEHPK3PXP",
            http=http_client,
        )
        auth.login()
    assert auth.is_authenticated
    assert any(
        c.name.startswith("_shibsession_") for c in http_client.cookies.jar
    )


def test_login_is_idempotent(fixtures_dir, http_client):
    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)
        auth = KyotoUAuth(
            "testuser", "testpass",
            totp_secret="JBSWY3DPEHPK3PXP",
            http=http_client,
        )
        auth.login()
        # Second call must not perform any further requests; respx would
        # raise if an unmatched call escaped.
        mock.reset()
        auth.login()
    assert auth.is_authenticated


def test_login_raises_without_otp_source(fixtures_dir, http_client):
    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)
        auth = KyotoUAuth("testuser", "testpass", http=http_client)
        with pytest.raises(AuthenticationError):
            auth.login()


def test_login_missing_shibsession_raises(fixtures_dir, http_client):
    """If SAML POST does not set a _shibsession_ cookie, login must fail."""
    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)
        # Override the SP endpoint to return 200 without a cookie.
        mock.post(
            "https://student.iimc.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
        ).mock(return_value=httpx.Response(200, text="<html></html>"))

        auth = KyotoUAuth(
            "testuser", "testpass",
            totp_secret="JBSWY3DPEHPK3PXP",
            http=http_client,
        )
        with pytest.raises(AuthenticationError):
            auth.login()
