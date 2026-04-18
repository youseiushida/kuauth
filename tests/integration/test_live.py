"""Live integration tests — require real credentials.

Gated by ``KUAUTH_LIVE=1`` (handled in conftest.py). Additionally requires:

- ``KUAUTH_USERNAME`` — SPS ID
- ``KUAUTH_PASSWORD``
- ``KUAUTH_TOTP_SECRET`` — base32 TOTP secret enrolled for the account
"""

from __future__ import annotations

import os

import pytest

from kuauth import KyotoUAuth, KULASIS, KULMS, MyKULINE, PandA


pytestmark = pytest.mark.integration


def _creds() -> tuple[str, str, str]:
    try:
        return (
            os.environ["KUAUTH_USERNAME"],
            os.environ["KUAUTH_PASSWORD"],
            os.environ["KUAUTH_TOTP_SECRET"],
        )
    except KeyError as e:
        pytest.skip(f"missing env var: {e.args[0]}")


@pytest.fixture(scope="module")
def auth() -> KyotoUAuth:
    user, pw, totp = _creds()
    a = KyotoUAuth(user, pw, totp_secret=totp).login()
    yield a
    a.close()


def test_login_obtains_session(auth: KyotoUAuth) -> None:
    assert auth.is_authenticated


def test_kulasis_top_is_readable(auth: KyotoUAuth) -> None:
    html = KULASIS(auth).get("/student/la/top").text
    assert len(html) > 100
    assert "\u4eac\u90fd\u5927\u5b66" in html  # 京都大学


def test_kulms_portal_is_readable(auth: KyotoUAuth) -> None:
    html = KULMS(auth).get("/portal").text
    assert "Sakai" in html or "portal" in html.lower()


def test_mykuline_secure_mypage(auth: KyotoUAuth) -> None:
    r = MyKULINE(auth).get("/opac/opac_secure/opac_mypage/")
    assert r.status_code == 200
    assert len(r.text) > 100


def test_panda_portal_is_readable(auth: KyotoUAuth) -> None:
    # PandA uses ECS CAS — ``auth`` only supplies username/password; OTP is
    # unused. It shares the httpx.Client so hitting KULMS first (different
    # host) doesn't interfere with PandA's own session.
    r = PandA(auth).get("/portal")
    assert r.status_code == 200
    assert "PandA" in r.text or "Sakai" in r.text
