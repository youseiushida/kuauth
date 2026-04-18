"""Replay test for KULASIS service (Shift_JIS decoding)."""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.services.kulasis import KULASIS

from tests.replay._router import build_login_router, load_bytes, load_text


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def test_top_returns_sjis_decoded_html(fixtures_dir, http_client):
    saml_html = load_text(fixtures_dir, "saml_autosubmit_kulasis.html")
    body_sjis = load_bytes(fixtures_dir, "kulasis_top.html.sjis")

    with respx.mock(assert_all_called=False) as mock:
        build_login_router(mock, fixtures_dir)
        # 1st GET: entry → SAML autosubmit;
        # 2nd GET: landing after SAML POST redirect;
        # 3rd GET: explicit top() call returns SJIS body.
        sjis_response = httpx.Response(
            200,
            headers={"Content-Type": "text/html; charset=Shift_JIS"},
            content=body_sjis,
        )
        mock.get("https://www.k.kyoto-u.ac.jp/student/la/top").mock(
            side_effect=[
                httpx.Response(200, text=saml_html),
                sjis_response,
                httpx.Response(
                    200,
                    headers={"Content-Type": "text/html; charset=Shift_JIS"},
                    content=body_sjis,
                ),
            ]
        )
        mock.post(
            "https://www.k.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
        ).mock(
            return_value=httpx.Response(
                302,
                headers={
                    "Location": "https://www.k.kyoto-u.ac.jp/student/la/top",
                    "Set-Cookie": (
                        "_shibsession_KULASIS=TEST; "
                        "Path=/; Domain=www.k.kyoto-u.ac.jp; Secure"
                    ),
                },
            )
        )

        auth = KyotoUAuth(
            "u", "p", totp_secret="JBSWY3DPEHPK3PXP", http=http_client
        )
        kulasis = KULASIS(auth.login())
        html = kulasis.get("/student/la/top").text

    assert "\u6559\u52d9\u60c5\u5831\u30b7\u30b9\u30c6\u30e0" in html  # 教務情報システム
    assert "TEST_COURSE_A" in html
