"""Replay test for PandA (ECS Sakai LMS behind its own CAS).

Unlike KULMS/KULASIS/MyKULINE, PandA does not traverse the Kyoto-U
Shibboleth IdP — so no ``build_login_router`` / OTP machinery is needed.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from kuauth.auth import KyotoUAuth
from kuauth.exceptions import AuthenticationError, SPAccessError
from kuauth.services.panda import PandA
from tests.replay._router import load_text

CAS_ACTION_URL = (
    "https://panda.ecs.kyoto-u.ac.jp/cas/login;jsessionid=TEST_JSESSIONID"
    "?service=https%3A%2F%2Fpanda.ecs.kyoto-u.ac.jp%2Fsakai-login-tool%2Fcontainer"
)
CAS_LOGIN_URL = (
    "https://panda.ecs.kyoto-u.ac.jp/cas/login"
    "?service=https%3A%2F%2Fpanda.ecs.kyoto-u.ac.jp%2Fsakai-login-tool%2Fcontainer"
)


@pytest.fixture
def http_client():
    client = httpx.Client(follow_redirects=True, timeout=5.0)
    yield client
    client.close()


def _wire_successful_login(mock: respx.Router, fixtures_dir) -> None:
    cas_html = load_text(fixtures_dir, "panda_cas_login.html")
    portal_html = load_text(fixtures_dir, "panda_portal.html")

    # respx falls back to path-only matching when a registered URL has no
    # query string, so /sakai-login-tool/container would also swallow the
    # later /sakai-login-tool/container?ticket=... request. We disambiguate
    # with url__regex.
    mock.get(url__regex=r"^https://panda\.ecs\.kyoto-u\.ac\.jp/sakai-login-tool/container$").mock(
        return_value=httpx.Response(302, headers={"Location": CAS_LOGIN_URL})
    )
    mock.get(CAS_LOGIN_URL).mock(
        return_value=httpx.Response(
            200,
            headers={"Content-Type": "text/html;charset=UTF-8"},
            text=cas_html,
        )
    )
    # Successful POST → 302 to sakai with ticket → 302 to /portal.
    mock.post(CAS_ACTION_URL).mock(
        return_value=httpx.Response(
            302,
            headers={
                "Location": (
                    "https://panda.ecs.kyoto-u.ac.jp/sakai-login-tool/container"
                    "?ticket=ST-1234-TEST_TICKET"
                )
            },
        )
    )
    mock.get(
        "https://panda.ecs.kyoto-u.ac.jp/sakai-login-tool/container?ticket=ST-1234-TEST_TICKET"
    ).mock(
        return_value=httpx.Response(
            302,
            headers={"Location": "https://panda.ecs.kyoto-u.ac.jp/portal"},
        )
    )
    mock.get("https://panda.ecs.kyoto-u.ac.jp/portal").mock(
        return_value=httpx.Response(
            200,
            headers={
                "Content-Type": "text/html;charset=UTF-8",
                # Sakai stamps this on every authenticated portal response;
                # _ensure_session checks for it as a positive proof of CAS
                # ticket exchange success.
                "X-Sakai-Session": "test-sakai-session-uuid",
            },
            text=portal_html,
        )
    )


def test_portal_returns_html(fixtures_dir, http_client):
    with respx.mock(assert_all_called=False) as mock:
        _wire_successful_login(mock, fixtures_dir)

        auth = KyotoUAuth("u", "p", http=http_client)
        html = PandA(auth).get("/portal").text

    assert "PandA 22" in html
    assert "test-site-id" in html


def test_submits_credentials_to_cas_action(fixtures_dir, http_client):
    with respx.mock(assert_all_called=False) as mock:
        _wire_successful_login(mock, fixtures_dir)

        auth = KyotoUAuth("u-123", "secret", http=http_client)
        PandA(auth).get("/portal")

        # Verify the POST actually went to the jsessionid-bearing action URL
        # with the lt/execution fields from the form. mock.calls is cleared
        # when the context manager exits, so we inspect it inside the block.
        post_calls = [r for r in mock.calls if r.request.method == "POST"]
        assert len(post_calls) == 1
        body = post_calls[0].request.content.decode()
        assert "username=u-123" in body
        assert "password=secret" in body
        assert "lt=LT-1500-TEST_LOGIN_TICKET" in body
        assert "execution=e1s1" in body
        assert "_eventId=submit" in body


def test_raises_on_cas_rejection(fixtures_dir, http_client):
    """If CAS re-serves the login form, we raise AuthenticationError
    instead of silently claiming the session is ready."""
    cas_html = load_text(fixtures_dir, "panda_cas_login.html")

    with respx.mock(assert_all_called=False) as mock:
        mock.get("https://panda.ecs.kyoto-u.ac.jp/sakai-login-tool/container").mock(
            return_value=httpx.Response(302, headers={"Location": CAS_LOGIN_URL})
        )
        mock.get(CAS_LOGIN_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"Content-Type": "text/html;charset=UTF-8"},
                text=cas_html,
            )
        )
        # Wrong password → CAS replays the login page.
        mock.post(CAS_ACTION_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"Content-Type": "text/html;charset=UTF-8"},
                text=cas_html,
            )
        )

        auth = KyotoUAuth("u", "wrong", http=http_client)
        with pytest.raises(AuthenticationError, match="CAS rejected"):
            PandA(auth).get("/portal")


def test_raises_when_post_cas_response_lacks_sakai_session(fixtures_dir, http_client):
    """If the CAS handoff settles on a 200 that doesn't carry the
    ``X-Sakai-Session`` header, ``_ensure_session`` must raise instead of
    latching ``_sp_ready=True`` on what may be an unauthenticated gateway
    page (e.g. CAS maintenance, ticket validation race).

    Symmetric with the shibsession guard in ShibbolethSPService — the prior
    check ('CAS form re-displayed?') only catches password rejection, not
    'CAS form gone but session was never minted.'
    """
    cas_html = load_text(fixtures_dir, "panda_cas_login.html")
    portal_html = load_text(fixtures_dir, "panda_portal.html")

    with respx.mock(assert_all_called=False) as mock:
        mock.get(
            url__regex=r"^https://panda\.ecs\.kyoto-u\.ac\.jp/sakai-login-tool/container$"
        ).mock(return_value=httpx.Response(302, headers={"Location": CAS_LOGIN_URL}))
        mock.get(CAS_LOGIN_URL).mock(
            return_value=httpx.Response(
                200,
                headers={"Content-Type": "text/html;charset=UTF-8"},
                text=cas_html,
            )
        )
        mock.post(CAS_ACTION_URL).mock(
            return_value=httpx.Response(
                302,
                headers={
                    "Location": (
                        "https://panda.ecs.kyoto-u.ac.jp/sakai-login-tool/container"
                        "?ticket=ST-1234-TEST_TICKET"
                    )
                },
            )
        )
        mock.get(
            "https://panda.ecs.kyoto-u.ac.jp/sakai-login-tool/container?ticket=ST-1234-TEST_TICKET"
        ).mock(
            return_value=httpx.Response(
                302,
                headers={"Location": "https://panda.ecs.kyoto-u.ac.jp/portal"},
            )
        )
        # /portal returns 200 but WITHOUT X-Sakai-Session — looks like the
        # public gateway page rather than an authenticated session.
        mock.get("https://panda.ecs.kyoto-u.ac.jp/portal").mock(
            return_value=httpx.Response(
                200,
                headers={"Content-Type": "text/html;charset=UTF-8"},
                text=portal_html,
            )
        )

        auth = KyotoUAuth("u", "p", http=http_client)
        with pytest.raises(SPAccessError, match="X-Sakai-Session"):
            PandA(auth).get("/portal")
