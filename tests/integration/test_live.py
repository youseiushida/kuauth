"""Live integration tests — require real credentials.

Gated by ``KUAUTH_LIVE=1`` (handled in conftest.py). Additionally requires:

- ``KUAUTH_USERNAME`` — SPS ID
- ``KUAUTH_PASSWORD``
- ``KUAUTH_TOTP_SECRET`` — base32 TOTP secret enrolled for the account
"""

from __future__ import annotations

import os
import re
import time
from typing import Callable

import httpx
import pytest

from kuauth import KyotoUAuth, KULASIS, KULMS, MyKULINE, PandA
from kuauth import _parsers
from kuauth.exceptions import SPAccessError


_UPSTREAM_5XX = re.compile(r"HTTP 5\d\d")


def _fetch_with_upstream_retry(
    call: Callable[[], httpx.Response],
    *,
    attempts: int = 2,
    backoff: float = 5.0,
) -> httpx.Response:
    """Invoke ``call`` with one retry on transient upstream 5xx.

    When the Kyoto-U SPs bounce a request with 5xx (KULMS Sakai behind a
    proxy does this occasionally), the first attempt raises
    ``SPAccessError("... HTTP 5xx")``. We retry once after ``backoff``
    seconds; if it still fails with 5xx, ``pytest.skip`` — persistent
    upstream trouble is not a library regression and shouldn't page us.

    ``attempts`` counts total tries (first + retries).
    """
    last: SPAccessError | None = None
    for i in range(attempts):
        try:
            return call()
        except SPAccessError as e:
            if not _UPSTREAM_5XX.search(str(e)):
                raise
            last = e
            if i < attempts - 1:
                time.sleep(backoff)
    pytest.skip(f"upstream 5xx after {attempts} attempts: {last}")


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


def _assert_authenticated_response(
    r: httpx.Response,
    *,
    expected_host: str,
    expected_path_prefix: str,
) -> None:
    """Fail if the response looks like an unauthenticated/interstitial page.

    Checks three things that together catch silent auth failures:

    1. Final URL is on the SP host and the path didn't get rewritten to a
       login endpoint (``/pub/login.cgi``, ``/idp/profile``, ``/cas/login``,
       etc.).
    2. The body contains no IdP/CAS form markers — anything that would
       indicate we're still on an auth wall.
    3. Body is non-trivial.
    """
    assert r.status_code == 200, f"got HTTP {r.status_code}"
    assert r.url.host == expected_host, f"redirected off-host to {r.url}"
    assert r.url.path.startswith(expected_path_prefix), (
        f"redirected to unexpected path {r.url.path!r} "
        f"(expected prefix {expected_path_prefix!r})"
    )
    body = r.text
    # Any of these predicates matching means we're looking at an auth wall,
    # not the resource. The service's ``_ensure_session`` should have caught
    # this, but assert on the returned body too — defense in depth.
    gates = {
        "SSP login form (login.cgi)": _parsers.contains_login_form(body),
        "SSP OTP form (otplogin.cgi)": _parsers.contains_otp_form(body),
        "Shib IdP j_username form": _parsers.contains_shib_idp_login_form(body),
        "Shib consent page": _parsers.contains_consent_page(body),
        "Shib localStorage form": _parsers.contains_localstorage_form(body),
        "SSP authselect picker": _parsers.contains_authselect(body),
        "SAML auto-submit (stuck mid-flow)": _parsers.contains_saml_autosubmit(body),
        "ECS CAS login form": _parsers.contains_cas_login_form(body),
        "MyKULINE EPPN/securelogin form": _parsers.contains_eppn_form(body),
    }
    hit = [name for name, flagged in gates.items() if flagged]
    assert not hit, f"response still contains auth gate(s): {hit}"
    assert len(body) > 500, f"body suspiciously short ({len(body)} chars)"


def test_login_obtains_session(auth: KyotoUAuth) -> None:
    # ``is_authenticated`` flips only after a ``_shibsession_*`` cookie is
    # seen — this isn't forgeable from a public page, so it's a real signal.
    assert auth.is_authenticated
    assert any(
        c.name.startswith("_shibsession_")
        for c in auth.http.cookies.jar
    )


def test_kulasis_top_is_readable(auth: KyotoUAuth) -> None:
    # KULASIS rewrites ``/student/la/top`` into a faculty-specific path
    # such as ``/student/u/t/top?server=europa`` post-login, so we only
    # assert the generic ``/student/`` namespace. An unauthenticated hit
    # would bounce off-host to the IIMC IdP and be caught by the host
    # check in _assert_authenticated_response.
    #
    # KULASIS does not echo the SPS-ID verbatim in the landing HTML
    # (unlike Sakai), so identity-level proof relies on the auth-gate
    # predicates + host/path checks in the helper rather than a
    # username string match.
    r = _fetch_with_upstream_retry(lambda: KULASIS(auth).get("/student/la/top"))
    _assert_authenticated_response(
        r, expected_host="www.k.kyoto-u.ac.jp",
        expected_path_prefix="/student/",
    )


def test_kulms_portal_is_readable(auth: KyotoUAuth) -> None:
    r = _fetch_with_upstream_retry(lambda: KULMS(auth).get("/portal"))
    _assert_authenticated_response(
        r, expected_host="lms.gakusei.kyoto-u.ac.jp",
        expected_path_prefix="/portal",
    )
    # Sakai stamps the viewer's user eid into the portal DOM; the
    # pre-login gateway page never does.
    assert os.environ["KUAUTH_USERNAME"] in r.text, (
        "logged-in KULMS portal should echo the viewer's user id"
    )


def test_mykuline_secure_mypage(auth: KyotoUAuth) -> None:
    r = _fetch_with_upstream_retry(
        lambda: MyKULINE(auth).get("/opac/opac_secure/opac_mypage/")
    )
    _assert_authenticated_response(
        r, expected_host="kuline.kulib.kyoto-u.ac.jp",
        expected_path_prefix="/opac/opac_secure/",
    )


def test_panda_portal_is_readable(auth: KyotoUAuth) -> None:
    # PandA uses ECS CAS — ``auth`` only supplies username/password; OTP is
    # unused. It shares the httpx.Client so hitting KULMS first (different
    # host) doesn't interfere with PandA's own session.
    r = _fetch_with_upstream_retry(lambda: PandA(auth).get("/portal"))
    _assert_authenticated_response(
        r, expected_host="panda.ecs.kyoto-u.ac.jp",
        expected_path_prefix="/portal",
    )
    assert os.environ["KUAUTH_USERNAME"] in r.text, (
        "logged-in PandA portal should echo the viewer's user id"
    )
