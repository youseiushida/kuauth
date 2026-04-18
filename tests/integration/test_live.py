"""Live integration tests — require real credentials.

Gated by ``KUAUTH_LIVE=1`` (handled in conftest.py). Required env:

- ``KUAUTH_USERNAME`` — SPS ID
- ``KUAUTH_PASSWORD``

Optional:

- ``KUAUTH_TOTP_SECRET`` — base32 TOTP secret. Only required for SPs that
  route through the OTP IdP (KULASIS, KULMS). Tests using ``auth_with_totp``
  skip when unset; tests using ``auth_no_totp`` run regardless.
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


def _creds() -> tuple[str, str, str | None]:
    """Return (username, password, totp_secret-or-None).

    ``KUAUTH_TOTP_SECRET`` is optional post-refactor — MyKULINE and PandA
    don't need it. Tests that do need it depend on ``auth_with_totp``,
    which skips when it's absent.
    """
    try:
        return (
            os.environ["KUAUTH_USERNAME"],
            os.environ["KUAUTH_PASSWORD"],
            os.environ.get("KUAUTH_TOTP_SECRET"),
        )
    except KeyError as e:
        pytest.skip(f"missing env var: {e.args[0]}")


@pytest.fixture(scope="module")
def auth_with_totp() -> KyotoUAuth:
    """For SPs that route through the OTP-required SimpleSAMLphp IdP
    (KULASIS, KULMS). Skips if ``KUAUTH_TOTP_SECRET`` is not set."""
    user, pw, totp = _creds()
    if totp is None:
        pytest.skip("KUAUTH_TOTP_SECRET not set")
    a = KyotoUAuth(user, pw, totp_secret=totp)
    yield a
    a.close()


@pytest.fixture(scope="module")
def auth_no_totp() -> KyotoUAuth:
    """For SPs that don't route through the OTP IdP (MyKULINE, PandA).

    Using this fixture proves those SPs don't require ``totp_secret`` —
    that's the motivation for the lazy-login refactor. ``KyotoUAuth`` is
    constructed without an OTP source; ``_resolve_otp`` is never called.
    """
    user, pw, _ = _creds()
    a = KyotoUAuth(user, pw)
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


def test_kulasis_top_is_readable(auth_with_totp: KyotoUAuth) -> None:
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
    r = _fetch_with_upstream_retry(
        lambda: KULASIS(auth_with_totp).get("/student/la/top")
    )
    _assert_authenticated_response(
        r, expected_host="www.k.kyoto-u.ac.jp",
        expected_path_prefix="/student/",
    )


def test_kulms_portal_is_readable(auth_with_totp: KyotoUAuth) -> None:
    r = _fetch_with_upstream_retry(lambda: KULMS(auth_with_totp).get("/portal"))
    _assert_authenticated_response(
        r, expected_host="lms.gakusei.kyoto-u.ac.jp",
        expected_path_prefix="/portal",
    )
    # Sakai stamps the viewer's user eid into the portal DOM; the
    # pre-login gateway page never does.
    assert os.environ["KUAUTH_USERNAME"] in r.text, (
        "logged-in KULMS portal should echo the viewer's user id"
    )


def test_mykuline_us_info_is_readable(auth_no_totp: KyotoUAuth) -> None:
    # ``/opac/us_info/`` is the logged-in "利用者情報" page. Unlike the initial
    # ``/opac/opac_secure/opac_search/`` entry, it does not re-trigger the
    # securelogin auto-submit — a direct GET after ``_ensure_session`` has
    # established the Django session returns the real page.
    #
    # Uses ``auth_no_totp`` deliberately: MyKULINE routes through authidp1,
    # which only needs j_username/j_password. If this test passes without
    # ``KUAUTH_TOTP_SECRET`` in the env, the lazy-login refactor is working.
    r = _fetch_with_upstream_retry(
        lambda: MyKULINE(auth_no_totp).get("/opac/us_info/?lang=0")
    )
    _assert_authenticated_response(
        r, expected_host="kuline.kulib.kyoto-u.ac.jp",
        expected_path_prefix="/opac/us_info/",
    )
    # us_info does not echo the EPPN, but a logged-in view always carries a
    # logout link. The pre-login securelogin shell has no logout link.
    assert "logout" in r.text.lower() or "\u30ed\u30b0\u30a2\u30a6\u30c8" in r.text, (
        "logged-in us_info should carry a logout link"
    )


def test_panda_portal_is_readable(auth_no_totp: KyotoUAuth) -> None:
    # PandA uses ECS CAS — only username/password. Uses ``auth_no_totp``
    # to pin that OTP is not required for this SP.
    r = _fetch_with_upstream_retry(lambda: PandA(auth_no_totp).get("/portal"))
    _assert_authenticated_response(
        r, expected_host="panda.ecs.kyoto-u.ac.jp",
        expected_path_prefix="/portal",
    )
    assert os.environ["KUAUTH_USERNAME"] in r.text, (
        "logged-in PandA portal should echo the viewer's user id"
    )
