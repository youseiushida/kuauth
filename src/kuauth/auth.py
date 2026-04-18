"""KyotoUAuth — password + OTP login against auth.iimc.kyoto-u.ac.jp."""

from __future__ import annotations

import logging
import ssl
from typing import Callable, Self

import httpx
import pyotp

from kuauth import _parsers, _saml
from kuauth.exceptions import AuthenticationError, OTPRequiredError

log = logging.getLogger("kuauth.auth")

PORTAL_ENTRY = "https://student.iimc.kyoto-u.ac.jp/login.html"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36 kuauth/0.1.0"
)


def _build_ssl_context() -> ssl.SSLContext:
    # MyKULINE (kuline.kulib.kyoto-u.ac.jp) rejects OpenSSL 3.0's default
    # SECLEVEL=2 offer list with TLSV1_ALERT_INSUFFICIENT_SECURITY.
    # SECLEVEL=1 still enforces cert validation, 2048-bit RSA, etc. — only
    # the SHA1-signed ciphers are re-allowed.
    ctx = ssl.create_default_context()
    ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    return ctx


class KyotoUAuth:
    """Holds a shared httpx.Client authenticated against the Kyoto-U IdP.

    OTP is resolved from one of three sources, in priority order:
    ``onetime_password`` (a pre-generated 6-digit code) >
    ``totp_secret`` (base32 seed, code generated on demand via pyotp) >
    ``otp_callback`` (zero-arg callable returning a code).

    Usage::

        auth = KyotoUAuth(user, password, totp_secret=secret).login()
        KULMS(auth).get("/portal").text
    """

    def __init__(
        self,
        username: str,
        password: str,
        *,
        totp_secret: str | None = None,
        onetime_password: str | None = None,
        otp_callback: Callable[[], str] | None = None,
        http: httpx.Client | None = None,
        timeout: float = 20.0,
    ) -> None:
        self._username = username
        self._password = password
        self._totp_secret = totp_secret
        self._onetime_password = onetime_password
        self._otp_callback = otp_callback
        self._owns_http = http is None
        if http is None:
            http = httpx.Client(
                follow_redirects=True,
                http2=True,
                timeout=timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                verify=_build_ssl_context(),
            )
        self._http = http
        self._logged_in = False

    @property
    def http(self) -> httpx.Client:
        return self._http

    @property
    def is_authenticated(self) -> bool:
        return self._logged_in

    @property
    def username(self) -> str:
        return self._username

    @property
    def password(self) -> str:
        return self._password

    def login(self) -> Self:
        if self._logged_in:
            return self
        r = self._http.get(PORTAL_ENTRY)
        r.raise_for_status()
        r = self._follow_meta_refresh(r)
        r = self._submit_password(r)
        r = self._follow_meta_refresh(r)
        if _parsers.contains_authselect(r.text):
            r = self._follow_authselect(r)
            r = self._follow_meta_refresh(r)
        # After password + optional authselect we must be at the OTP form. If
        # the login form is still showing, the password was rejected — raise
        # before _submit_otp would post the OTP into a login.cgi form.
        if not _parsers.contains_otp_form(r.text):
            if _parsers.contains_login_form(r.text):
                raise AuthenticationError("password rejected by IdP")
            raise AuthenticationError(
                "unexpected state after password (no OTP form)"
            )
        r = self._submit_otp(r)
        r = self._follow_meta_refresh(r)
        # After OTP we expect the SAML autosubmit. Still on OTP form ⇒ OTP
        # rejected.
        if not _parsers.contains_saml_autosubmit(r.text):
            if _parsers.contains_otp_form(r.text):
                raise AuthenticationError("OTP rejected by IdP")
            raise AuthenticationError(
                "unexpected state after OTP (no SAML autosubmit)"
            )
        r = _saml.post_saml_autosubmit(self._http, r.text, base_url=str(r.url))
        r = self._follow_meta_refresh(r)
        r.raise_for_status()
        if not self._has_shibsession():
            raise AuthenticationError(
                "login completed but no _shibsession_* cookie was set"
            )
        self._logged_in = True
        return self

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _submit_password(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_login_form(r.text, base_url=str(r.url))
        data = dict(form["fields"])
        data["username"] = self._username
        data["password"] = self._password
        return self._http.post(form["action"], data=data)

    def _follow_authselect(self, r: httpx.Response) -> httpx.Response:
        link = _parsers.parse_authselect_link(r.text, base_url=str(r.url))
        return self._http.get(link)

    def _submit_otp(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_otp_form(r.text, base_url=str(r.url))
        data = dict(form["fields"])
        data["username"] = self._username
        data["password"] = self._resolve_otp()
        return self._http.post(form["action"], data=data)

    def _resolve_otp(self) -> str:
        if self._onetime_password:
            return self._onetime_password.strip()
        if self._totp_secret:
            return pyotp.TOTP(self._totp_secret).now()
        if self._otp_callback:
            return str(self._otp_callback()).strip()
        raise OTPRequiredError(
            "OTP required but no onetime_password, totp_secret, or otp_callback configured"
        )

    def _has_shibsession(self) -> bool:
        for cookie in self._http.cookies.jar:
            if cookie.name.startswith("_shibsession_"):
                return True
        return False

    def _follow_meta_refresh(
        self, r: httpx.Response, *, max_hops: int = 10
    ) -> httpx.Response:
        for _ in range(max_hops):
            target = _parsers.extract_meta_refresh_url(
                r.text, base_url=str(r.url)
            )
            if not target:
                return r
            r = self._http.get(target)
        return r
