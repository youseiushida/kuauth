"""KyotoUAuth — credentials + shared httpx.Client holder for Kyoto-U SSO services."""

from __future__ import annotations

import ssl
from typing import Callable, Self

import httpx
import pyotp

from kuauth.exceptions import OTPRequiredError

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
    """Holds credentials and a shared ``httpx.Client`` for the Kyoto-U SPs.

    No network is issued at construction or by any method on this class —
    authentication is lazy and driven by the SP clients (``KULASIS``,
    ``KULMS``, ``MyKULINE``, ``PandA``). Whether OTP is required depends on
    which SP is called: KULASIS/KULMS route through the SimpleSAMLphp IdP at
    ``auth.iimc.kyoto-u.ac.jp`` and demand OTP; MyKULINE goes through the
    Java Shib IdP at ``authidp1.iimc.kyoto-u.ac.jp`` (no OTP); PandA uses
    ECS CAS (no OTP). If you only use non-OTP SPs, omit ``totp_secret``.

    OTP sources, in priority order if multiple are set:
    ``onetime_password`` (pre-generated 6-digit code) >
    ``totp_secret`` (base32 seed, code generated on demand via pyotp) >
    ``otp_callback`` (zero-arg callable returning a code).

    Not thread-safe. The shared ``httpx.Client`` and the per-SP
    ``_sp_ready`` flags are mutable; the first call that walks the IdP can
    race if two threads hit the same SP concurrently (double-POST
    credentials — Kyoto-U's account lockout threshold is low). Use one
    ``KyotoUAuth`` per thread, or serialize SP access externally.

    Usage::

        auth = KyotoUAuth(user, password, totp_secret=secret)
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

    @property
    def http(self) -> httpx.Client:
        return self._http

    @property
    def username(self) -> str:
        return self._username

    @property
    def password(self) -> str:
        return self._password

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

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

