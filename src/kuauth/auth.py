"""KyotoUAuth — credentials + shared httpx.Client holder for Kyoto-U SSO services."""

from __future__ import annotations

import ssl
from collections.abc import Callable
from typing import Self

import httpx
import pyotp

from kuauth.exceptions import OTPRequiredError

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"
)

_KULINE_HOST = "kuline.kulib.kyoto-u.ac.jp"


def _build_kuline_ssl_context() -> ssl.SSLContext:
    # MyKULINE (kuline.kulib.kyoto-u.ac.jp) rejects OpenSSL 3.0's default
    # SECLEVEL=2 offer list with TLSV1_ALERT_INSUFFICIENT_SECURITY.
    # SECLEVEL=1 still enforces cert validation, 2048-bit RSA, etc. — only
    # the SHA1-signed ciphers are re-allowed. The relaxation is mounted
    # on the kuline host alone; auth.iimc / authidp1 / KULASIS / KULMS /
    # PandA stay on OpenSSL defaults.
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
        # Credentials live in bytearrays so ``close()`` can overwrite them
        # with zeros. Python str is immutable — keeping passwords as str
        # leaves arbitrary copies in the GC graph until the next major
        # collection, which can show up in core dumps or swap. Bytearrays
        # are mutable and clearable in place, so the master copy held by
        # this instance has a bounded, explicit lifetime. Copies derived
        # at use-time (e.g. handed to httpx for form encoding) still leak
        # via str interning, but the master copy is the longest-lived one.
        self._password: bytearray | None = bytearray(password.encode("utf-8"))
        self._totp_secret: bytearray | None = (
            bytearray(totp_secret.encode("utf-8")) if totp_secret is not None else None
        )
        self._onetime_password: bytearray | None = (
            bytearray(onetime_password.encode("utf-8")) if onetime_password is not None else None
        )
        self._otp_callback = otp_callback
        self._owns_http = http is None
        if http is None:
            http = httpx.Client(
                follow_redirects=True,
                http2=True,
                timeout=timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                # Per-host TLS: kuline gets SECLEVEL=1 (it requires SHA1
                # ciphers to negotiate); every other host stays on
                # OpenSSL defaults. ``http2=True`` on httpx.Client only
                # affects the default transport, so the mounted one
                # opts in separately.
                mounts={
                    f"https://{_KULINE_HOST}": httpx.HTTPTransport(
                        verify=_build_kuline_ssl_context(),
                        http2=True,
                    ),
                },
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
        if self._password is None:
            raise RuntimeError("KyotoUAuth has been closed; credentials are no longer available")
        return bytes(self._password).decode("utf-8")

    def close(self) -> None:
        if self._owns_http and not self._http.is_closed:
            self._http.close()
        self._zero_credentials()

    def _zero_credentials(self) -> None:
        """Overwrite credential bytearrays with zeros and drop the references.

        Idempotent — safe to call repeatedly. Note that this only zeros the
        master copy held by this instance: any str/bytes copies that pyotp
        or httpx took during the auth flow live in their own GC graphs and
        will be collected on their own schedule.
        """
        for attr in ("_password", "_totp_secret", "_onetime_password"):
            buf = getattr(self, attr, None)
            if isinstance(buf, bytearray):
                for i in range(len(buf)):
                    buf[i] = 0
                buf.clear()
                setattr(self, attr, None)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def __repr__(self) -> str:
        # Don't leak credentials when the auth object is logged, printed,
        # or shows up in a traceback's locals dump. Reveal only what's
        # already public (the username) plus presence flags.
        return (
            f"KyotoUAuth(username={self._username!r}, "
            f"password={'<redacted>' if self._password is not None else '<closed>'}, "
            f"totp_secret={'<redacted>' if self._totp_secret is not None else None}, "
            f"onetime_password={'<redacted>' if self._onetime_password is not None else None}, "
            f"otp_callback={'<set>' if self._otp_callback is not None else None})"
        )

    def _resolve_otp(self) -> str:
        if self._onetime_password is not None:
            return bytes(self._onetime_password).decode("utf-8").strip()
        if self._totp_secret is not None:
            return pyotp.TOTP(bytes(self._totp_secret).decode("utf-8")).now()
        if self._otp_callback is not None:
            return str(self._otp_callback()).strip()
        raise OTPRequiredError(
            "OTP required but no onetime_password, totp_secret, or otp_callback configured"
        )
