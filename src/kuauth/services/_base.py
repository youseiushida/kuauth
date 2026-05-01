"""Base classes shared by service clients.

``_SPService`` is the generic plumbing: it holds a ``KyotoUAuth`` reference,
exposes its ``httpx.Client`` via ``http``, and defines ``get``/``post``/
``request`` that run ``_ensure_session`` exactly once before any call.

``ShibbolethSPService`` is the concrete base for SPs behind the Kyoto-U
Shibboleth IdPs. It walks whatever IdP interstitials the SP redirects to —
either the SimpleSAMLphp arm at ``auth.iimc.kyoto-u.ac.jp`` (login.cgi +
authselect + otplogin.cgi, used by KULASIS/KULMS, requires OTP) or the
Java Shib IdP at ``authidp1.iimc.kyoto-u.ac.jp`` (j_username/j_password +
consent + localStorage, used by MyKULINE, no OTP). OTP is resolved lazily
only when the otplogin.cgi form is actually encountered, so SPs that
route exclusively through authidp1 can be used without ``totp_secret``.

PandA is **not** a Shibboleth SP; it authenticates against ECS's own CAS
server and lives in its own module.
"""

from __future__ import annotations

from copy import copy
from http.cookiejar import CookieJar
from typing import ClassVar
from urllib.parse import urlparse

import httpx

from kuauth import _parsers, _saml
from kuauth.auth import KyotoUAuth
from kuauth.exceptions import (
    AuthenticationError,
    ConsentRequiredError,
    SPAccessError,
)


class _SPService:
    """Common HTTP plumbing for any SP backed by a shared ``KyotoUAuth``.

    Subclasses override ``BASE_URL`` and ``ENTRY_PATH`` and implement
    ``_ensure_session`` to perform whatever login the SP requires.

    Not thread-safe. ``_sp_ready`` and the underlying ``httpx.Client`` are
    shared mutable state; use one service instance per thread.
    """

    BASE_URL: ClassVar[str]
    ENTRY_PATH: ClassVar[str]

    def __init__(self, auth: KyotoUAuth) -> None:
        self._auth = auth
        self._sp_ready = False

    @property
    def http(self) -> httpx.Client:
        return self._auth.http

    def get(self, path_or_url: str, **kwargs) -> httpx.Response:
        """Ensure session, then GET ``path_or_url`` (absolute or BASE_URL-relative)."""
        self._ensure_session()
        return self.http.get(self._resolve(path_or_url), **kwargs)

    def post(self, path_or_url: str, **kwargs) -> httpx.Response:
        """Ensure session, then POST to ``path_or_url``."""
        self._ensure_session()
        return self.http.post(self._resolve(path_or_url), **kwargs)

    def request(self, method: str, path_or_url: str, **kwargs) -> httpx.Response:
        """Ensure session, then issue an arbitrary request."""
        self._ensure_session()
        return self.http.request(method, self._resolve(path_or_url), **kwargs)

    def cookies(self) -> httpx.Cookies:
        """Ensure session, then return a detached cookie jar for this service."""
        self._ensure_session()
        jar = CookieJar()
        host = urlparse(self.BASE_URL).hostname or ""
        for c in self.http.cookies.jar:
            if self._cookie_matches_host(c.domain or "", host):
                jar.set_cookie(copy(c))
        return httpx.Cookies(jar)

    def _resolve(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        # Auto-prepend "/" so a missing leading slash doesn't host-glue
        # into ``https://hoststudent/la/top``. Avoid urljoin: it would
        # resolve protocol-relative ``//other.com/x`` off-host.
        if not path_or_url.startswith("/"):
            path_or_url = "/" + path_or_url
        return self.BASE_URL + path_or_url

    def _ensure_session(self) -> None:
        raise NotImplementedError

    def _follow_meta_refresh(self, r: httpx.Response, *, max_hops: int = 10) -> httpx.Response:
        for _ in range(max_hops):
            target = _parsers.extract_meta_refresh_url(r.text, base_url=str(r.url))
            if not target:
                return r
            r = self.http.get(target)
        # The last GET may have landed on the settled page; accept it if so.
        if not _parsers.extract_meta_refresh_url(r.text, base_url=str(r.url)):
            return r
        raise SPAccessError(
            f"{type(self).__name__}: meta-refresh chain did not settle within {max_hops} hops"
        )

    @staticmethod
    def _cookie_matches_host(cookie_domain: str, host: str) -> bool:
        cookie_host = cookie_domain.lstrip(".")
        if not cookie_host or not host:
            return False
        return cookie_host == host or host.endswith("." + cookie_host)


class ShibbolethSPService(_SPService):
    """Base for an SP behind one of the Kyoto-U Shibboleth IdPs.

    The ``_advance_through_idp`` loop handles both the SimpleSAMLphp arm
    (``auth.iimc.kyoto-u.ac.jp`` — login.cgi / authselect / otplogin.cgi)
    and the Java Shib IdP arm (``authidp1.iimc.kyoto-u.ac.jp`` —
    j_username / consent / localStorage), followed in both cases by the
    SAML auto-submit back to the SP.

    If the IdP shows a consent page or a localStorage sync form before
    returning the SAML auto-submit, set ``REQUIRES_CONSENT = True`` and
    override ``_walk_consent_flow``.
    """

    REQUIRES_CONSENT: ClassVar[bool] = False

    def _ensure_session(self) -> None:
        if self._sp_ready:
            return
        r = self.http.get(self.BASE_URL + self.ENTRY_PATH)
        r = self._advance_through_idp(r)
        r = self._post_saml_hook(r)
        if r.status_code >= 400:
            raise SPAccessError(f"{type(self).__name__}: entry returned HTTP {r.status_code}")
        # Defense in depth: the IdP walk can settle on a 200 that doesn't
        # actually carry an SP session (e.g., SAML POST returned but the
        # ACS didn't mint a cookie). The check must be scoped to THIS SP's
        # host — a shared KyotoUAuth may already carry _shibsession_* for
        # a sibling SP, and a global check would falsely pass when this
        # SP's ACS failed to set its own cookie.
        sp_host = urlparse(self.BASE_URL).hostname or ""
        if not self._has_shibsession_for_host(sp_host):
            raise SPAccessError(
                f"{type(self).__name__}: IdP flow settled but no _shibsession_* cookie was set for {sp_host}"
            )
        self._sp_ready = True

    def _has_shibsession_for_host(self, host: str) -> bool:
        for c in self.http.cookies.jar:
            if not c.name.startswith("_shibsession_"):
                continue
            # Exact match is the common case (SP sets cookie on its own host).
            # Suffix match handles the RFC-6265 "Domain=parent" case where
            # the cookie would still be sent to ``host`` — defense in depth.
            if self._cookie_matches_host(c.domain or "", host):
                return True
        return False

    def _advance_through_idp(self, r: httpx.Response) -> httpx.Response:
        """Walk interstitial IdP pages (login, consent, localStorage, SAML)
        until we land on SP content.

        Branch order matches the wire order in the two arms we support:
        SimpleSAMLphp (login.cgi → authselect → otplogin.cgi → SAML) and
        authidp1 (j_username → consent → localStorage → SAML). The two
        arms never interleave in practice (each SP's redirect pins it to
        one arm), but the parsers pin on distinct form markers so the
        branches are disjoint regardless.

        Guards against three failure modes:
        - After either password submission, if the same form persists we
          raise immediately instead of retrying — Kyoto-U's lockout
          threshold is low enough that the hop budget could burn the
          account.
        - After OTP submission, same: if still on otplogin.cgi, the OTP
          was rejected.
        - After the loop exits, if ``r`` still contains any interstitial
          form marker, we raise rather than letting ``_ensure_session``
          mark the service ready on an unauthenticated page.
        """
        # Budget covers the longest real walk: SP entry → meta → login.cgi
        # → meta → authselect → meta → otplogin.cgi → meta → SAML → SP,
        # plus a little slack. The old 15 was tight for the full
        # SimpleSAMLphp arm.
        for _ in range(20):
            r = self._follow_meta_refresh(r)
            if _parsers.contains_login_form(r.text):
                r = self._submit_simplesaml_password(r)
                r = self._follow_meta_refresh(r)
                if _parsers.contains_login_form(r.text):
                    raise AuthenticationError(f"{type(self).__name__}: password rejected by IdP")
                continue
            if _parsers.contains_authselect(r.text):
                r = self._follow_authselect(r)
                continue
            if _parsers.contains_otp_form(r.text):
                r = self._submit_simplesaml_otp(r)
                r = self._follow_meta_refresh(r)
                if _parsers.contains_otp_form(r.text):
                    raise AuthenticationError(f"{type(self).__name__}: OTP rejected by IdP")
                continue
            if _parsers.contains_shib_idp_login_form(r.text):
                r = self._submit_shib_idp_login(r)
                r = self._follow_meta_refresh(r)
                if _parsers.contains_shib_idp_login_form(r.text):
                    raise AuthenticationError(
                        f"{type(self).__name__}: Shib IdP rejected credentials"
                    )
                continue
            if self.REQUIRES_CONSENT and _parsers.contains_consent_page(r.text):
                r = self._walk_consent_flow(r)
                continue
            if _parsers.contains_localstorage_form(r.text):
                r = self._walk_localstorage_form(r)
                continue
            if _parsers.contains_saml_autosubmit(r.text):
                r = _saml.post_saml_autosubmit(self.http, r.text, base_url=str(r.url))
                continue
            break
        if (
            _parsers.contains_login_form(r.text)
            or _parsers.contains_authselect(r.text)
            or _parsers.contains_otp_form(r.text)
            or _parsers.contains_shib_idp_login_form(r.text)
            or (self.REQUIRES_CONSENT and _parsers.contains_consent_page(r.text))
            or _parsers.contains_localstorage_form(r.text)
            or _parsers.contains_saml_autosubmit(r.text)
        ):
            raise SPAccessError(f"{type(self).__name__}: IdP flow did not complete within 20 hops")
        return r

    def _submit_simplesaml_password(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_login_form(r.text, base_url=str(r.url))
        data = dict(form["fields"])
        data["username"] = self._auth.username
        data["password"] = self._auth.password
        return self.http.post(form["action"], data=data)

    def _follow_authselect(self, r: httpx.Response) -> httpx.Response:
        link = _parsers.parse_authselect_link(r.text, base_url=str(r.url))
        return self.http.get(link)

    def _submit_simplesaml_otp(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_otp_form(r.text, base_url=str(r.url))
        data = dict(form["fields"])
        data["username"] = self._auth.username
        data["password"] = self._auth._resolve_otp()
        return self.http.post(form["action"], data=data)

    def _submit_shib_idp_login(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_shib_idp_login_form(r.text, base_url=str(r.url))
        fields = dict(form["fields"])
        fields["j_username"] = self._auth.username
        fields["j_password"] = self._auth.password
        return self.http.post(form["action"], data=fields)

    def _walk_localstorage_form(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_shib_localstorage_form(r.text, base_url=str(r.url))
        return self.http.post(form["action"], data=form["fields"])

    def _post_saml_hook(self, r: httpx.Response) -> httpx.Response:
        return r

    def _walk_consent_flow(self, r: httpx.Response) -> httpx.Response:
        raise ConsentRequiredError(
            f"{type(self).__name__} encountered a consent page but does not handle it"
        )
