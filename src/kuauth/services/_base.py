"""Base classes shared by service clients.

``_SPService`` is the generic plumbing: it holds a ``KyotoUAuth`` reference,
exposes its ``httpx.Client`` via ``http``, and defines ``get``/``post``/
``request`` that run ``_ensure_session`` exactly once before any call.

``ShibbolethSPService`` is the concrete base for SPs behind the Kyoto-U
Shibboleth IdP (KULASIS, KULMS, MyKULINE). PandA is **not** a Shibboleth SP;
it authenticates against ECS's own CAS server and lives in its own module.
"""

from __future__ import annotations

from typing import ClassVar

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

    def _resolve(self, path_or_url: str) -> str:
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return self.BASE_URL + path_or_url

    def _ensure_session(self) -> None:
        raise NotImplementedError

    def _follow_meta_refresh(
        self, r: httpx.Response, *, max_hops: int = 10
    ) -> httpx.Response:
        for _ in range(max_hops):
            target = _parsers.extract_meta_refresh_url(
                r.text, base_url=str(r.url)
            )
            if not target:
                return r
            r = self.http.get(target)
        # The last GET may have landed on the settled page; accept it if so.
        if not _parsers.extract_meta_refresh_url(r.text, base_url=str(r.url)):
            return r
        raise SPAccessError(
            f"{type(self).__name__}: meta-refresh chain did not settle within {max_hops} hops"
        )


class ShibbolethSPService(_SPService):
    """Base for an SP behind the Kyoto-U Shibboleth IdP.

    If the IdP shows a consent page or a localStorage sync form before
    returning the SAML auto-submit, set ``REQUIRES_CONSENT = True`` and
    override ``_walk_consent_flow``.
    """

    REQUIRES_CONSENT: ClassVar[bool] = False

    def _ensure_session(self) -> None:
        if self._sp_ready:
            return
        self._auth.login()
        r = self.http.get(self.BASE_URL + self.ENTRY_PATH)
        r = self._advance_through_idp(r)
        r = self._post_saml_hook(r)
        if r.status_code >= 400:
            raise SPAccessError(
                f"{type(self).__name__}: entry returned HTTP {r.status_code}"
            )
        self._sp_ready = True

    def _advance_through_idp(self, r: httpx.Response) -> httpx.Response:
        """Walk interstitial IdP pages (login, consent, localStorage, SAML)
        until we land on SP content.

        Guards against two failure modes:
        - After ``_submit_shib_idp_login``, if the same login form persists we
          raise immediately instead of retrying — Kyoto-U's lockout threshold
          is low enough that the 15-iteration budget could burn the account.
        - After the loop exits, if ``r`` still contains any interstitial form
          marker, we raise rather than letting ``_ensure_session`` mark the
          service ready on an unauthenticated page.
        """
        for _ in range(15):
            r = self._follow_meta_refresh(r)
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
                r = _saml.post_saml_autosubmit(
                    self.http, r.text, base_url=str(r.url)
                )
                continue
            break
        if (
            _parsers.contains_shib_idp_login_form(r.text)
            or (self.REQUIRES_CONSENT and _parsers.contains_consent_page(r.text))
            or _parsers.contains_localstorage_form(r.text)
            or _parsers.contains_saml_autosubmit(r.text)
        ):
            raise SPAccessError(
                f"{type(self).__name__}: IdP flow did not complete within 15 hops"
            )
        return r

    def _submit_shib_idp_login(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_shib_idp_login_form(r.text, base_url=str(r.url))
        fields = dict(form["fields"])
        fields["j_username"] = self._auth.username
        fields["j_password"] = self._auth.password
        return self.http.post(form["action"], data=fields)

    def _walk_localstorage_form(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_shib_localstorage_form(
            r.text, base_url=str(r.url)
        )
        return self.http.post(form["action"], data=form["fields"])

    def _post_saml_hook(self, r: httpx.Response) -> httpx.Response:
        return r

    def _walk_consent_flow(self, r: httpx.Response) -> httpx.Response:
        raise ConsentRequiredError(
            f"{type(self).__name__} encountered a consent page but does not handle it"
        )
