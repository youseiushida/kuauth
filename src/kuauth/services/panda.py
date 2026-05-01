"""PandA — panda.ecs.kyoto-u.ac.jp. ECS's Sakai LMS (KULMS's predecessor).

Despite being Sakai like KULMS, PandA does **not** sit behind the Kyoto-U
Shibboleth IdP. It uses ECS's own Apereo CAS server at ``/cas/login``, so
the full KyotoUAuth/Shibboleth/OTP dance is bypassed — we only need
``username`` and ``password`` from the ``KyotoUAuth`` container.

Flow::

    GET  /sakai-login-tool/container
      -> 302  /cas/login?service=.../sakai-login-tool/container
      -> 200  CAS form (username/password + lt/execution/_eventId)
    POST form action (may carry ;jsessionid=...)
      -> 302  /sakai-login-tool/container?ticket=ST-...
      -> 302  /portal
      -> 200  portal HTML
"""

from __future__ import annotations

import httpx

from kuauth import _parsers
from kuauth.exceptions import AuthenticationError, SPAccessError
from kuauth.services._base import _SPService


class PandA(_SPService):
    BASE_URL = "https://panda.ecs.kyoto-u.ac.jp"
    ENTRY_PATH = "/sakai-login-tool/container"

    def _ensure_session(self) -> None:
        if self._sp_ready:
            return
        r = self.http.get(self.BASE_URL + self.ENTRY_PATH)
        if _parsers.contains_cas_login_form(r.text):
            r = self._submit_cas_login(r)
        if _parsers.contains_cas_login_form(r.text):
            raise AuthenticationError(f"{type(self).__name__}: CAS rejected credentials")
        if r.status_code >= 400:
            raise SPAccessError(f"{type(self).__name__}: entry returned HTTP {r.status_code}")
        # Defense in depth, symmetric with ShibbolethSPService's
        # _has_shibsession_for_host. Sakai stamps ``X-Sakai-Session`` on
        # every response served by an authenticated portal request; the
        # public pre-login gateway returns 200 without it. So presence of
        # this header is a positive signal that CAS ticket exchange
        # actually minted a session, not just that the redirect chain
        # settled on a 200.
        if not r.headers.get("x-sakai-session"):
            raise SPAccessError(
                f"{type(self).__name__}: post-CAS response missing X-Sakai-Session (URL: {r.url})"
            )
        self._sp_ready = True

    def _submit_cas_login(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_cas_login_form(r.text, base_url=str(r.url))
        data = dict(form["fields"])
        data["username"] = self._auth.username
        data["password"] = self._auth.password
        return self.http.post(form["action"], data=data)
