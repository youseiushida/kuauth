"""MyKULINE — kuline.kulib.kyoto-u.ac.jp. Django OPAC with Shibboleth consent + EPPN exchange."""

from __future__ import annotations

import httpx

from kuauth import _parsers
from kuauth.exceptions import SPAccessError
from kuauth.services._base import ShibbolethSPService


class MyKULINE(ShibbolethSPService):
    BASE_URL = "https://kuline.kulib.kyoto-u.ac.jp"
    ENTRY_PATH = "/opac/opac_secure/opac_search/"
    REQUIRES_CONSENT = True

    def get(self, path_or_url: str, **kwargs) -> httpx.Response:
        return self._follow_securelogin(super().get(path_or_url, **kwargs))

    def post(self, path_or_url: str, **kwargs) -> httpx.Response:
        return self._follow_securelogin(super().post(path_or_url, **kwargs))

    def request(self, method: str, path_or_url: str, **kwargs) -> httpx.Response:
        return self._follow_securelogin(
            super().request(method, path_or_url, **kwargs)
        )

    def _walk_consent_flow(self, r: httpx.Response) -> httpx.Response:
        form = _parsers.parse_shib_consent_form(r.text, base_url=str(r.url))
        return self.http.post(form["action"], data=form["fields"])

    def _post_saml_hook(self, r: httpx.Response) -> httpx.Response:
        return self._follow_securelogin(r)

    def _follow_securelogin(
        self, r: httpx.Response, *, max_hops: int = 3
    ) -> httpx.Response:
        # Django OPAC wraps every secure page with an auto-submit form
        # (id="securelogin") that JS POSTs back to `rurl`. httpx doesn't run
        # JS, so replay the POST ourselves until we land on real content.
        for _ in range(max_hops):
            if not _parsers.contains_eppn_form(r.text):
                return r
            form = _parsers.parse_mykuline_eppn_form(r.text, base_url=str(r.url))
            # If the server returned a securelogin shell with empty `rurl`,
            # replaying it self-loops forever (the JS sets action=rurl, and
            # the browser does the same). This happens when the requested
            # path is not a valid secure-entry URL — there's no populated SSO
            # payload to forward.
            if not form["fields"].get("rurl"):
                raise SPAccessError(
                    f"MyKULINE: securelogin shell at {r.url} has empty rurl; "
                    f"this path is not a valid SSO entry point"
                )
            r = self.http.post(
                form["action"],
                data=form["fields"],
                headers={"Referer": str(r.url)},
            )
            r.raise_for_status()
        # The last POST may have landed on real content; accept it if so.
        if not _parsers.contains_eppn_form(r.text):
            return r
        raise SPAccessError(
            f"MyKULINE: securelogin chain did not settle within {max_hops} hops"
        )
