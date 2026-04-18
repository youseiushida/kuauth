"""KULASIS — www.k.kyoto-u.ac.jp. Plain Shibboleth SP, Shift_JIS HTML."""

from __future__ import annotations

import httpx

from kuauth.services._base import ShibbolethSPService


class KULASIS(ShibbolethSPService):
    BASE_URL = "https://www.k.kyoto-u.ac.jp"
    ENTRY_PATH = "/student/la/top"

    def get(self, path_or_url: str, **kwargs) -> httpx.Response:
        r = super().get(path_or_url, **kwargs)
        r.encoding = "cp932"
        return r

    def post(self, path_or_url: str, **kwargs) -> httpx.Response:
        r = super().post(path_or_url, **kwargs)
        r.encoding = "cp932"
        return r

    def request(self, method: str, path_or_url: str, **kwargs) -> httpx.Response:
        r = super().request(method, path_or_url, **kwargs)
        r.encoding = "cp932"
        return r
