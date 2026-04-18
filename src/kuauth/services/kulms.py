"""KULMS — lms.gakusei.kyoto-u.ac.jp. Sakai LMS via container authentication."""

from __future__ import annotations

from kuauth.services._base import ShibbolethSPService


class KULMS(ShibbolethSPService):
    BASE_URL = "https://lms.gakusei.kyoto-u.ac.jp"
    ENTRY_PATH = "/sakai-login-tool/container"
