"""SAML auto-submit form helpers."""

from __future__ import annotations

from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from kuauth._parsers import _coerce_str
from kuauth.exceptions import AuthenticationError


def parse_saml_autosubmit(html: str, *, base_url: str | None = None) -> tuple[str, dict[str, str]]:
    """Find the SAMLResponse auto-submit form.

    Returns (action_url, {"SAMLResponse": ..., "RelayState": ...}).
    """
    soup = BeautifulSoup(html, "lxml")
    form = None
    for f in soup.find_all("form"):
        if f.find("input", {"name": "SAMLResponse"}):
            form = f
            break
    if form is None:
        raise AuthenticationError("SAMLResponse auto-submit form not found")
    action = _coerce_str(form.get("action"))
    if base_url:
        action = urljoin(base_url, action)
    fields: dict[str, str] = {}
    for inp in form.find_all("input"):
        raw_name = inp.get("name")
        if not raw_name:
            continue
        fields[_coerce_str(raw_name)] = _coerce_str(inp.get("value"), "")
    if "SAMLResponse" not in fields:
        raise AuthenticationError("SAMLResponse field missing")
    return action, fields


def post_saml_autosubmit(
    client: httpx.Client, html: str, *, base_url: str | None = None
) -> httpx.Response:
    """Locate and submit a SAMLResponse auto-submit form."""
    action, fields = parse_saml_autosubmit(html, base_url=base_url)
    return client.post(action, data=fields)
