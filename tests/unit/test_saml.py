"""Unit tests for kuauth._saml."""

from __future__ import annotations

import pytest

from kuauth import _saml
from kuauth.exceptions import AuthenticationError

AUTOSUBMIT_HTML = """
<html><body onload="document.forms[0].submit()">
<form action="https://student.iimc.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST" method="post">
  <input type="hidden" name="RelayState" value="ss:mem:abc123">
  <input type="hidden" name="SAMLResponse" value="TEST_SAML_RESPONSE_B64">
  <input type="submit" value="submit">
</form>
</body></html>
"""


def test_parse_autosubmit():
    action, fields = _saml.parse_saml_autosubmit(AUTOSUBMIT_HTML)
    assert action == "https://student.iimc.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
    assert fields["SAMLResponse"] == "TEST_SAML_RESPONSE_B64"
    assert fields["RelayState"] == "ss:mem:abc123"


def test_parse_autosubmit_missing_form_raises():
    with pytest.raises(AuthenticationError):
        _saml.parse_saml_autosubmit("<html><body></body></html>")


def test_parse_autosubmit_with_relative_action():
    html = """
    <form action="/Shibboleth.sso/SAML2/POST" method="post">
      <input type="hidden" name="SAMLResponse" value="X">
      <input type="hidden" name="RelayState" value="Y">
    </form>
    """
    action, _fields = _saml.parse_saml_autosubmit(
        html, base_url="https://kuline.kulib.kyoto-u.ac.jp/"
    )
    assert action == "https://kuline.kulib.kyoto-u.ac.jp/Shibboleth.sso/SAML2/POST"
