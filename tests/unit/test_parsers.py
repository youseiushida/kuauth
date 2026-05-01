"""Unit tests for kuauth._parsers."""

from __future__ import annotations

import pytest

from kuauth import _parsers
from kuauth.exceptions import AuthenticationError

LOGIN_FORM_HTML = """
<html><body>
<form id="login" name="login" method="post" action="login.cgi" autocomplete="off">
  <input type="text" name="dummy" style="display:none;">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="op" value="login">
  <input type="hidden" name="back" value="https://example.test/back">
  <input type="hidden" name="sessid" value="TEST_SESSID_ABC123">
</form>
</body></html>
"""


OTP_FORM_HTML = """
<html><body>
<form id="login" name="login" method="post" action="otplogin.cgi" autocomplete="off">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="op" value="login">
  <input type="hidden" name="back" value="https://example.test/back">
  <input type="hidden" name="sessid" value="TEST_SESSID_OTP_XYZ">
</form>
</body></html>
"""


AUTHSELECT_HTML = """
<html><body>
<ul>
  <li><a href="/pub/otplogin.cgi?back=xyz">TOTP</a></li>
  <li><a href="/pub/u2flogin.cgi?back=xyz">Security Key</a></li>
</ul>
</body></html>
"""


CONSENT_HTML = """
<html><body>
<form method="post" action="/idp/profile/SAML2/Redirect/SSO?execution=e3s1">
  <input type="hidden" name="csrf_token" value="TEST_CSRF_TOKEN">
  <input type="checkbox" name="_shib_idp_consentIds" value="uid" checked>
  <input type="checkbox" name="_shib_idp_consentOptions" value="_shib_idp_rememberConsent">
  <input type="submit" name="_eventId_proceed" value="Agree">
</form>
</body></html>
"""


LS_HTML = """
<html><body>
<form method="post" action="/idp/profile/SAML2/Redirect/SSO?execution=e3s2">
  <input type="hidden" name="csrf_token" value="TEST_CSRF_TOKEN">
  <input type="hidden" name="shib_idp_ls_exception.shib_idp_persistent_ss" value="">
  <input type="hidden" name="shib_idp_ls_success.shib_idp_persistent_ss" value="">
  <input type="submit" name="_eventId_proceed" value="">
</form>
</body></html>
"""


EPPN_FORM_HTML = """
<html><body>
<form action="/opac/opac_search/" method="post">
  <input type="hidden" name="csrfmiddlewaretoken" value="TEST_CSRF_TOKEN">
  <input type="hidden" name="lang" value="0">
  <input type="hidden" name="loginMode" value="login">
  <input type="hidden" name="EPPN" value="test-eppn@example.test">
  <input type="hidden" name="rurl" value="/opac/opac_search/">
  <input type="hidden" name="opkey" value="">
</form>
</body></html>
"""


CAS_LOGIN_HTML = """
<html><body>
<form id="fm1" method="post"
      action="/cas/login;jsessionid=ABC123?service=https%3A%2F%2Fpanda.ecs.kyoto-u.ac.jp%2Fsakai-login-tool%2Fcontainer">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="lt" value="LT-1500-TESTTICKET">
  <input type="hidden" name="execution" value="e1s1">
  <input type="hidden" name="_eventId" value="submit">
  <input type="submit" name="submit" value="LOGIN">
</form>
</body></html>
"""


class TestLoginForm:
    def test_extracts_fields_and_action(self):
        result = _parsers.parse_login_form(
            LOGIN_FORM_HTML, base_url="https://auth.iimc.kyoto-u.ac.jp/pub/"
        )
        assert result["action"] == "https://auth.iimc.kyoto-u.ac.jp/pub/login.cgi"
        fields = result["fields"]
        assert fields["sessid"] == "TEST_SESSID_ABC123"
        assert fields["op"] == "login"
        assert fields["back"] == "https://example.test/back"
        assert fields["username"] == ""  # placeholder to be filled by caller

    def test_relative_action_without_base(self):
        result = _parsers.parse_login_form(LOGIN_FORM_HTML)
        assert result["action"] == "login.cgi"

    def test_missing_form_raises(self):
        with pytest.raises(AuthenticationError):
            _parsers.parse_login_form("<html></html>")


class TestOtpForm:
    def test_parses_otp_form(self):
        result = _parsers.parse_otp_form(OTP_FORM_HTML)
        assert result["fields"]["sessid"] == "TEST_SESSID_OTP_XYZ"
        assert result["action"] == "otplogin.cgi"

    def test_rejects_login_form(self):
        # Regression: wrong password returns login form; parse_otp_form must
        # not accept it or we'd POST the OTP into a login.cgi password field.
        with pytest.raises(AuthenticationError):
            _parsers.parse_otp_form(LOGIN_FORM_HTML)


class TestAuthselectLink:
    def test_prefers_otplogin(self):
        link = _parsers.parse_authselect_link(
            AUTHSELECT_HTML, base_url="https://auth.iimc.kyoto-u.ac.jp"
        )
        assert link.endswith("otplogin.cgi?back=xyz")
        assert link.startswith("https://auth.iimc.kyoto-u.ac.jp")

    def test_fallback_order(self):
        html = """<a href="/pub/u2flogin.cgi">x</a>"""
        link = _parsers.parse_authselect_link(html, prefer=("otplogin", "u2flogin"))
        assert "u2flogin.cgi" in link

    def test_no_link_raises(self):
        with pytest.raises(AuthenticationError):
            _parsers.parse_authselect_link("<html></html>")


class TestConsentForm:
    def test_defaults_filled(self):
        result = _parsers.parse_shib_consent_form(
            CONSENT_HTML, base_url="https://authidp1.iimc.kyoto-u.ac.jp"
        )
        fields = result["fields"]
        assert fields["_shib_idp_consentIds"] == "uid"
        assert fields["_shib_idp_consentOptions"] == "_shib_idp_rememberConsent"
        assert fields["_eventId_proceed"]  # non-empty (button label)
        assert fields["csrf_token"] == "TEST_CSRF_TOKEN"
        assert result["action"].startswith("https://authidp1.iimc.kyoto-u.ac.jp")


class TestLocalStorageForm:
    def test_success_flag_set_true(self):
        result = _parsers.parse_shib_localstorage_form(LS_HTML)
        fields = result["fields"]
        assert fields["shib_idp_ls_success.shib_idp_persistent_ss"] == "true"
        assert fields["csrf_token"] == "TEST_CSRF_TOKEN"


class TestCasLoginForm:
    def test_extracts_fields_and_action(self):
        result = _parsers.parse_cas_login_form(
            CAS_LOGIN_HTML, base_url="https://panda.ecs.kyoto-u.ac.jp/cas/login"
        )
        fields = result["fields"]
        assert fields["lt"] == "LT-1500-TESTTICKET"
        assert fields["execution"] == "e1s1"
        assert fields["_eventId"] == "submit"
        # submit button omitted by _collect_inputs; username/password are
        # placeholders the caller fills in.
        assert fields["username"] == ""
        assert fields["password"] == ""
        assert result["action"].startswith(
            "https://panda.ecs.kyoto-u.ac.jp/cas/login;jsessionid=ABC123"
        )

    def test_rejects_non_cas_form(self):
        # The SSP login form has an ``op`` field, not ``lt``/``execution`` —
        # must not be parsed as CAS.
        with pytest.raises(AuthenticationError):
            _parsers.parse_cas_login_form(LOGIN_FORM_HTML)


class TestEppnForm:
    def test_extracts_eppn_and_csrf(self):
        result = _parsers.parse_mykuline_eppn_form(EPPN_FORM_HTML)
        fields = result["fields"]
        assert fields["csrfmiddlewaretoken"] == "TEST_CSRF_TOKEN"
        assert fields["EPPN"] == "test-eppn@example.test"
        assert fields["loginMode"] == "login"


class TestSjisDecode:
    def test_roundtrip(self):
        text = "時間割"
        assert _parsers.decode_sjis(text.encode("cp932")) == text


class TestPredicates:
    def test_detects_consent(self):
        assert _parsers.contains_consent_page(CONSENT_HTML)
        assert not _parsers.contains_consent_page(LOGIN_FORM_HTML)

    def test_detects_localstorage(self):
        assert _parsers.contains_localstorage_form(LS_HTML)
        assert not _parsers.contains_localstorage_form(CONSENT_HTML)

    def test_detects_eppn_form(self):
        assert _parsers.contains_eppn_form(EPPN_FORM_HTML)
        assert not _parsers.contains_eppn_form(LOGIN_FORM_HTML)

    def test_detects_authselect(self):
        assert _parsers.contains_authselect('<a href="authselect.php?x=1">pick</a>')
        assert not _parsers.contains_authselect(LOGIN_FORM_HTML)

    def test_detects_cas_login(self):
        assert _parsers.contains_cas_login_form(CAS_LOGIN_HTML)
        # A form with an ``lt`` input but no ``execution`` must not match.
        assert not _parsers.contains_cas_login_form('<input name="lt" value="x">')
        assert not _parsers.contains_cas_login_form(LOGIN_FORM_HTML)


class TestMetaRefresh:
    def test_extracts_absolute_url(self):
        html = (
            '<html><head><meta http-equiv="refresh" '
            'content="0;URL=https://auth.iimc.kyoto-u.ac.jp/saml/saml2/idp/SSOService.php?x=1" />'
            "</head></html>"
        )
        url = _parsers.extract_meta_refresh_url(html)
        assert url == "https://auth.iimc.kyoto-u.ac.jp/saml/saml2/idp/SSOService.php?x=1"

    def test_resolves_relative_against_base(self):
        html = '<meta http-equiv="refresh" content="0; url=/next?a=1" />'
        url = _parsers.extract_meta_refresh_url(
            html, base_url="https://auth.iimc.kyoto-u.ac.jp/pub/login.cgi"
        )
        assert url == "https://auth.iimc.kyoto-u.ac.jp/next?a=1"

    def test_case_insensitive(self):
        html = '<META HTTP-EQUIV="Refresh" CONTENT="1;   URL = https://x.test/y">'
        assert _parsers.extract_meta_refresh_url(html) == "https://x.test/y"

    def test_returns_none_when_absent(self):
        assert _parsers.extract_meta_refresh_url(LOGIN_FORM_HTML) is None

    def test_returns_none_for_non_refresh_meta(self):
        html = '<meta name="viewport" content="0;url=ignored">'
        assert _parsers.extract_meta_refresh_url(html) is None
