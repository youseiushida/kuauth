"""Pure HTML/form parsers. No network, no side effects."""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from kuauth.exceptions import AuthenticationError


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "lxml")


def _collect_inputs(form: Tag) -> dict[str, str]:
    """Collect form inputs into a dict, mirroring browser submission rules.

    - Unchecked checkboxes / radios are omitted (browsers don't submit them).
    - Submit buttons are omitted; callers re-inject the one they "pressed".
    - Everything else keeps its ``value`` attribute (defaulting to "").
    """
    fields: dict[str, str] = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        inp_type = (inp.get("type") or "text").lower()
        if inp_type in ("checkbox", "radio"):
            if inp.has_attr("checked"):
                fields[name] = inp.get("value", "on")
            continue
        if inp_type == "submit":
            continue
        fields[name] = inp.get("value", "")
    return fields


def _find_form(
    soup: BeautifulSoup, *, form_id: str | None = None, has_input: str | None = None
) -> Tag:
    if form_id:
        form = soup.find("form", id=form_id)
        if form:
            return form
    if has_input:
        for form in soup.find_all("form"):
            if form.find("input", {"name": has_input}):
                return form
    raise AuthenticationError(f"form not found (id={form_id!r}, has_input={has_input!r})")


def _resolve_action(form: Tag, base_url: str | None) -> str:
    action = form.get("action", "")
    if base_url:
        return urljoin(base_url, action) if action else base_url
    return action


def _action_basename(form: Tag) -> str:
    action = form.get("action", "") or ""
    return action.rsplit("/", 1)[-1].split("?", 1)[0]


def _find_form_by_action(soup: BeautifulSoup, basename: str) -> Tag | None:
    for form in soup.find_all("form"):
        if _action_basename(form) == basename:
            return form
    return None


def parse_login_form(html: str, *, base_url: str | None = None) -> dict:
    """Parse the SimpleSAMLphp /pub/login.cgi login form.

    The login form and OTP form share ``id="login"`` + ``sessid`` — we pin on
    the form's action basename (``login.cgi``) to distinguish them, so a
    rejected password doesn't get parsed as an OTP form downstream.

    Returns {"action": str, "fields": dict[str, str]}.
    """
    soup = _soup(html)
    form = _find_form_by_action(soup, "login.cgi")
    if form is None or not form.find("input", {"name": "sessid"}):
        raise AuthenticationError("login form (action=login.cgi) not found")
    return {
        "action": _resolve_action(form, base_url),
        "fields": _collect_inputs(form),
    }


def parse_otp_form(html: str, *, base_url: str | None = None) -> dict:
    """Parse the SimpleSAMLphp /pub/otplogin.cgi form.

    Same shape as the password form; the ``password`` field carries the OTP.
    Pinned on action basename ``otplogin.cgi``.
    """
    soup = _soup(html)
    form = _find_form_by_action(soup, "otplogin.cgi")
    if form is None or not form.find("input", {"name": "sessid"}):
        raise AuthenticationError("OTP form (action=otplogin.cgi) not found")
    return {
        "action": _resolve_action(form, base_url),
        "fields": _collect_inputs(form),
    }


def parse_authselect_link(
    html: str,
    *,
    base_url: str | None = None,
    prefer: Iterable[str] = ("otplogin", "motplogin", "u2flogin"),
) -> str:
    """Find the preferred method link on the /user/authselect.php picker page.

    Returns an absolute URL (if ``base_url`` is given) or whatever the link has.
    """
    soup = _soup(html)
    for method in prefer:
        # Bind ``method`` explicitly so the lambda captures the iteration's
        # value rather than the late-binding loop variable. (BeautifulSoup
        # invokes the predicate immediately during the same iteration, so
        # the bug doesn't trigger today, but the explicit bind keeps
        # tooling like ``ruff B023`` quiet and the intent obvious.)
        a = soup.find("a", href=lambda h, m=method: h and m in h)
        if a:
            href = a["href"]
            return urljoin(base_url, href) if base_url else href
    raise AuthenticationError(f"no authselect link found for methods: {tuple(prefer)}")


def parse_shib_consent_form(html: str, *, base_url: str | None = None) -> dict:
    """Parse the Shibboleth IdP attribute-release consent page.

    Returns {"action": str, "fields": dict[str, str]}. Caller should ensure
    _shib_idp_consentIds and _shib_idp_consentOptions are set appropriately.
    """
    soup = _soup(html)
    form = _find_form(soup, has_input="_shib_idp_consentIds")
    fields = _collect_inputs(form)
    # Ensure consent fields have sensible defaults if absent as values.
    fields.setdefault("_shib_idp_consentIds", "uid")
    fields.setdefault("_shib_idp_consentOptions", "_shib_idp_rememberConsent")
    # _eventId_proceed is the submit button; carry a non-empty value.
    if not fields.get("_eventId_proceed"):
        fields["_eventId_proceed"] = "\u540c\u610f"  # 同意
    return {
        "action": _resolve_action(form, base_url),
        "fields": fields,
    }


def parse_shib_localstorage_form(html: str, *, base_url: str | None = None) -> dict:
    """Parse the Shibboleth IdP localStorage-sync form.

    We claim success without real localStorage state to let the flow proceed.
    """
    soup = _soup(html)
    form = _find_form(soup, has_input="shib_idp_ls_success.shib_idp_persistent_ss")
    fields = _collect_inputs(form)
    fields["shib_idp_ls_success.shib_idp_persistent_ss"] = "true"
    fields.setdefault("shib_idp_ls_exception.shib_idp_persistent_ss", "")
    fields.setdefault("_eventId_proceed", "")
    return {
        "action": _resolve_action(form, base_url),
        "fields": fields,
    }


def parse_shib_idp_login_form(html: str, *, base_url: str | None = None) -> dict:
    """Parse the Shibboleth IdP (Java) username/password login form.

    Field names are ``j_username`` and ``j_password``. Caller must inject
    credentials into the returned ``fields`` dict before POSTing.
    """
    soup = _soup(html)
    form = _find_form(soup, has_input="j_username")
    fields = _collect_inputs(form)
    fields.setdefault("_eventId_proceed", "")
    return {
        "action": _resolve_action(form, base_url),
        "fields": fields,
    }


def parse_cas_login_form(html: str, *, base_url: str | None = None) -> dict:
    """Parse the Apereo/Jasig CAS 3.x login form served by ECS (PandA).

    The form carries ``username``/``password`` plus hidden ``lt`` (login
    ticket), ``execution``, and ``_eventId`` fields. The action may have a
    ``;jsessionid=...`` path parameter when cookies aren't available — we
    keep it as-is so the POST goes to the same session.

    Returns {"action": str, "fields": dict[str, str]}.
    """
    soup = _soup(html)
    form = _find_form(soup, has_input="lt")
    if not form.find("input", {"name": "execution"}):
        raise AuthenticationError("CAS login form missing 'execution' field")
    fields = _collect_inputs(form)
    fields.setdefault("_eventId", "submit")
    return {
        "action": _resolve_action(form, base_url),
        "fields": fields,
    }


def contains_cas_login_form(html: str) -> bool:
    """Detect the ECS CAS login form.

    Pins on the combination of ``name="lt"`` and ``name="execution"`` so we
    don't false-positive on stray ``lt`` inputs.
    """
    return ('name="lt"' in html or "name='lt'" in html) and (
        'name="execution"' in html or "name='execution'" in html
    )


def parse_mykuline_eppn_form(html: str, *, base_url: str | None = None) -> dict:
    """Parse the Django EPPN exchange form on MyKULINE.

    The form has csrfmiddlewaretoken, loginMode, EPPN, rurl, opkey, lang.
    The HTML ``action="./"`` is a stub — the page's JS overrides it with the
    ``rurl`` field before submitting, so POST target is ``rurl``.
    Returns {"action": str, "fields": dict[str, str]}.
    """
    soup = _soup(html)
    form = _find_form(soup, has_input="csrfmiddlewaretoken")
    fields = _collect_inputs(form)
    fields.setdefault("loginMode", "login")
    rurl = fields.get("rurl", "")
    action = urljoin(base_url, rurl) if rurl and base_url else _resolve_action(form, base_url)
    return {
        "action": action,
        "fields": fields,
    }


def decode_sjis(body: bytes) -> str:
    """Decode a cp932/Shift_JIS byte string used by KULASIS."""
    return body.decode("cp932")


def contains_consent_page(html: str) -> bool:
    return "_shib_idp_consentIds" in html


def contains_localstorage_form(html: str) -> bool:
    return "shib_idp_ls_success" in html


_SAML_RESPONSE_ATTR_RE = re.compile(r'name\s*=\s*["\']?SAMLResponse\b')


def contains_saml_autosubmit(html: str) -> bool:
    return bool(_SAML_RESPONSE_ATTR_RE.search(html))


def contains_eppn_form(html: str) -> bool:
    return "csrfmiddlewaretoken" in html and "EPPN" in html


def contains_authselect(html: str) -> bool:
    return "authselect.php" in html


def contains_login_form(html: str) -> bool:
    soup = _soup(html)
    return _find_form_by_action(soup, "login.cgi") is not None


def contains_otp_form(html: str) -> bool:
    soup = _soup(html)
    return _find_form_by_action(soup, "otplogin.cgi") is not None


def contains_shib_idp_login_form(html: str) -> bool:
    return 'name="j_username"' in html or "name='j_username'" in html


_META_REFRESH_URL_RE = re.compile(r"""url\s*=\s*['"]?([^'"\s]+)""", re.IGNORECASE)


def extract_meta_refresh_url(html: str, *, base_url: str | None = None) -> str | None:
    """Return the target URL of a ``<meta http-equiv="refresh" ...>`` tag.

    Accepts ``content="0;URL=..."`` with any casing/spacing. Returns ``None``
    if no meta-refresh is present.
    """
    soup = _soup(html)
    for m in soup.find_all("meta"):
        if (m.get("http-equiv") or "").lower() != "refresh":
            continue
        content = m.get("content") or ""
        match = _META_REFRESH_URL_RE.search(content)
        if not match:
            continue
        url = match.group(1).strip()
        return urljoin(base_url, url) if base_url else url
    return None
