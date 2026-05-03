"""Unit tests for kuauth.auth (state logic, not network)."""

from __future__ import annotations

import httpx
import pytest

from kuauth.auth import DEFAULT_USER_AGENT, KyotoUAuth
from kuauth.exceptions import OTPRequiredError


def _auth(**kwargs) -> KyotoUAuth:
    client = kwargs.pop("http", None) or httpx.Client()
    return KyotoUAuth("user", "pw", http=client, **kwargs)


def test_onetime_password_wins_over_secret_and_callback():
    a = _auth(
        onetime_password="424242",
        totp_secret="JBSWY3DPEHPK3PXP",
        otp_callback=lambda: "should-not-run",
    )
    assert a._resolve_otp() == "424242"


def test_onetime_password_stripped():
    a = _auth(onetime_password="  112233\n")
    assert a._resolve_otp() == "112233"


def test_totp_secret_wins_over_callback():
    a = _auth(totp_secret="JBSWY3DPEHPK3PXP", otp_callback=lambda: "should-not-run")
    code = a._resolve_otp()
    assert code.isdigit() and len(code) == 6


def test_callback_used_when_no_secret():
    a = _auth(otp_callback=lambda: "123456")
    assert a._resolve_otp() == "123456"


def test_callback_stripped():
    a = _auth(otp_callback=lambda: "  654321\n")
    assert a._resolve_otp() == "654321"


def test_no_otp_source_raises():
    a = _auth()
    with pytest.raises(OTPRequiredError):
        a._resolve_otp()


def test_context_manager_closes_client():
    client = httpx.Client()
    with KyotoUAuth("u", "p", http=client) as a:
        assert a.http is client
    # http was DI'd, so we don't own it; stays open
    assert not client.is_closed


def test_owned_client_closes_on_exit():
    a = KyotoUAuth("u", "p")
    client = a.http
    with a:
        pass
    assert client.is_closed


def test_default_user_agent_does_not_self_identify():
    a = KyotoUAuth("u", "p")
    try:
        assert a.http.headers["User-Agent"] == DEFAULT_USER_AGENT
        assert "kuauth" not in DEFAULT_USER_AGENT.lower()
    finally:
        a.close()


def test_kuline_host_constant_matches_mykuline_base_url():
    # _KULINE_HOST in auth.py and MyKULINE.BASE_URL must agree, otherwise
    # the per-host SECLEVEL=1 mount stops covering MyKULINE on a rename.
    from urllib.parse import urlparse

    from kuauth.auth import _KULINE_HOST
    from kuauth.services.mykuline import MyKULINE

    assert urlparse(MyKULINE.BASE_URL).hostname == _KULINE_HOST


# --- Secret hygiene ---


def test_repr_does_not_leak_password():
    a = _auth(totp_secret="JBSWY3DPEHPK3PXP", onetime_password="424242")
    rep = repr(a)
    a.close()
    assert "pw" not in rep, "password leaked into repr"
    assert "JBSWY3DPEHPK3PXP" not in rep, "totp_secret leaked into repr"
    assert "424242" not in rep, "onetime_password leaked into repr"
    assert "<redacted>" in rep
    # Username is intentionally not redacted — it's already in the EPPN
    # the IdP receives, so treating it as a secret would be theatre.
    assert "user" in rep


def test_str_falls_through_to_repr():
    # ``str(obj)`` defaults to ``repr(obj)`` when __str__ is not defined,
    # so the redaction must hold for ``f"{auth}"`` / ``print(auth)`` paths.
    a = _auth()
    s = str(a)
    a.close()
    assert "pw" not in s
    assert "<redacted>" in s


def test_password_property_works_before_close():
    a = _auth()
    assert a.password == "pw"
    a.close()


def test_password_property_raises_after_close():
    a = _auth()
    a.close()
    with pytest.raises(RuntimeError, match="closed"):
        _ = a.password


def test_close_zeros_credential_bytearrays():
    # Hold references to the bytearrays before close so we can inspect
    # them after — close() drops the attribute references but the
    # bytearrays themselves should be cleared in place first.
    a = _auth(totp_secret="JBSWY3DPEHPK3PXP", onetime_password="424242")
    pw_buf = a._password
    totp_buf = a._totp_secret
    otp_buf = a._onetime_password
    assert pw_buf is not None and len(pw_buf) > 0  # baseline
    a.close()
    # After close, the buffers we held references to should have been
    # cleared (zeroed and length=0). The attributes themselves are now
    # None, but our held references show what zeroing did.
    assert pw_buf is not None
    assert len(pw_buf) == 0, "password bytearray was not cleared"
    assert totp_buf is not None and len(totp_buf) == 0, "totp_secret was not cleared"
    assert otp_buf is not None and len(otp_buf) == 0, "onetime_password was not cleared"
    assert a._password is None
    assert a._totp_secret is None
    assert a._onetime_password is None


def test_close_is_idempotent():
    a = _auth()
    a.close()
    a.close()  # second close must not raise


def test_close_via_context_manager_zeros_credentials():
    with _auth(totp_secret="JBSWY3DPEHPK3PXP") as a:
        assert a.password == "pw"
    # Exiting the context manager zeroed credentials.
    with pytest.raises(RuntimeError, match="closed"):
        _ = a.password


def test_resolve_otp_works_with_bytearray_storage():
    # Regression: _resolve_otp must decode the bytearray before handing
    # to pyotp, otherwise pyotp raises ``binascii.Error: Non-base32 digit``.
    a = _auth(totp_secret="JBSWY3DPEHPK3PXP")
    code = a._resolve_otp()
    assert len(code) == 6 and code.isdigit()
    a.close()


def test_unicode_password_roundtrips_through_bytearray():
    # Defense-in-depth for non-ASCII passwords: utf-8 encode at construction,
    # utf-8 decode on read. ``encode("utf-8")`` always produces valid bytes
    # for any str input, so the bytearray storage doesn't constrain charset.
    a = KyotoUAuth("user", "パスワード🔑", http=httpx.Client())
    try:
        assert a.password == "パスワード🔑"
    finally:
        a.close()
