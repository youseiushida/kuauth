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
