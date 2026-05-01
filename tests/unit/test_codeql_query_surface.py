"""Pin the kuauth attribute surface that the CodeQL custom queries match.

The bespoke queries in ``.github/codeql/lib/KuauthSources.qll`` identify
credentials by ATTRIBUTE NAME (``_password``, ``_totp_secret``, etc.) on
``KyotoUAuth`` instances. The QL test fixtures use synthetic stand-ins
that mirror those names, so the QL test pack alone cannot detect a
rename in the real source — the queries would silently stop matching
while ``query-tests`` stays green.

These tests close that gap. If you rename one of the pinned attributes
or methods in ``src/kuauth/auth.py``:

1. This test fails immediately on the next ``uv run pytest`` / CI run.
2. Update ``.github/codeql/lib/KuauthSources.qll`` so its name lookup
   matches the new identifier.
3. Update each QL test fixture (``test.py``) to use the new name.
4. Regenerate ``.expected`` baselines via
   ``codeql test run --learn .github/codeql/queries/tests/`` and
   re-commit.

Adding a NEW credential-bearing attribute? Add the name here AND in
``KuauthSources.qll`` together, in the same change.
"""

from __future__ import annotations

import pytest

from kuauth.auth import KyotoUAuth


@pytest.fixture
def auth() -> KyotoUAuth:
    a = KyotoUAuth(
        "u",
        "p",
        totp_secret="JBSWY3DPEHPK3PXP",
        onetime_password="123456",
        otp_callback=lambda: "654321",
    )
    yield a
    a.close()


# Attribute names referenced by KuauthSources.isCredentialAttributeRead.
PRIVATE_CREDENTIAL_ATTRS = ["_password", "_totp_secret", "_onetime_password"]


@pytest.mark.parametrize("name", PRIVATE_CREDENTIAL_ATTRS)
def test_private_credential_attribute_present(auth: KyotoUAuth, name: str) -> None:
    assert hasattr(auth, name), (
        f"KyotoUAuth.{name} not found. "
        "If renamed, update .github/codeql/lib/KuauthSources.qll "
        "(isCredentialAttributeRead) and the QL test fixtures."
    )


def test_password_property_present() -> None:
    # KuauthSources.isCredentialAttributeRead also matches the public
    # ``password`` name (e.g. ``auth.password``).
    descriptor = getattr(KyotoUAuth, "password", None)
    assert isinstance(descriptor, property), (
        "KyotoUAuth.password is no longer a property. "
        "If removed/renamed, drop ``password`` from "
        "KuauthSources.isCredentialAttributeRead's name list."
    )


def test_resolve_otp_method_present(auth: KyotoUAuth) -> None:
    # KuauthSources.isResolveOtpCall matches ``_resolve_otp`` calls.
    method = getattr(auth, "_resolve_otp", None)
    assert callable(method), (
        "KyotoUAuth._resolve_otp is no longer callable. "
        "If renamed, update KuauthSources.isResolveOtpCall."
    )


def test_otp_callback_attribute_present() -> None:
    # KuauthSources.isOtpCallableInvocation matches ``<obj>._otp_callback()``.
    a = KyotoUAuth("u", "p", otp_callback=lambda: "654321")
    try:
        cb = getattr(a, "_otp_callback", None)
        assert callable(cb), (
            "KyotoUAuth._otp_callback is no longer callable. "
            "If renamed, update KuauthSources.isOtpCallableInvocation."
        )
    finally:
        a.close()


# Function names allowlisted by KuauthAllowedHosts.isLegitimateAuthSubmitter.
LEGITIMATE_AUTH_SUBMITTERS = [
    ("kuauth.services._base", "ShibbolethSPService", "_submit_simplesaml_password"),
    ("kuauth.services._base", "ShibbolethSPService", "_submit_simplesaml_otp"),
    ("kuauth.services._base", "ShibbolethSPService", "_submit_shib_idp_login"),
    ("kuauth.services.panda", "PandA", "_submit_cas_login"),
]


@pytest.mark.parametrize("module_name, class_name, method_name", LEGITIMATE_AUTH_SUBMITTERS)
def test_legitimate_auth_submitter_present(
    module_name: str, class_name: str, method_name: str
) -> None:
    """Each name on the IdP/CAS submitter allowlist must still exist in
    src/. A rename here without a corresponding update to
    ``KuauthAllowedHosts.qll`` would un-sanitize legitimate POSTs and
    flood ``CredLeak-UnknownHttp`` with false positives."""
    import importlib

    mod = importlib.import_module(module_name)
    cls = getattr(mod, class_name, None)
    assert cls is not None, (
        f"{module_name}.{class_name} missing — update KuauthAllowedHosts.qll."
    )
    method = getattr(cls, method_name, None)
    assert callable(method), (
        f"{class_name}.{method_name} missing — update "
        f"KuauthAllowedHosts.isLegitimateAuthSubmitter."
    )
