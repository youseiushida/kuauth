"""Exception hierarchy for kuauth."""


class KuauthError(Exception):
    """Base exception for kuauth."""


class AuthenticationError(KuauthError):
    """Raised when authentication to the IdP fails."""


class OTPRequiredError(AuthenticationError):
    """Raised when OTP is needed but no secret or callback is configured."""


class ConsentRequiredError(AuthenticationError):
    """Raised when an IdP consent page cannot be auto-accepted."""


class SPAccessError(KuauthError):
    """Raised when the Shibboleth handoff to an SP fails."""
