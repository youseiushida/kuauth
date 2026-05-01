"""Test fixtures for CredLeak-Exception."""


class KyotoUAuth:
    def __init__(self, username: str, password: str, *, totp_secret: str | None = None):
        self._username = username
        self._password = password
        self._totp_secret = totp_secret

    @property
    def password(self) -> str:
        return self._password

    @property
    def username(self) -> str:
        return self._username

    def _resolve_otp(self) -> str:
        return "123456"


class AuthenticationError(Exception):
    pass


# --- Positive cases (should be flagged) ---

def leak_password_in_raise(auth: KyotoUAuth) -> None:
    raise AuthenticationError(f"failed for {auth._password}")  # NOT OK


def leak_password_via_property(auth: KyotoUAuth) -> None:
    raise AuthenticationError(auth.password)  # NOT OK


def leak_otp_in_raise(auth: KyotoUAuth) -> None:
    otp = auth._resolve_otp()
    raise AuthenticationError(f"otp {otp} rejected")  # NOT OK


def leak_totp_secret_in_raise(auth: KyotoUAuth) -> None:
    raise ValueError(f"bad seed: {auth._totp_secret}")  # NOT OK


def leak_via_concat(auth: KyotoUAuth) -> None:
    msg = "password=" + auth._password
    raise AuthenticationError(msg)  # NOT OK


# --- Negative cases (should NOT be flagged) ---

def safe_username_in_raise(auth: KyotoUAuth) -> None:
    raise AuthenticationError(f"login failed for user={auth.username}")  # OK


def safe_metadata_in_raise(auth: KyotoUAuth) -> None:
    if not auth._password:
        raise AuthenticationError("password not configured")  # OK


def safe_otp_length_in_raise(auth: KyotoUAuth) -> None:
    otp = auth._resolve_otp()
    if len(otp) != 6:
        raise AuthenticationError(f"OTP length {len(otp)} != 6")  # OK
