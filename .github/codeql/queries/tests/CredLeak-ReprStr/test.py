"""Test fixtures for CredLeak-ReprStr."""


# --- Positive cases (should be flagged) ---

class KyotoUAuthBadRepr:
    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def __repr__(self) -> str:
        return f"KyotoUAuthBadRepr(user={self._username}, pw={self._password})"  # NOT OK


class KyotoUAuthBadStr:
    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def __str__(self) -> str:
        return f"<auth pw={self._password}>"  # NOT OK


class WithOtpRepr:
    def __init__(self, totp_secret: str):
        self._totp_secret = totp_secret

    def __repr__(self) -> str:
        return f"WithOtpRepr(seed={self._totp_secret})"  # NOT OK


# --- Negative cases (should NOT be flagged) ---

class KyotoUAuthGoodRepr:
    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def __repr__(self) -> str:
        return f"KyotoUAuthGoodRepr(user={self._username})"  # OK


class KyotoUAuthRedactedRepr:
    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def __repr__(self) -> str:
        has_pw = "yes" if self._password else "no"
        return f"KyotoUAuthRedactedRepr(user={self._username}, pw_set={has_pw})"  # OK


class KyotoUAuthDefaultRepr:
    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password
    # No __repr__ / __str__ — uses default object identity. OK.
