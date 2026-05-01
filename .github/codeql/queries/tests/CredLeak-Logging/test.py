"""Test fixtures for CredLeak-Logging."""

import logging
import sys
import warnings


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


logger = logging.getLogger(__name__)


# --- Positive cases (should be flagged) ---

def leak_password_via_logger_info(auth: KyotoUAuth) -> None:
    logger.info(auth.password)  # NOT OK


def leak_password_via_logger_debug_format(auth: KyotoUAuth) -> None:
    logger.debug("password=%s", auth.password)  # NOT OK


def leak_otp_via_print(auth: KyotoUAuth) -> None:
    otp = auth._resolve_otp()
    print(f"otp={otp}")  # NOT OK


def leak_password_via_warnings(auth: KyotoUAuth) -> None:
    warnings.warn(f"using password {auth._password}")  # NOT OK


def leak_password_via_stderr(auth: KyotoUAuth) -> None:
    sys.stderr.write(auth._password)  # NOT OK


def leak_totp_secret_via_logger(auth: KyotoUAuth) -> None:
    logger.error("seed: %s", auth._totp_secret)  # NOT OK


def leak_via_log_method(auth: KyotoUAuth) -> None:
    logger.log(logging.WARNING, auth.password)  # NOT OK


# --- Negative cases (should NOT be flagged) ---

def safe_log_username(auth: KyotoUAuth) -> None:
    logger.info("user=%s", auth.username)  # OK — username is not a source


def safe_log_metadata(auth: KyotoUAuth) -> None:
    otp = auth._resolve_otp()
    logger.debug("otp len=%d", len(otp))  # OK — only the length is logged


def safe_log_redacted(auth: KyotoUAuth) -> None:
    if auth._password:
        logger.info("password configured: yes")  # OK — flag, not value
