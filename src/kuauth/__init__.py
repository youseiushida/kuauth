"""kuauth — Unified client for Kyoto University SSO services."""

from kuauth.auth import KyotoUAuth
from kuauth.exceptions import (
    AuthenticationError,
    ConsentRequiredError,
    KuauthError,
    OTPRequiredError,
    SPAccessError,
)
from kuauth.services.kulasis import KULASIS
from kuauth.services.kulms import KULMS
from kuauth.services.mykuline import MyKULINE
from kuauth.services.panda import PandA

__version__ = "0.4.0"

__all__ = [
    "KULASIS",
    "KULMS",
    "AuthenticationError",
    "ConsentRequiredError",
    "KuauthError",
    "KyotoUAuth",
    "MyKULINE",
    "OTPRequiredError",
    "PandA",
    "SPAccessError",
    "__version__",
]
