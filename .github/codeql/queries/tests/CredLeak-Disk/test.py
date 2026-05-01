"""Test fixtures for CredLeak-Disk."""

import csv
import json
import pickle
from pathlib import Path


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


# --- Positive cases (should be flagged) ---

def leak_via_file_write(auth: KyotoUAuth) -> None:
    with open("/tmp/cache.txt", "w") as f:
        f.write(auth._password)  # NOT OK


def leak_via_path_write_text(auth: KyotoUAuth) -> None:
    Path("/tmp/cache.txt").write_text(auth.password)  # NOT OK


def leak_via_json_dumps(auth: KyotoUAuth) -> None:
    payload = {"user": auth.username, "pw": auth._password}
    json.dumps(payload)  # NOT OK (pw in serialized blob)


def leak_via_json_dump(auth: KyotoUAuth) -> None:
    with open("/tmp/cache.json", "w") as f:
        json.dump({"otp": auth._resolve_otp()}, f)  # NOT OK


def leak_via_pickle_dumps(auth: KyotoUAuth) -> None:
    pickle.dumps({"seed": auth._totp_secret})  # NOT OK


def leak_via_csv_writerow(auth: KyotoUAuth) -> None:
    with open("/tmp/cache.csv", "w") as f:
        w = csv.writer(f)
        w.writerow([auth.username, auth._password])  # NOT OK


# --- Negative cases (should NOT be flagged) ---

def safe_username_only(auth: KyotoUAuth) -> None:
    Path("/tmp/cache.txt").write_text(auth.username)  # OK


def safe_metadata_json(auth: KyotoUAuth) -> None:
    has_pw = bool(auth._password)
    json.dumps({"user": auth.username, "pw_set": has_pw})  # OK
