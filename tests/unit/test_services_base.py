"""Unit tests for ShibbolethSPService's generic get/post/request + KULASIS SJIS override."""

from __future__ import annotations

import httpx
import pytest

from kuauth.auth import KyotoUAuth
from kuauth.services._base import ShibbolethSPService
from kuauth.services.kulasis import KULASIS


class _FakeService(ShibbolethSPService):
    BASE_URL = "https://example.test"
    ENTRY_PATH = "/entry"


def _auth_with_mock(responses: dict[tuple[str, str], httpx.Response]) -> KyotoUAuth:
    def handler(req: httpx.Request) -> httpx.Response:
        key = (req.method, str(req.url))
        if key not in responses:
            return httpx.Response(404, text="unmatched " + repr(key))
        return responses[key]

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, base_url="https://example.test")
    return KyotoUAuth("u", "p", http=client)


def _ready_service(cls, responses) -> ShibbolethSPService:
    auth = _auth_with_mock(responses)
    svc = cls(auth)
    svc._sp_ready = True
    auth._logged_in = True
    return svc


def test_resolve_absolute_passes_through():
    svc = _FakeService(_auth_with_mock({}))
    assert svc._resolve("https://other.example/x") == "https://other.example/x"
    assert svc._resolve("http://other.example/x") == "http://other.example/x"


def test_resolve_relative_prepends_base():
    svc = _FakeService(_auth_with_mock({}))
    assert svc._resolve("/foo") == "https://example.test/foo"


def test_get_hits_resolved_url():
    svc = _ready_service(
        _FakeService,
        {("GET", "https://example.test/ping"): httpx.Response(200, text="pong")},
    )
    r = svc.get("/ping")
    assert r.status_code == 200 and r.text == "pong"


def test_post_forwards_body():
    captured: dict = {}

    def handler(req: httpx.Request) -> httpx.Response:
        captured["url"] = str(req.url)
        captured["body"] = req.content
        return httpx.Response(200, text="ok")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    auth = KyotoUAuth("u", "p", http=client)
    auth._logged_in = True
    svc = _FakeService(auth)
    svc._sp_ready = True

    r = svc.post("/submit", data={"k": "v"})
    assert r.status_code == 200
    assert captured["url"] == "https://example.test/submit"
    assert b"k=v" in captured["body"]


def test_request_supports_arbitrary_method():
    svc = _ready_service(
        _FakeService,
        {("PUT", "https://example.test/x"): httpx.Response(204)},
    )
    r = svc.request("PUT", "/x")
    assert r.status_code == 204


def test_get_accepts_absolute_url():
    svc = _ready_service(
        _FakeService,
        {("GET", "https://other.example/z"): httpx.Response(200, text="z")},
    )
    r = svc.get("https://other.example/z")
    assert r.text == "z"


def test_kulasis_get_decodes_sjis():
    sjis_bytes = "京大".encode("cp932")
    svc = _ready_service(
        KULASIS,
        {(
            "GET",
            "https://www.k.kyoto-u.ac.jp/student/la/top",
        ): httpx.Response(200, content=sjis_bytes)},
    )
    r = svc.get("/student/la/top")
    assert r.encoding == "cp932"
    assert r.text == "京大"
    assert r.content == sjis_bytes


def test_get_triggers_ensure_session_when_not_ready(monkeypatch):
    svc = _FakeService(_auth_with_mock(
        {("GET", "https://example.test/x"): httpx.Response(200, text="ok")}
    ))
    calls = {"n": 0}

    def fake_ensure(self):
        calls["n"] += 1
        self._sp_ready = True

    monkeypatch.setattr(_FakeService, "_ensure_session", fake_ensure)
    svc.get("/x")
    assert calls["n"] == 1
    # Second call is a no-op (already ready), ensure_session still called (but sees _sp_ready)
    svc.get("/x")
    assert calls["n"] == 2
