"""Shared pytest config for kuauth tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless KUAUTH_LIVE=1."""
    if os.environ.get("KUAUTH_LIVE") == "1":
        return
    skip_mark = pytest.mark.skip(reason="live credentials not configured (set KUAUTH_LIVE=1)")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_mark)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR
