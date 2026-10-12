"""`docs/api.md` is generated, so it can't be edited by hand or left behind."""

from pathlib import Path
from typing import Any

from syncryption_server.apidocs import render
from syncryption_server.app import create_app
from syncryption_server.config import Settings

API_MD = Path(__file__).resolve().parents[2] / "docs" / "api.md"
REGENERATE = "uv run python -m syncryption_server apidocs > ../docs/api.md"


def schema() -> dict[str, Any]:
    # The schema doesn't depend on the settings, and building the app opens nothing.
    return create_app(Settings(shared_secret="unused")).openapi()  # noqa: S106


def test_api_md_is_current() -> None:
    assert API_MD.read_text() == render(schema()), f"docs/api.md is out of date: run `{REGENERATE}`"


def test_every_endpoint_has_a_description() -> None:
    """A route without a docstring would be a bare heading in the reference."""
    missing = [
        f"{method.upper()} {path}"
        for path, operations in schema()["paths"].items()
        for method, operation in operations.items()
        if not operation.get("description", "").strip()
    ]
    assert not missing, f"no docstring on: {', '.join(missing)}"


def test_validation_errors_are_documented_as_400() -> None:
    """The app answers 400 with the error envelope, not FastAPI's 422 (openapi.py)."""
    api = schema()
    verify = api["paths"]["/api/v1/auth/verify"]["post"]["responses"]
    assert "422" not in verify
    assert verify["400"]["content"]["application/json"]["schema"]["$ref"].endswith("/Error")
    assert "HTTPValidationError" not in api["components"]["schemas"]
