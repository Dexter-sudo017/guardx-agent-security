from starlette.requests import Request

from app.services.admin_runtime import web_access_allowed


def _request(host: str, headers: list[tuple[bytes, bytes]] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/v1/private",
            "raw_path": b"/v1/private",
            "query_string": b"",
            "headers": headers or [],
            "client": (host, 12345),
            "server": ("guardx", 8000),
        }
    )


def test_missing_token_is_local_only(monkeypatch) -> None:
    monkeypatch.delenv("GUARDX_WEB_TOKEN", raising=False)
    monkeypatch.delenv("GUARDX_WEB_ALLOW_UNAUTHENTICATED_LOCALHOST", raising=False)
    monkeypatch.delenv("GUARDX_WEB_ALLOW_UNAUTHENTICATED_PUBLIC_DEMO", raising=False)
    assert web_access_allowed(_request("127.0.0.1")) is True
    assert web_access_allowed(_request("203.0.113.10")) is False


def test_configured_token_is_required_even_on_localhost(monkeypatch) -> None:
    monkeypatch.setenv("GUARDX_WEB_TOKEN", "test-token")
    assert web_access_allowed(_request("127.0.0.1")) is False
    assert web_access_allowed(_request("127.0.0.1", [(b"x-guardx-token", b"test-token")])) is True


def test_public_demo_requires_explicit_opt_in(monkeypatch) -> None:
    monkeypatch.delenv("GUARDX_WEB_TOKEN", raising=False)
    monkeypatch.setenv("GUARDX_WEB_ALLOW_UNAUTHENTICATED_PUBLIC_DEMO", "1")
    assert web_access_allowed(_request("203.0.113.10")) is True
