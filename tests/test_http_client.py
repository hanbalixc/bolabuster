"""Tests fuer den HTTP-Wrapper (bolabuster.http.client)."""

import httpx
import pytest
import respx

from bolabuster.http.client import HttpxClient, MockHttpClient
from bolabuster.models import PreparedRequest, RawResponse


def _prepared(method: str = "GET", url: str = "https://example.test/api/1") -> PreparedRequest:
    return PreparedRequest(
        method=method,
        url=url,
        headers={"Accept": "application/json"},
        body=None,
        identity_name="attacker",
        strategy="self",
    )


@respx.mock
def test_httpx_client_200_response():
    respx.get("https://example.test/api/1").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    client = HttpxClient()

    result = client.send(_prepared(), timeout=5.0)

    assert result.status == 200
    assert result.body == b'{"ok":true}'
    assert result.error is None
    assert result.elapsed_ms >= 0


@respx.mock
def test_httpx_client_404_response_is_not_an_error():
    respx.get("https://example.test/api/1").mock(return_value=httpx.Response(404))
    client = HttpxClient()

    result = client.send(_prepared(), timeout=5.0)

    assert result.status == 404
    assert result.error is None


@respx.mock
def test_httpx_client_transport_error_does_not_raise():
    respx.get("https://example.test/api/1").mock(
        side_effect=httpx.ConnectError("connection refused")
    )
    client = HttpxClient()

    result = client.send(_prepared(), timeout=5.0)

    assert result.status == -1
    assert result.error is not None
    assert "connection refused" in result.error


@respx.mock
def test_httpx_client_timeout_does_not_raise():
    respx.get("https://example.test/api/1").mock(
        side_effect=httpx.TimeoutException("timed out")
    )
    client = HttpxClient()

    result = client.send(_prepared(), timeout=5.0)

    assert result.status == -1
    assert result.error is not None


def test_mock_http_client_returns_configured_response():
    prepared = _prepared()
    expected = RawResponse(status=200, headers={}, body=b"hello", elapsed_ms=1.0)
    key = MockHttpClient.key_for(prepared)
    client = MockHttpClient({key: expected})

    result = client.send(prepared, timeout=5.0)

    assert result is expected


def test_mock_http_client_unknown_key_returns_error_response_without_raising():
    client = MockHttpClient({})

    result = client.send(_prepared(), timeout=5.0)

    assert result.status == -1
    assert result.error is not None
    assert "no mock for key" in result.error
