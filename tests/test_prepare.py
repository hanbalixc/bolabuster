"""Tests fuer `prepare_request` (Auth-Anwendung + ID-Substitution)."""

import json

from bolabuster.config.auth import BearerAuth
from bolabuster.engine.prepare import prepare_request
from bolabuster.models import CanonicalRequest, Identity, ObjectRef


def _identity(name="alice", token="tok-alice", headers=None) -> Identity:
    return Identity(name=name, auth=BearerAuth(token=token), headers=headers or {})


def test_prepare_request_applies_auth_header():
    req = CanonicalRequest(
        method="GET",
        url="https://api.example.com/api/v1/users/1001",
        headers={},
        body=None,
        body_media_type=None,
        source_ref="test",
    )

    prepared = prepare_request(req, _identity(), strategy="self", mutated_ref=None)

    assert prepared.headers["Authorization"] == "Bearer tok-alice"
    assert prepared.identity_name == "alice"
    assert prepared.strategy == "self"
    assert prepared.method == "GET"
    assert prepared.url == req.url


def test_prepare_request_applies_identity_headers_without_overriding_auth():
    req = CanonicalRequest(
        method="GET",
        url="https://api.example.com/api/v1/users/1001",
        headers={},
        body=None,
        body_media_type=None,
        source_ref="test",
    )
    identity = _identity(headers={"Authorization": "should-not-win", "X-Tenant": "acme"})

    prepared = prepare_request(req, identity, strategy="self", mutated_ref=None)

    assert prepared.headers["Authorization"] == "Bearer tok-alice"
    assert prepared.headers["X-Tenant"] == "acme"


def test_prepare_request_substitutes_path_segment():
    req = CanonicalRequest(
        method="GET",
        url="https://api.example.com/api/v1/users/1001",
        headers={},
        body=None,
        body_media_type=None,
        source_ref="test",
    )
    ref = ObjectRef(location="path", selector="3", id_type="numeric", value="9999", confidence=0.85)

    prepared = prepare_request(req, _identity(), strategy="swap", mutated_ref=ref)

    assert prepared.url == "https://api.example.com/api/v1/users/9999"
    assert prepared.mutated_ref is ref


def test_prepare_request_substitutes_query_param():
    req = CanonicalRequest(
        method="GET",
        url="https://api.example.com/api/v1/orders?order_id=42&page=1",
        headers={},
        body=None,
        body_media_type=None,
        source_ref="test",
    )
    ref = ObjectRef(location="query", selector="order_id", id_type="numeric", value="42", confidence=0.85)

    prepared = prepare_request(req, _identity(), strategy="swap", mutated_ref=replace_value(ref, "9999"))

    assert "order_id=9999" in prepared.url
    assert "page=1" in prepared.url


def replace_value(ref: ObjectRef, new_value: str) -> ObjectRef:
    return ObjectRef(location=ref.location, selector=ref.selector, id_type=ref.id_type, value=new_value, confidence=ref.confidence)


def test_prepare_request_substitutes_body_json_pointer_preserves_int_type():
    body = json.dumps({"order": {"id": 42}}).encode("utf-8")
    req = CanonicalRequest(
        method="POST",
        url="https://api.example.com/api/v1/orders",
        headers={"Content-Type": "application/json"},
        body=body,
        body_media_type="application/json",
        source_ref="test",
    )
    ref = ObjectRef(location="body", selector="/order/id", id_type="numeric", value="9999", confidence=0.85)

    prepared = prepare_request(req, _identity(), strategy="swap", mutated_ref=ref)

    assert json.loads(prepared.body) == {"order": {"id": 9999}}


def test_prepare_request_substitutes_header():
    req = CanonicalRequest(
        method="GET",
        url="https://api.example.com/api/v1/orders",
        headers={"X-Account-Id": "42"},
        body=None,
        body_media_type=None,
        source_ref="test",
    )
    ref = ObjectRef(location="header", selector="X-Account-Id", id_type="numeric", value="9999", confidence=0.85)

    prepared = prepare_request(req, _identity(), strategy="swap", mutated_ref=ref)

    assert prepared.headers["X-Account-Id"] == "9999"
