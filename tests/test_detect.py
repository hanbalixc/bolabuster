"""Tests fuer die Objekt-Referenz-Erkennung (bolabuster.detect)."""

import json

from bolabuster.detect import DEFAULT_DETECTORS, DetectionHints, extract_object_refs
from bolabuster.models import CanonicalRequest, GraphQlMeta


def _req(**overrides) -> CanonicalRequest:
    defaults = dict(
        method="GET",
        url="https://example.test/api/v1/users/1001?order=99",
        headers={"Accept": "application/json"},
        body=None,
        body_media_type=None,
        source_ref="test#0",
    )
    defaults.update(overrides)
    return CanonicalRequest(**defaults)


def test_mixed_ids_across_locations():
    body = json.dumps({"account": {"id": "550e8400-e29b-41d4-a716-446655440000"}}).encode()
    req = _req(body=body, body_media_type="application/json")

    refs = extract_object_refs(req, DEFAULT_DETECTORS, DetectionHints())

    path_refs = [r for r in refs if r.location == "path"]
    query_refs = [r for r in refs if r.location == "query"]
    body_refs = [r for r in refs if r.location == "body"]

    assert any(r.selector == "3" and r.value == "1001" and r.id_type == "numeric" for r in path_refs)
    assert any(r.selector == "order" and r.value == "99" for r in query_refs)
    assert any(
        r.selector == "/account/id" and r.id_type == "uuid" and r.value == "550e8400-e29b-41d4-a716-446655440000"
        for r in body_refs
    )
    assert req.body_parse_failed is False


def test_uuid_detected_with_high_confidence():
    req = _req(url="https://example.test/api/orders/550e8400-e29b-41d4-a716-446655440000")
    refs = extract_object_refs(req, DEFAULT_DETECTORS, DetectionHints())
    uuid_refs = [r for r in refs if r.id_type == "uuid"]
    assert len(uuid_refs) == 1
    assert uuid_refs[0].confidence == 1.0


def test_graphql_global_id_detected():
    import base64

    global_id = base64.b64encode(b"User:42").decode()
    meta = GraphQlMeta(operation="GetUser", query="query GetUser($id: ID!) { user(id: $id) { id } }",
                        variables={"id": global_id})
    req = _req(url="https://example.test/graphql", graphql=meta, body=None)

    refs = extract_object_refs(req, DEFAULT_DETECTORS, DetectionHints())

    gql_refs = [r for r in refs if r.location == "graphql"]
    assert len(gql_refs) == 1
    assert gql_refs[0].id_type == "graphql_global"
    assert gql_refs[0].value == global_id
    assert gql_refs[0].confidence < 1.0


def test_pagination_param_not_flagged_as_id():
    req = _req(url="https://example.test/api/v1/items?page=2")
    refs = extract_object_refs(req, DEFAULT_DETECTORS, DetectionHints())
    query_refs = [r for r in refs if r.location == "query"]
    assert query_refs == []


def test_body_parse_failure_sets_flag_and_warns_without_raising():
    req = _req(url="https://example.test/api/v1/orders", body=b"{not valid json", body_media_type="application/json")
    hints = DetectionHints()

    refs = extract_object_refs(req, DEFAULT_DETECTORS, hints)

    assert req.body_parse_failed is True
    assert [r for r in refs if r.location == "body"] == []
    assert len(hints.warnings) == 1
    assert "test#0" in hints.warnings[0]


def test_hint_ignore_suppresses_selector():
    req = _req(url="https://example.test/api/orders/550e8400-e29b-41d4-a716-446655440000")
    hints = DetectionHints(ignore={"2"})  # path segment index 2 = die UUID

    refs = extract_object_refs(req, DEFAULT_DETECTORS, hints)

    assert refs == []


def test_hint_force_id_creates_ref_for_unrecognized_selector():
    body = json.dumps({"token": "opaque-not-id-shaped"}).encode()
    req = _req(url="https://example.test/api/v1/session", body=body, body_media_type="application/json")

    # Ohne Hint wird "/token" nicht erkannt (kein UUID/numeric/graphql-Muster).
    baseline = extract_object_refs(req, DEFAULT_DETECTORS, DetectionHints())
    assert baseline == []

    req.body_parse_failed = False  # frischer Request-State fuer den zweiten Lauf
    hints = DetectionHints(force_id={"/token": "numeric"})
    refs = extract_object_refs(req, DEFAULT_DETECTORS, hints)

    forced = [r for r in refs if r.selector == "/token"]
    assert len(forced) == 1
    assert forced[0].id_type == "numeric"
    assert forced[0].confidence == 1.0
