"""Roundtrip-Smoketest: je ein Objekt jeder Dataclass instanziieren."""

from bolabuster.models import (
    CanonicalRequest,
    DiffEvidence,
    Finding,
    GraphQlMeta,
    Identity,
    ObjectRef,
    PreparedRequest,
    RawResponse,
)


class DummyAuth:
    """Minimales AuthMaterial fuer den Smoketest (Protocol-Erfuellung)."""

    type = "dummy"

    def apply(self, prepared: PreparedRequest) -> PreparedRequest:
        return prepared


def test_graphql_meta_roundtrip():
    meta = GraphQlMeta(operation="GetUser", query="query { user { id } }")
    assert meta.operation == "GetUser"
    assert meta.variables == {}


def test_object_ref_roundtrip():
    ref = ObjectRef(location="path", selector="1", id_type="uuid", value="abc-123", confidence=0.9)
    assert ref.location == "path"


def test_prepared_request_roundtrip():
    prepared = PreparedRequest(
        method="GET",
        url="https://example.test/api/1",
        headers={},
        body=None,
        identity_name="attacker",
        strategy="swap",
    )
    assert prepared.strategy == "swap"


def test_identity_roundtrip():
    identity = Identity(name="attacker", auth=DummyAuth())
    assert identity.headers == {}
    assert identity.known_object_ids == []


def test_canonical_request_roundtrip():
    req = CanonicalRequest(
        method="GET",
        url="https://example.test/api/1",
        headers={"Accept": "application/json"},
        body=None,
        body_media_type=None,
        source_ref="harfile.har#0",
    )
    assert req.object_refs == []
    assert req.body_parse_failed is False


def test_raw_response_roundtrip():
    resp = RawResponse(status=200, headers={}, body=b"{}", elapsed_ms=12.3)
    assert resp.status == 200
    assert resp.error is None


def test_diff_evidence_roundtrip():
    evidence = DiffEvidence(attacker_excerpt="...", owner_excerpt="...")
    assert evidence.notes == ""


def test_finding_roundtrip():
    finding = Finding(
        id="abc123",
        severity="high",
        verdict="confirmed",
        endpoint="GET /api/orders/{id}",
        parameter="id",
        id_type="uuid",
        attacker_identity="attacker",
        owner_identity="owner",
        evidence=DiffEvidence(attacker_excerpt="a", owner_excerpt="b"),
        repro_curl="curl ...",
        write_operation=False,
        source_ref="harfile.har#0",
    )
    assert finding.severity == "high"
