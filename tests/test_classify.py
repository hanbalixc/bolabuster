"""Tests fuer bolabuster.classify (Response-Diffing & Klassifikation)."""

import json

from bolabuster.classify import CellContext, ClassifyConfig, build_finding, classify_cell
from bolabuster.models import ObjectRef, RawResponse


def _resp(status=200, body=b"", headers=None, elapsed_ms=10.0, error=None) -> RawResponse:
    return RawResponse(status=status, headers=headers or {}, body=body, elapsed_ms=elapsed_ms, error=error)


def _ref(value="1001") -> ObjectRef:
    return ObjectRef(location="path", selector="3", id_type="numeric", value=value, confidence=0.85)


def _cell(write_operation=False, strategy="swap") -> CellContext:
    return CellContext(
        endpoint="GET /api/v1/accounts/{id}",
        parameter="3",
        id_type="numeric",
        attacker_identity="attacker",
        owner_identity="owner",
        write_operation=write_operation,
        source_ref="corpus.har#0",
        strategy=strategy,
        repro_curl="curl -X GET https://example.test/api/v1/accounts/1001",
    )


def _json_body(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")


# ---------------------------------------------------------------------------
# confirmed
# ---------------------------------------------------------------------------


def test_confirmed_when_attacker_sees_owner_marker():
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test", "balance": 500}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test", "balance": 10}))
    attacker_resp = _resp(body=_json_body({"id": 1001, "email": "owner@example.test", "balance": 500}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "confirmed"
    assert cls.structural_only is False
    assert cls.score == 1.0
    assert "owner@example.test" in cls.evidence.attacker_excerpt


def test_build_finding_confirmed_read_is_high():
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test"}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test"}))
    attacker_resp = _resp(body=_json_body({"id": 1001, "email": "owner@example.test"}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())
    finding = build_finding(_cell(write_operation=False), cls)

    assert finding is not None
    assert finding.severity == "high"
    assert finding.verdict == "confirmed"


def test_build_finding_confirmed_write_is_critical():
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test"}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test"}))
    attacker_resp = _resp(body=_json_body({"id": 1001, "email": "owner@example.test"}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())
    finding = build_finding(_cell(write_operation=True), cls)

    assert finding is not None
    assert finding.severity == "critical"


# ---------------------------------------------------------------------------
# empty_200
# ---------------------------------------------------------------------------


def test_empty_200_when_body_empty_json():
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test", "balance": 500}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test", "balance": 10}))
    attacker_resp = _resp(body=_json_body({}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "empty_200"
    assert cls.verdict != "confirmed"


def test_build_finding_empty_200_is_low():
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test", "balance": 500}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test", "balance": 10}))
    attacker_resp = _resp(body=_json_body({}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())
    finding = build_finding(_cell(), cls)

    assert finding is not None
    assert finding.severity == "low"


# ---------------------------------------------------------------------------
# denied
# ---------------------------------------------------------------------------


def test_denied_on_403():
    owner_baseline = _resp(body=_json_body({"id": 1001}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002}))
    attacker_resp = _resp(status=403, body=b"forbidden")

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "denied"
    assert build_finding(_cell(), cls) is None


def test_denied_on_login_redirect():
    owner_baseline = _resp(body=_json_body({"id": 1001}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002}))
    attacker_resp = _resp(status=302, headers={"Location": "https://example.test/login"})

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "denied"


# ---------------------------------------------------------------------------
# error
# ---------------------------------------------------------------------------


def test_error_on_transport_error():
    owner_baseline = _resp(body=_json_body({"id": 1001}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002}))
    attacker_resp = _resp(status=-1, error="connection reset")

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "error"
    assert build_finding(_cell(), cls) is None


def test_error_on_5xx():
    owner_baseline = _resp(body=_json_body({"id": 1001}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002}))
    attacker_resp = _resp(status=500, body=b"internal server error")

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "error"


# ---------------------------------------------------------------------------
# irrelevant
# ---------------------------------------------------------------------------


def test_irrelevant_when_attacker_sees_only_own_data():
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test", "balance": 500}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test", "balance": 10}))
    attacker_resp = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test", "balance": 10}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "irrelevant"
    assert build_finding(_cell(), cls) is None


# ---------------------------------------------------------------------------
# Volatile-Maskierung
# ---------------------------------------------------------------------------


def test_volatile_timestamp_does_not_affect_verdict():
    owner_baseline = _resp(
        body=_json_body({"id": 1001, "email": "owner@example.test", "generated_at": "2026-09-04T10:00:00Z"})
    )
    attacker_own_baseline = _resp(
        body=_json_body({"id": 1001, "email": "owner@example.test", "generated_at": "2026-09-04T11:30:00Z"})
    )
    attacker_resp = _resp(
        body=_json_body({"id": 1001, "email": "owner@example.test", "generated_at": "2026-09-04T12:45:00Z"})
    )

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    # owner_baseline und attacker_own_baseline unterscheiden sich nur im
    # (volatilen) Timestamp -> nach Maskierung identisch -> Risiko-1-Pfad,
    # nicht "confirmed" ueber einen Timestamp-Marker.
    assert cls.verdict == "confirmed"
    assert cls.structural_only is True


def test_volatile_custom_field_masked_via_config():
    cfg = ClassifyConfig(volatile_fields=["request_nonce"])
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test", "request_nonce": "aaa111"}))
    attacker_own_baseline = _resp(
        body=_json_body({"id": 1001, "email": "owner@example.test", "request_nonce": "bbb222"})
    )
    attacker_resp = _resp(body=_json_body({"id": 1001, "email": "owner@example.test", "request_nonce": "ccc333"}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), cfg)

    assert cls.verdict == "confirmed"
    assert cls.structural_only is True


# ---------------------------------------------------------------------------
# nicht-JSON-Body (Fallback-Marker-Ableitung)
# ---------------------------------------------------------------------------


def test_non_json_body_fallback_marker_confirms():
    owner_baseline = _resp(
        body=b"<html><body>Account owner-secret-marker-xyz balance 500</body></html>",
        headers={"Content-Type": "text/html"},
    )
    attacker_own_baseline = _resp(
        body=b"<html><body>Account attacker-own-value-abc balance 10</body></html>",
        headers={"Content-Type": "text/html"},
    )
    attacker_resp = _resp(
        body=b"<html><body>Account owner-secret-marker-xyz balance 500</body></html>",
        headers={"Content-Type": "text/html"},
    )

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "confirmed"


def test_non_json_body_never_raises_on_irrelevant():
    owner_baseline = _resp(body=b"<html>owner-secret-marker-xyz</html>", headers={"Content-Type": "text/html"})
    attacker_own_baseline = _resp(body=b"<html>attacker-own-value</html>", headers={"Content-Type": "text/html"})
    attacker_resp = _resp(body=b"<html>generic public page</html>", headers={"Content-Type": "text/html"})

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict in ("irrelevant", "empty_200")


# ---------------------------------------------------------------------------
# Finding 1: kein False Positive durch Substring-Marker-Matching
# ---------------------------------------------------------------------------


def test_short_numeric_id_does_not_falsely_confirm_via_substring():
    # owner id=1/Bob, attacker_own id=2/Alice, attacker_resp id=21/Alice:
    # Server isoliert korrekt (A bekommt ihr eigenes Objekt id=21), aber
    # "1" ist ein Teilstring von "21" - das darf NICHT als Marker-Treffer
    # zaehlen (frueher: Substring-Match -> faelschlich confirmed).
    owner_baseline = _resp(body=_json_body({"id": 1, "name": "Bob"}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2, "name": "Alice"}))
    attacker_resp = _resp(body=_json_body({"id": 21, "name": "Alice"}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict != "confirmed"
    assert build_finding(_cell(), cls) is None


def test_real_unique_marker_still_confirms_despite_short_id_noise():
    # Echte, eindeutige Marker (hier: der Name "Bob") muessen weiterhin
    # confirmed ergeben - auch wenn zusaetzlich eine kurze numerische ID
    # als (nicht matchender) Kandidat mit im Marker-Set steckt.
    owner_baseline = _resp(body=_json_body({"id": 1, "name": "Bob"}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2, "name": "Alice"}))
    attacker_resp = _resp(body=_json_body({"id": 1, "name": "Bob"}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "confirmed"
    assert cls.structural_only is False


# ---------------------------------------------------------------------------
# Risiko-1: identische Baselines
# ---------------------------------------------------------------------------


def test_risk1_identical_baselines_yields_structural_only_medium_finding():
    shared_body = _json_body({"id": 1001, "status": "active"})
    owner_baseline = _resp(body=shared_body)
    attacker_own_baseline = _resp(body=shared_body)
    attacker_resp = _resp(body=shared_body)

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "confirmed"
    assert cls.structural_only is True
    assert "manuelle Verifikation" in cls.evidence.notes

    finding = build_finding(_cell(), cls)
    assert finding is not None
    assert finding.severity == "medium"


# ---------------------------------------------------------------------------
# build_finding: Determinismus & Secret-Maskierung
# ---------------------------------------------------------------------------


def test_finding_id_is_deterministic():
    owner_baseline = _resp(body=_json_body({"id": 1001, "email": "owner@example.test"}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "email": "attacker@example.test"}))
    attacker_resp = _resp(body=_json_body({"id": 1001, "email": "owner@example.test"}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    finding_a = build_finding(_cell(), cls)
    finding_b = build_finding(_cell(), cls)

    assert finding_a is not None and finding_b is not None
    assert finding_a.id == finding_b.id
    assert len(finding_a.id) > 0


def test_secret_in_body_is_masked_in_evidence():
    owner_baseline = _resp(
        body=_json_body(
            {
                "id": 1001,
                "email": "owner@example.test",
                "password": "super-secret-value",
                "api_key": "sk_live_abcdef1234567890",
            }
        )
    )
    attacker_own_baseline = _resp(
        body=_json_body({"id": 2002, "email": "attacker@example.test", "password": "x", "api_key": "y"})
    )
    attacker_resp = _resp(
        body=_json_body(
            {
                "id": 1001,
                "email": "owner@example.test",
                "password": "super-secret-value",
                "api_key": "sk_live_abcdef1234567890",
            }
        )
    )

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert cls.verdict == "confirmed"
    assert "super-secret-value" not in cls.evidence.attacker_excerpt
    assert "sk_live_abcdef1234567890" not in cls.evidence.attacker_excerpt
    assert "super-secret-value" not in cls.evidence.owner_excerpt


def test_jwt_access_token_masked_in_evidence():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    owner_baseline = _resp(body=_json_body({"id": 1001, "access": jwt}))
    attacker_own_baseline = _resp(body=_json_body({"id": 2002, "access": "other"}))
    attacker_resp = _resp(body=_json_body({"id": 1001, "access": jwt}))

    cls = classify_cell(owner_baseline, attacker_resp, attacker_own_baseline, _ref(), ClassifyConfig())

    assert jwt not in cls.evidence.attacker_excerpt
    assert jwt not in cls.evidence.owner_excerpt
