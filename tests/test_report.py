"""Tests fuer bolabuster.report: to_curl, write_json, render_text."""

import json

import pytest

from bolabuster.errors import ReportWriteError
from bolabuster.models import DiffEvidence, Finding, PreparedRequest
from bolabuster.report import RunMeta, render_text, to_curl, write_json


def _make_finding(
    *,
    id="f-1",
    severity="high",
    endpoint="GET /api/orders/{id}",
    parameter="id",
) -> Finding:
    return Finding(
        id=id,
        severity=severity,
        verdict="confirmed",
        endpoint=endpoint,
        parameter=parameter,
        id_type="uuid",
        attacker_identity="attacker",
        owner_identity="owner",
        evidence=DiffEvidence(attacker_excerpt="200 {...}", owner_excerpt="200 {...}"),
        repro_curl="curl ...",
        write_operation=False,
        source_ref="harfile.har#0",
    )


def _make_meta(**overrides) -> RunMeta:
    defaults = dict(
        version="0.1.0",
        target="https://example.test",
        started_at="2026-09-04T10:00:00Z",
        finished_at="2026-09-04T10:05:00Z",
        engagement_ref="ENG-1",
        counts={"high": 1},
    )
    defaults.update(overrides)
    return RunMeta(**defaults)


# --- to_curl ---------------------------------------------------------------


def test_to_curl_contains_method_headers_body_and_warning():
    prepared = PreparedRequest(
        method="POST",
        url="https://example.test/api/orders/42",
        headers={"Authorization": "Bearer secret-token", "Content-Type": "application/json"},
        body=b'{"note": "it\'s a test"}',
        identity_name="attacker",
        strategy="swap",
    )

    curl = to_curl(prepared)

    assert "WARNING" in curl.splitlines()[0]
    assert "-X POST" in curl
    assert "-H 'Authorization: Bearer secret-token'" in curl
    assert "-H 'Content-Type: application/json'" in curl
    assert "--data" in curl
    # Body-Inhalt muss enthalten sein; der Apostroph wird shell-sicher gequotet.
    assert "note" in curl and "test" in curl
    assert "https://example.test/api/orders/42" in curl


def test_to_curl_undecodable_body_is_omitted_with_note():
    prepared = PreparedRequest(
        method="POST",
        url="https://example.test/api/upload",
        headers={},
        body=b"\xff\xfe\x00binary",
        identity_name="attacker",
        strategy="swap",
    )

    curl = to_curl(prepared)

    assert "--data" not in curl
    assert "NOTE" in curl


def test_to_curl_no_body_no_data_flag():
    prepared = PreparedRequest(
        method="GET",
        url="https://example.test/api/orders/42",
        headers={},
        body=None,
        identity_name="attacker",
        strategy="swap",
    )

    curl = to_curl(prepared)

    assert "--data" not in curl
    assert "-X GET" in curl


# --- write_json --------------------------------------------------------


def test_write_json_schema_and_sorting(tmp_path):
    findings = [
        _make_finding(id="f-low", severity="low", endpoint="GET /b"),
        _make_finding(id="f-critical", severity="critical", endpoint="GET /a"),
        _make_finding(id="f-high", severity="high", endpoint="GET /c"),
    ]
    meta = _make_meta(counts={"low": 1, "critical": 1, "high": 1})
    out = tmp_path / "report.json"

    write_json(findings, meta, out)

    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["schema_version"] == "1.0"
    assert document["meta"]["target"] == "https://example.test"
    ids_in_order = [f["id"] for f in document["findings"]]
    assert ids_in_order == ["f-critical", "f-high", "f-low"]


def test_write_json_is_deterministic(tmp_path):
    findings = [
        _make_finding(id="f-1", severity="high"),
        _make_finding(id="f-2", severity="critical"),
    ]
    meta = _make_meta()
    out1 = tmp_path / "report1.json"
    out2 = tmp_path / "report2.json"

    write_json(findings, meta, out1)
    write_json(findings, meta, out2)

    assert out1.read_bytes() == out2.read_bytes()


def test_write_json_invalid_path_raises_report_write_error(tmp_path):
    findings = [_make_finding()]
    meta = _make_meta()
    # Verzeichnis als Ziel existiert nicht -> OSError beim Schreiben.
    out = tmp_path / "does" / "not" / "exist" / "report.json"

    with pytest.raises(ReportWriteError):
        write_json(findings, meta, out)


# --- render_text ---------------------------------------------------------


def test_render_text_contains_key_fields():
    finding = _make_finding()
    meta = _make_meta()

    text = render_text([finding], meta)

    assert "HIGH" in text
    assert finding.endpoint in text
    assert finding.attacker_identity in text
    assert finding.owner_identity in text
    assert finding.verdict in text
    assert finding.repro_curl in text


def test_render_text_stable_severity_order():
    findings = [
        _make_finding(id="f-info", severity="info", endpoint="GET /z"),
        _make_finding(id="f-critical", severity="critical", endpoint="GET /a"),
        _make_finding(id="f-medium", severity="medium", endpoint="GET /m"),
    ]
    meta = _make_meta()

    text = render_text(findings, meta)

    pos_critical = text.index("f-critical")
    pos_medium = text.index("f-medium")
    pos_info = text.index("f-info")
    assert pos_critical < pos_medium < pos_info
