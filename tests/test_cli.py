"""E2E-/Orchestrierungstests fuer `bolabuster.cli` (Schritt 11).

Alle Tests, die eine Replay-Matrix ausfuehren, spritzen `MockHttpClient` ueber
`run_scan(args, client=...)` - netzfrei, kein echter Server, keine echten
Requests.
"""

from __future__ import annotations

import json

import pytest

from bolabuster.cli import build_arg_parser, run_scan
from bolabuster.http.client import MockHttpClient
from bolabuster.models import RawResponse

_BASE_URL = "https://api.example.test"

_IDENTITIES_YAML = """\
identities:
  - name: alice
    auth: {type: bearer, token: alice-token}
    known_object_ids: ["1001"]
  - name: bob
    auth: {type: bearer, token: bob-token}
"""

_SCOPE_YAML_CONFIRMED = f"""\
authorization:
  confirmed: true
  engagement_ref: BB-2026-cli-test
target:
  base_url: {_BASE_URL}
  allow_paths: ["/api/v1/*"]
limits:
  rate_per_sec: 1000
  max_requests: 5000
  timeout_sec: 5
enumeration:
  enabled: false
  neighbor_range: 5
"""

_SCOPE_YAML_NOT_CONFIRMED = f"""\
authorization:
  confirmed: false
  engagement_ref: BB-2026-cli-test
target:
  base_url: {_BASE_URL}
  allow_paths: ["/api/v1/*"]
"""

_SCOPE_YAML_MISSING_AUTH = f"""\
target:
  base_url: {_BASE_URL}
  allow_paths: ["/api/v1/*"]
"""

_CORPUS_TEXT = """\
GET /api/v1/orders/9999 HTTP/1.1
Host: api.example.test

======

GET /api/v1/profile/4444 HTTP/1.1
Host: api.example.test
"""


def _write(path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def _base_args(tmp_path, **overrides):
    identities_path = _write(tmp_path / "identities.yaml", _IDENTITIES_YAML)
    scope_path = _write(tmp_path / "scope.yaml", overrides.pop("scope_yaml", _SCOPE_YAML_CONFIRMED))
    corpus_path = _write(tmp_path / "corpus.txt", overrides.pop("corpus_text", _CORPUS_TEXT))

    argv = ["--config", identities_path, "--scope", scope_path, "--corpus", corpus_path]
    for key, value in overrides.items():
        flag = "--" + key.replace("_", "-")
        if value is True:
            argv.append(flag)
        elif value is not False and value is not None:
            argv.extend([flag, str(value)])
    return build_arg_parser().parse_args(argv)


def _resp(status: int, body: dict) -> RawResponse:
    return RawResponse(
        status=status,
        headers={"content-type": "application/json"},
        body=json.dumps(body).encode("utf-8"),
        elapsed_ms=1.0,
        error=None,
    )


def _happy_path_mock() -> MockHttpClient:
    return MockHttpClient(
        {
            # verwundbarer Endpoint: bob's swap (owner=alice, id=1001) landet
            # auf derselben URL wie alice's eigene Baseline.
            f"GET {_BASE_URL}/api/v1/orders/1001": _resp(200, {"owner": "alice", "secret": "alice-secret-data"}),
            # bob's Self-Baseline (kein known_object_ids -> Fallback auf den
            # Original-Wert aus dem Korpus).
            f"GET {_BASE_URL}/api/v1/orders/9999": _resp(200, {"owner": "bob", "secret": "bob-secret-data"}),
            # sicherer Endpoint: der Owner-Wert (alice, "1001") ist hier
            # sauber vor Bob geschuetzt - 403 fuer jeden, der ihn abruft.
            f"GET {_BASE_URL}/api/v1/profile/1001": _resp(403, {"error": "forbidden"}),
            f"GET {_BASE_URL}/api/v1/profile/4444": _resp(200, {"owner": "bob", "email": "bob@example.test"}),
        }
    )


# --- Autorisierungs-Gate ----------------------------------------------------


def test_exit_3_when_authorization_not_confirmed(tmp_path):
    args = _base_args(tmp_path, scope_yaml=_SCOPE_YAML_NOT_CONFIRMED)
    client = MockHttpClient({})

    code = run_scan(args, client=client)

    assert code == 3


def test_exit_3_when_authorization_block_missing(tmp_path):
    args = _base_args(tmp_path, scope_yaml=_SCOPE_YAML_MISSING_AUTH)
    client = MockHttpClient({})

    code = run_scan(args, client=client)

    assert code == 3


# --- Finding 4: fehlende Config-/Corpus-Datei -> Exit 2, Scope bleibt Exit 3 -


def test_exit_2_when_config_file_missing(tmp_path):
    args = _base_args(tmp_path)
    args.config = str(tmp_path / "does-not-exist.yaml")
    client = MockHttpClient({})

    code = run_scan(args, client=client)

    assert code == 2


def test_exit_2_when_corpus_file_missing(tmp_path):
    args = _base_args(tmp_path)
    args.corpus = str(tmp_path / "does-not-exist.txt")
    client = MockHttpClient({})

    code = run_scan(args, client=client)

    assert code == 2


def test_exit_3_when_scope_file_missing(tmp_path):
    args = _base_args(tmp_path)
    args.scope = str(tmp_path / "does-not-exist.yaml")
    client = MockHttpClient({})

    code = run_scan(args, client=client)

    assert code == 3


# --- E2E happy path ----------------------------------------------------------


def test_happy_path_produces_exactly_one_confirmed_finding(tmp_path, capsys):
    out_path = tmp_path / "report.txt"
    args = _base_args(tmp_path, output=str(out_path))
    client = _happy_path_mock()

    code = run_scan(args, client=client)

    assert code == 0
    text = out_path.read_text(encoding="utf-8")
    assert text.count("- confirmed") == 1
    assert "orders" in text


# --- Dry-Run -----------------------------------------------------------------


def test_dry_run_never_sends_and_has_no_findings_section(tmp_path):
    out_path = tmp_path / "report.txt"
    args = _base_args(tmp_path, dry_run=True, output=str(out_path))

    class _CountingClient:
        def __init__(self):
            self.send_count = 0

        def send(self, req, timeout):
            self.send_count += 1
            raise AssertionError("darf im Dry-Run nie aufgerufen werden")

    client = _CountingClient()

    code = run_scan(args, client=client)

    assert code == 0
    assert client.send_count == 0
    text = out_path.read_text(encoding="utf-8")
    assert "dry-run summary" in text
    assert "geplante Requests" in text
    assert "CONFIRMED" not in text
    assert "findings by severity" not in text


# --- --format json -------------------------------------------------------


def test_format_json_produces_valid_schema(tmp_path):
    out_path = tmp_path / "report.json"
    args = _base_args(tmp_path, format="json", output=str(out_path))
    client = _happy_path_mock()

    code = run_scan(args, client=client)

    assert code == 0
    document = json.loads(out_path.read_text(encoding="utf-8"))
    assert "schema_version" in document
    assert "meta" in document
    assert "findings" in document
    assert isinstance(document["findings"], list)
    confirmed = [f for f in document["findings"] if f["verdict"] == "confirmed"]
    assert len(confirmed) == 1


# --- neighbor_range-Wiring -----------------------------------------------


_ENUM_CORPUS = """\
GET /api/v1/orders/1000 HTTP/1.1
Host: api.example.test
"""

_ENUM_IDENTITIES_YAML = """\
identities:
  - name: alice
    auth: {type: bearer, token: alice-token}
    known_object_ids: ["1000"]
  - name: bob
    auth: {type: bearer, token: bob-token}
    known_object_ids: ["1000"]
"""


def _enum_scope_yaml(neighbor_range: int) -> str:
    return f"""\
authorization:
  confirmed: true
  engagement_ref: BB-2026-enum-test
target:
  base_url: {_BASE_URL}
  allow_paths: ["/api/v1/*"]
limits:
  rate_per_sec: 1000
  max_requests: 5000
  timeout_sec: 5
enumeration:
  enabled: true
  neighbor_range: {neighbor_range}
"""


def test_neighbor_range_from_scope_yaml_controls_enumeration_via_summary(tmp_path):
    identities_path = _write(tmp_path / "identities.yaml", _ENUM_IDENTITIES_YAML)
    scope_path = _write(tmp_path / "scope.yaml", _enum_scope_yaml(neighbor_range=2))
    corpus_path = _write(tmp_path / "corpus.txt", _ENUM_CORPUS)
    out_path = tmp_path / "summary.txt"

    args = build_arg_parser().parse_args(
        [
            "--config",
            identities_path,
            "--scope",
            scope_path,
            "--corpus",
            corpus_path,
            "--enumerate",
            "--dry-run",
            "-o",
            str(out_path),
        ]
    )

    client = MockHttpClient({})
    code = run_scan(args, client=client)

    assert code == 0
    text = out_path.read_text(encoding="utf-8")
    # self(2) + swap(2, da beide bekannte IDs haben) + enumerate(2 Identitaeten * 4 Nachbarn = 8) = 12 geplante Zellen.
    assert "geplante Requests: 12" in text
