"""Verpflichtender End-to-End-Test der kompletten `scan`-Pipeline.

Deckt den zentralen Vertrag ab: gegen ein Ziel mit einer verwundbaren und
einer sicheren Route entsteht genau EIN `confirmed`-Finding (auf der
verwundbaren Route), und `--dry-run` sendet nichts. Netzfrei via
`MockHttpClient`, injiziert ueber `run_scan(args, client=...)`.

Ergaenzt (nicht dupliziert) `tests/test_cli.py::test_happy_path_...`: dort
liegt der Fokus auf CLI-Wiring (Flags, JSON, neighbor_range); hier liegt der
Fokus auf dem Sicherheitsvertrag selbst - zwei eigenstaendige Identitaeten
alice/bob, eine verwundbare und eine sichere Route, explizite Pruefung von
Attacker-/Owner-Identitaet, Severity und repro_curl-Warnzeile.
"""

from __future__ import annotations

import json

from bolabuster.cli import build_arg_parser, run_scan
from bolabuster.http.client import MockHttpClient
from bolabuster.models import PreparedRequest, RawResponse

_BASE_URL = "https://api.example.test"

# Engine-Semantik (siehe `engine/replay.py::_plan_cells`): eine `swap`-Zelle
# fuer (attacker=X, owner=Y) wird nur geplant, wenn Y (der "Owner") an der
# Ref-Position `known_object_ids` traegt - dieser Wert ist das Angriffsziel.
# Um Alice eindeutig als alleinige Angreiferin auf Bobs Objekt 1002 zu
# planen (und NICHT zusaetzlich die Gegenrichtung Bob->Alice), bekommt nur
# Bob eine `known_object_ids`-Eintragung. Alices Self-Baseline faellt auf den
# unveraenderten Original-Wert aus dem Korpus zurueck (hier "1001") - das ist
# der dokumentierte Fallback-Mechanismus, kein Sonderfall.
_IDENTITIES_YAML = """\
identities:
  - name: alice
    auth: {type: bearer, token: alice-token}
  - name: bob
    auth: {type: bearer, token: bob-token}
    known_object_ids: ["1002"]
"""

_SCOPE_YAML = f"""\
authorization:
  confirmed: true
  engagement_ref: BB-2026-e2e-test
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

# Zwei objektbezogene GET-Requests: eine verwundbare Order-Route (Bob ist
# Owner von 1002, Ziel der Alice-Attacke) und eine sichere Profil-Route
# (ebenfalls Bobs 1002 als Ziel), die Cross-Access sauber mit 403 abweist.
# Der im Korpus aufgezeichnete Original-Wert (1001) wird Alices Self-Baseline
# (Fallback, s.o.).
_CORPUS_TEXT = """\
GET /api/v1/orders/1001 HTTP/1.1
Host: api.example.test

======

GET /api/v1/profile/1001 HTTP/1.1
Host: api.example.test
"""


def _write(path, text: str) -> str:
    path.write_text(text, encoding="utf-8")
    return str(path)


def _base_args(tmp_path, **overrides):
    identities_path = _write(tmp_path / "identities.yaml", _IDENTITIES_YAML)
    scope_path = _write(tmp_path / "scope.yaml", _SCOPE_YAML)
    corpus_path = _write(tmp_path / "corpus.txt", _CORPUS_TEXT)

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


def _vulnerable_and_secure_mock() -> MockHttpClient:
    return MockHttpClient(
        {
            # --- verwundbare Route: /api/v1/orders/{id} -----------------
            # owner_baseline (Bob ruft 1002 ab) UND attacker_resp (Alice
            # ruft per swap ebenfalls 1002 ab) treffen auf dieselbe URL -
            # MockHttpClient schluesselt nur nach Methode+URL, nicht nach
            # Identitaet/Auth-Header. Das bildet exakt die Schwachstelle ab:
            # der Server liefert Bobs Marker an jeden, der die URL kennt.
            f"GET {_BASE_URL}/api/v1/orders/1002": _resp(
                200, {"owner": "bob", "secret": "bob-order-secret"}
            ),
            # attacker_own_baseline: Alice ruft ihr eigenes Objekt (Fallback
            # auf den Original-Korpuswert 1001) ab -> Alices eigener Marker
            # (strukturgleich, andere Werte als Bobs Baseline).
            f"GET {_BASE_URL}/api/v1/orders/1001": _resp(
                200, {"owner": "alice", "secret": "alice-order-secret"}
            ),
            #
            # --- sichere Route: /api/v1/profile/{id} --------------------
            # owner_baseline UND attacker_resp treffen ebenfalls auf
            # dieselbe URL (Bobs Ziel-ID 1002) - hier antwortet der Server
            # aber korrekt mit 403, unabhaengig vom Aufrufer.
            f"GET {_BASE_URL}/api/v1/profile/1002": _resp(
                403, {"error": "forbidden"}
            ),
            # Alices Self-Baseline auf der sicheren Route (Fallback 1001),
            # damit die Triade ueberhaupt vollstaendig zusammengesetzt wird.
            f"GET {_BASE_URL}/api/v1/profile/1001": _resp(
                200, {"owner": "alice", "email": "alice@example.test"}
            ),
        }
    )


class _CountingClient:
    """Zaehlt `send`-Aufrufe und delegiert an einen echten MockHttpClient.

    Wird fuer den Dry-Run-Test gebraucht, um zu belegen, dass die Engine im
    Dry-Run wirklich niemals `send` aufruft.
    """

    def __init__(self, inner: MockHttpClient) -> None:
        self._inner = inner
        self.send_count = 0

    def send(self, req: PreparedRequest, timeout: float) -> RawResponse:
        self.send_count += 1
        return self._inner.send(req, timeout)


# --- E2E: genau ein confirmed-Finding auf der verwundbaren Route -----------


def test_e2e_exactly_one_confirmed_finding_on_vulnerable_route(tmp_path):
    out_path = tmp_path / "report.json"
    args = _base_args(tmp_path, format="json", output=str(out_path))
    client = _vulnerable_and_secure_mock()

    code = run_scan(args, client=client)

    assert code == 0
    document = json.loads(out_path.read_text(encoding="utf-8"))
    findings = document["findings"]

    confirmed = [f for f in findings if f["verdict"] == "confirmed"]
    assert len(confirmed) == 1, f"expected exactly one confirmed finding, got: {confirmed}"

    finding = confirmed[0]
    assert "orders" in finding["endpoint"]
    assert "profile" not in finding["endpoint"]
    assert finding["attacker_identity"] == "alice"
    assert finding["owner_identity"] == "bob"
    assert finding["severity"] == "high"  # Read (GET), kein write_operation
    assert finding["write_operation"] is False

    # Die sichere Route darf zu KEINEM confirmed-Finding fuehren.
    confirmed_endpoints = {f["endpoint"] for f in confirmed}
    assert not any("profile" in e for e in confirmed_endpoints)

    # repro_curl enthaelt die verpflichtende Warn-Kommentarzeile fuer
    # Live-Zugangsdaten der Angreifer-Identitaet.
    assert "WARNING" in finding["repro_curl"]
    assert "Live-Zugangsdaten der Angreifer-Identitaet" in finding["repro_curl"]
    assert "curl" in finding["repro_curl"]


def test_e2e_secure_route_produces_no_finding_at_all(tmp_path):
    """Die sichere 403-Route darf ueberhaupt kein Finding erzeugen (weder
    confirmed noch empty_200) - 403 ist der klassifizierte `denied`-Fall,
    fuer den `build_finding` bewusst `None` liefert."""
    out_path = tmp_path / "report.json"
    args = _base_args(tmp_path, format="json", output=str(out_path))
    client = _vulnerable_and_secure_mock()

    code = run_scan(args, client=client)

    assert code == 0
    document = json.loads(out_path.read_text(encoding="utf-8"))
    findings_on_profile = [f for f in document["findings"] if "profile" in f["endpoint"]]
    assert findings_on_profile == []


# --- Dry-Run: sendet nichts -------------------------------------------------


def test_e2e_dry_run_sends_nothing(tmp_path):
    out_path = tmp_path / "report.txt"
    args = _base_args(tmp_path, dry_run=True, output=str(out_path))
    counting_client = _CountingClient(_vulnerable_and_secure_mock())

    code = run_scan(args, client=counting_client)

    assert code == 0
    assert counting_client.send_count == 0

    text = out_path.read_text(encoding="utf-8")
    assert "dry-run summary" in text
    # Keine Findings-Sektion im Dry-Run, da nichts gesendet/klassifiziert wurde.
    assert "confirmed" not in text.lower()
    assert "findings by severity" not in text
