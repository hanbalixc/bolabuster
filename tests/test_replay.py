"""Tests fuer `ReplayEngine`, `ReplayResult` und `assemble_triads`."""

from __future__ import annotations

from bolabuster.config.auth import BearerAuth
from bolabuster.config.scope import EnumerationConfig, LimitsConfig, RunConfig, ScopeConfig, TargetConfig
from bolabuster.engine.ratelimit import NullLimiter
from bolabuster.engine.replay import ReplayEngine, assemble_triads
from bolabuster.engine.scope import ScopeEnforcer
from bolabuster.http.client import MockHttpClient
from bolabuster.models import CanonicalRequest, Identity, ObjectRef, RawResponse

_BASE_URL = "https://api.example.com"


class _CountingClient:
    """Wrappt `MockHttpClient` und zaehlt tatsaechliche `send`-Aufrufe."""

    def __init__(self, mock: MockHttpClient) -> None:
        self._mock = mock
        self.send_count = 0

    def send(self, req, timeout: float):
        self.send_count += 1
        return self._mock.send(req, timeout)


def _identity(name: str, known_ids: list[str]) -> Identity:
    return Identity(name=name, auth=BearerAuth(token=f"tok-{name}"), known_object_ids=known_ids)


def _scope_enforcer(allow_paths=None) -> ScopeEnforcer:
    scope = ScopeConfig(
        engagement_ref="BB-2026-test",
        target=TargetConfig(base_url=_BASE_URL, allow_paths=allow_paths or ["/api/v1/*"], deny_paths=[]),
        limits=LimitsConfig(),
        enumeration=EnumerationConfig(),
    )
    return ScopeEnforcer(scope, allow_writes=False)


def _run_config(dry_run=False, enumerate_=False, max_requests=5000, rate_per_sec=1000.0) -> RunConfig:
    return RunConfig(
        dry_run=dry_run,
        allow_writes=False,
        enumerate=enumerate_,
        limits=LimitsConfig(rate_per_sec=rate_per_sec, max_requests=max_requests, timeout_sec=5.0),
    )


def _order_request(order_id: str = "1001") -> CanonicalRequest:
    return CanonicalRequest(
        method="GET",
        url=f"{_BASE_URL}/api/v1/orders/{order_id}",
        headers={},
        body=None,
        body_media_type=None,
        source_ref="req-1",
        object_refs=[ObjectRef(location="path", selector="3", id_type="numeric", value=order_id, confidence=0.85)],
    )


def _resp(status=200) -> RawResponse:
    return RawResponse(status=status, headers={}, body=b"{}", elapsed_ms=1.0, error=None)


def test_matrix_covers_self_for_both_identities_and_swap_cross_play():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])
    bob = _identity("bob", ["2002"])

    client = MockHttpClient(
        {
            "GET https://api.example.com/api/v1/orders/1001": _resp(200),
            "GET https://api.example.com/api/v1/orders/2002": _resp(200),
        }
    )
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config())

    results = engine.run([req], [alice, bob])

    self_cells = {(r.identity_name, r.owner_identity) for r in results if r.strategy == "self"}
    swap_cells = {(r.identity_name, r.owner_identity) for r in results if r.strategy == "swap"}

    assert self_cells == {("alice", "alice"), ("bob", "bob")}
    assert swap_cells == {("alice", "bob"), ("bob", "alice")}
    assert len(results) == 4
    assert all(r.skipped is False and r.planned_only is False and r.error is None for r in results)


def test_dry_run_never_sends_and_marks_planned_only():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])
    bob = _identity("bob", ["2002"])

    client = _CountingClient(MockHttpClient({}))
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config(dry_run=True))

    results = engine.run([req], [alice, bob])

    assert client.send_count == 0
    assert len(results) == 4
    assert all(r.planned_only is True and r.response is None for r in results)
    assert all(r.prepared is not None for r in results)


def test_off_scope_request_is_skipped_and_not_sent():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])
    bob = _identity("bob", ["2002"])

    client = _CountingClient(MockHttpClient({}))
    engine = ReplayEngine(client, _scope_enforcer(allow_paths=["/other/*"]), NullLimiter(), _run_config())

    results = engine.run([req], [alice, bob])

    assert client.send_count == 0
    assert len(results) == 2  # eine Zeile pro Identitaet, keine Zellen-Explosion
    assert all(r.skipped is True and r.skip_reason for r in results)


def test_enumeration_disabled_produces_no_enumerate_cells():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])

    client = MockHttpClient({})
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config(dry_run=True, enumerate_=False))

    results = engine.run([req], [alice])

    assert not any(r.strategy == "enumerate" for r in results)


def test_enumeration_enabled_produces_neighbors_within_default_range():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])
    bob = _identity("bob", ["2002"])

    client = MockHttpClient({})
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config(dry_run=True, enumerate_=True))

    results = engine.run([req], [alice, bob])

    enumerate_results = [r for r in results if r.strategy == "enumerate"]
    # Default neighbor_range = 5 (EnumerationConfig-Default) -> 10 Nachbarn je Identitaet.
    assert len(enumerate_results) == 2 * 10
    values = {r.object_ref.value for r in enumerate_results}
    assert "1001" not in values
    assert "996" in values
    assert "1006" in values
    assert all(r.owner_identity is None for r in enumerate_results)


def test_max_requests_cap_stops_sends_at_limit():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])
    bob = _identity("bob", ["2002"])

    client = _CountingClient(
        MockHttpClient(
            {
                "GET https://api.example.com/api/v1/orders/1001": _resp(200),
                "GET https://api.example.com/api/v1/orders/2002": _resp(200),
            }
        )
    )
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config(max_requests=2))

    results = engine.run([req], [alice, bob])

    assert client.send_count == 2
    assert any(r.skipped is True and "max_requests" in (r.skip_reason or "") for r in results)


def test_transport_error_does_not_abort_matrix():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])
    bob = _identity("bob", ["2002"])

    client = MockHttpClient(
        {
            "GET https://api.example.com/api/v1/orders/1001": RawResponse(
                status=-1, headers={}, body=b"", elapsed_ms=0.0, error="ConnectError: boom"
            ),
            "GET https://api.example.com/api/v1/orders/2002": _resp(200),
        }
    )
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config())

    results = engine.run([req], [alice, bob])

    assert len(results) == 4
    errored = [r for r in results if r.response is not None and r.response.status == -1]
    ok = [r for r in results if r.response is not None and r.response.status == 200]
    assert len(errored) >= 1
    assert len(ok) >= 1


class _RecordingClient:
    """Zeichnet die tatsaechlich gesendeten URLs auf (statt nur zu zaehlen)."""

    def __init__(self, mock: MockHttpClient) -> None:
        self._mock = mock
        self.sent_urls: list[str] = []

    def send(self, req, timeout: float):
        self.sent_urls.append(req.url)
        return self._mock.send(req, timeout)


def test_swap_value_with_path_traversal_is_skipped_and_not_sent():
    # known_object_ids traegt einen manipulierten Wert mit Pfadinjektion -
    # die daraus resultierende, tatsaechlich zu sendende URL landet
    # ausserhalb des erlaubten Pfads. Die Re-Pruefung auf der finalen URL
    # (Finding 3) muss das erkennen, BEVOR gesendet wird.
    req = _order_request("1001")
    alice = _identity("alice", ["../../admin"])
    bob = _identity("bob", ["2002"])

    client = _RecordingClient(
        MockHttpClient(
            {
                "GET https://api.example.com/api/v1/orders/1001": _resp(200),
                "GET https://api.example.com/api/v1/orders/2002": _resp(200),
            }
        )
    )
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config())

    results = engine.run([req], [alice, bob])

    swap_bob_to_alice = [
        r for r in results if r.strategy == "swap" and r.identity_name == "bob" and r.owner_identity == "alice"
    ]
    assert len(swap_bob_to_alice) == 1
    assert swap_bob_to_alice[0].skipped is True
    assert swap_bob_to_alice[0].response is None
    malicious_prepared_url = swap_bob_to_alice[0].prepared.url
    assert malicious_prepared_url not in client.sent_urls
    assert not any("admin" in url for url in client.sent_urls)


def test_assemble_triads_builds_at_least_one_complete_triad():
    req = _order_request("1001")
    alice = _identity("alice", ["1001"])
    bob = _identity("bob", ["2002"])

    client = MockHttpClient(
        {
            "GET https://api.example.com/api/v1/orders/1001": _resp(200),
            "GET https://api.example.com/api/v1/orders/2002": _resp(200),
        }
    )
    engine = ReplayEngine(client, _scope_enforcer(), NullLimiter(), _run_config())
    results = engine.run([req], [alice, bob])

    triads = assemble_triads(results)

    assert len(triads) == 2  # alice-als-attacker/bob-als-owner UND umgekehrt
    pairs = {(t.attacker_identity, t.owner_identity) for t in triads}
    assert pairs == {("alice", "bob"), ("bob", "alice")}
    for triad in triads:
        assert triad.owner_baseline.status == 200
        assert triad.attacker_resp.status == 200
        assert triad.attacker_own_baseline.status == 200
        assert triad.endpoint == "GET /api/v1/orders/{numeric}"
        assert triad.attacker_prepared is not None
