"""Replay-Engine: spielt die Anfrage x Identitaet x Strategie-Matrix ab.

Baut fuer jede `CanonicalRequest` und jede `Identity` zunaechst die
`self`-Zellen (Identitaet gegen ihre eigenen Objekt-IDs, als
Ownership-Baseline), danach die `swap`-Zellen (Cross-Play: Identitaet A
sendet mit der von Identitaet B beobachteten/bekannten Objekt-ID) und
optional `enumerate`-Zellen (numerische Nachbar-IDs), bevor sie zur naechsten
Anfrage weitergeht. Jede Zelle laeuft durch den Scope-Enforcer und - im
Nicht-Dry-Run-Fall - durch den RateLimiter, bevor gesendet wird. Ein
unerwarteter Fehler in einer Zelle beendet nicht die gesamte Matrix.

Bewusst KEIN Import aus `bolabuster.classify` - die Engine liefert nur
Rohdaten (`ReplayResult`); `assemble_triads` gruppiert diese zu Triaden fuer
die spaetere Klassifikation, ohne selbst zu klassifizieren.

Defense-in-Depth (Scope-Re-Pruefung): `ScopeEnforcer.check` laeuft zuerst auf
der unmutierten `CanonicalRequest.url`, VOR der ID-Substitution. Da eine
`mutated_ref` (Swap-/Enumerationswert) Pfadstruktur in die tatsaechlich
gesendete URL injizieren kann (z.B. `../../admin` als `known_object_ids`-Wert),
wird der Enforcer nach `prepare_request` und vor `client.send` erneut auf der
finalen, sendebereiten URL aufgerufen - eine Zelle, die dabei durchfaellt,
wird nicht gesendet, sondern als `ReplayResult(skipped=True, ...)` protokolliert.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from bolabuster.config.scope import RunConfig
from bolabuster.engine.prepare import prepare_request
from bolabuster.engine.ratelimit import RateLimiter
from bolabuster.engine.scope import ScopeEnforcer
from bolabuster.http import HttpClient
from bolabuster.models import CanonicalRequest, Identity, ObjectRef, PreparedRequest, RawResponse

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class _ScopeCheckTarget:
    """Leichtgewichtiges Check-Objekt fuer die Re-Pruefung der finalen,
    sendebereiten URL gegen `ScopeEnforcer.check` - Methode + URL genuegen
    fuer Host-/Pfad-/Methode-Pruefung (siehe `ScopeEnforcer.check`, das nur
    `req.url` und `req.method` liest)."""

    method: str
    url: str


@dataclass
class ReplayResult:
    request_source_ref: str
    identity_name: str
    strategy: str  # "self" | "swap" | "enumerate"
    object_ref: ObjectRef | None
    owner_identity: str | None  # bei swap: wem der Ref-Wert gehoert; bei self: = identity_name
    prepared: PreparedRequest | None
    response: RawResponse | None
    endpoint: str  # method + path-template
    write_operation: bool
    skipped: bool = False
    skip_reason: str | None = None
    planned_only: bool = False
    error: str | None = None


@dataclass
class ReplayTriad:
    owner_baseline: RawResponse  # owner ruft eigenes Objekt (self des owners)
    attacker_resp: RawResponse  # attacker ruft owners Objekt (swap)
    attacker_own_baseline: RawResponse  # attacker ruft eigenes Objekt (self des attackers)
    object_ref: ObjectRef
    endpoint: str
    attacker_identity: str
    owner_identity: str
    write_operation: bool
    source_ref: str
    strategy: str
    attacker_prepared: PreparedRequest  # fuer spaetere curl-Erzeugung


@dataclass
class _Cell:
    identity: Identity
    strategy: str
    mutated_ref: ObjectRef | None
    owner_identity: str | None


class ReplayEngine:
    def __init__(self, client: HttpClient, scope: ScopeEnforcer, limiter: RateLimiter, cfg: RunConfig) -> None:
        self._client = client
        self._scope = scope
        self._limiter = limiter
        self._cfg = cfg

    def run(self, requests: list[CanonicalRequest], identities: list[Identity]) -> list[ReplayResult]:
        results: list[ReplayResult] = []
        sent_count = 0
        max_requests = self._cfg.limits.max_requests
        aborted = False

        for req in requests:
            if aborted:
                break

            endpoint = _endpoint(req)
            write_operation = req.method.upper() not in _SAFE_METHODS

            decision = self._scope.check(req)
            if not decision.allowed:
                for identity in identities:
                    results.append(
                        ReplayResult(
                            request_source_ref=req.source_ref,
                            identity_name=identity.name,
                            strategy="self",
                            object_ref=None,
                            owner_identity=identity.name,
                            prepared=None,
                            response=None,
                            endpoint=endpoint,
                            write_operation=write_operation,
                            skipped=True,
                            skip_reason=decision.reason,
                        )
                    )
                continue

            for cell in _plan_cells(req, identities, self._cfg):
                if aborted:
                    break

                try:
                    prepared = prepare_request(req, cell.identity, cell.strategy, cell.mutated_ref)
                except Exception as exc:  # noqa: BLE001 - Einzelzelle darf Matrix nicht abbrechen
                    results.append(
                        ReplayResult(
                            request_source_ref=req.source_ref,
                            identity_name=cell.identity.name,
                            strategy=cell.strategy,
                            object_ref=cell.mutated_ref,
                            owner_identity=cell.owner_identity,
                            prepared=None,
                            response=None,
                            endpoint=endpoint,
                            write_operation=write_operation,
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    )
                    continue

                if self._cfg.dry_run:
                    results.append(
                        ReplayResult(
                            request_source_ref=req.source_ref,
                            identity_name=cell.identity.name,
                            strategy=cell.strategy,
                            object_ref=cell.mutated_ref,
                            owner_identity=cell.owner_identity,
                            prepared=prepared,
                            response=None,
                            endpoint=endpoint,
                            write_operation=write_operation,
                            planned_only=True,
                        )
                    )
                    continue

                if sent_count >= max_requests:
                    results.append(
                        ReplayResult(
                            request_source_ref=req.source_ref,
                            identity_name=cell.identity.name,
                            strategy=cell.strategy,
                            object_ref=cell.mutated_ref,
                            owner_identity=cell.owner_identity,
                            prepared=prepared,
                            response=None,
                            endpoint=endpoint,
                            write_operation=write_operation,
                            skipped=True,
                            skip_reason=f"max_requests-Limit ({max_requests}) erreicht; Matrix abgebrochen",
                        )
                    )
                    aborted = True
                    break

                # Re-Pruefung auf der finalen, sendebereiten URL (Defense-in-
                # Depth gegen Traversal ueber mutierte ID-Werte, s. Moduldoc).
                sent_decision = self._scope.check(_ScopeCheckTarget(method=prepared.method, url=prepared.url))
                if not sent_decision.allowed:
                    results.append(
                        ReplayResult(
                            request_source_ref=req.source_ref,
                            identity_name=cell.identity.name,
                            strategy=cell.strategy,
                            object_ref=cell.mutated_ref,
                            owner_identity=cell.owner_identity,
                            prepared=prepared,
                            response=None,
                            endpoint=endpoint,
                            write_operation=write_operation,
                            skipped=True,
                            skip_reason=f"gesendete URL out-of-scope: {sent_decision.reason}",
                        )
                    )
                    continue

                self._limiter.acquire()
                try:
                    response = self._client.send(prepared, self._cfg.limits.timeout_sec)
                    sent_count += 1
                except Exception as exc:  # noqa: BLE001 - Einzelzelle darf Matrix nicht abbrechen
                    sent_count += 1
                    results.append(
                        ReplayResult(
                            request_source_ref=req.source_ref,
                            identity_name=cell.identity.name,
                            strategy=cell.strategy,
                            object_ref=cell.mutated_ref,
                            owner_identity=cell.owner_identity,
                            prepared=prepared,
                            response=None,
                            endpoint=endpoint,
                            write_operation=write_operation,
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    )
                    continue

                results.append(
                    ReplayResult(
                        request_source_ref=req.source_ref,
                        identity_name=cell.identity.name,
                        strategy=cell.strategy,
                        object_ref=cell.mutated_ref,
                        owner_identity=cell.owner_identity,
                        prepared=prepared,
                        response=response,
                        endpoint=endpoint,
                        write_operation=write_operation,
                    )
                )

        return results


def _plan_cells(req: CanonicalRequest, identities: list[Identity], cfg: RunConfig) -> list[_Cell]:
    """Baut die Zell-Liste (self, dann swap, dann ggf. enumerate) fuer `req`.

    Ref-Wert-Quelle: `Identity.known_object_ids` wird POSITIONELL zu
    `req.object_refs` gemappt (Index i im Ref-Array -> `known_object_ids[i]`).
    Ist die Liste einer Identitaet an dieser Position leer/zu kurz, faellt
    `self` auf den unveraenderten `ref.value` zurueck (der Original-Request
    gilt dann als deren Baseline), und `swap` wird fuer diesen Ref bei dieser
    Identitaet als Quelle uebersprungen (keine bekannte Fremd-ID vorhanden).
    """
    refs = req.object_refs
    cells: list[_Cell] = []

    for identity in identities:
        if not refs:
            cells.append(_Cell(identity=identity, strategy="self", mutated_ref=None, owner_identity=identity.name))
            continue
        for index, ref in enumerate(refs):
            own_value = _own_value(identity, index)
            mutated = replace(ref, value=own_value) if own_value is not None else ref
            cells.append(_Cell(identity=identity, strategy="self", mutated_ref=mutated, owner_identity=identity.name))

    if refs:
        for attacker in identities:
            for owner in identities:
                if owner is attacker:
                    continue
                for index, ref in enumerate(refs):
                    owner_value = _own_value(owner, index)
                    if owner_value is None:
                        continue
                    mutated = replace(ref, value=owner_value)
                    cells.append(
                        _Cell(identity=attacker, strategy="swap", mutated_ref=mutated, owner_identity=owner.name)
                    )

    if cfg.enumerate and refs:
        for identity in identities:
            for ref in refs:
                if not _is_numeric(ref.value):
                    continue
                base = int(ref.value)
                for offset in range(-cfg.neighbor_range, cfg.neighbor_range + 1):
                    if offset == 0:
                        continue
                    neighbor = base + offset
                    if neighbor < 0:
                        continue
                    mutated = replace(ref, value=str(neighbor))
                    cells.append(
                        _Cell(identity=identity, strategy="enumerate", mutated_ref=mutated, owner_identity=None)
                    )

    return cells


def _own_value(identity: Identity, index: int) -> str | None:
    if index < len(identity.known_object_ids):
        return identity.known_object_ids[index]
    return None


def _is_numeric(value: str) -> bool:
    stripped = value.lstrip("-")
    return stripped.isdigit()


def _endpoint(req: CanonicalRequest) -> str:
    """Leitet ein Endpoint-Label (`METHOD path-template`) aus `req` ab.

    Pfadsegmente, die eine erkannte `ObjectRef` mit `location="path"` tragen,
    werden durch `{id_type}` ersetzt (Quelle: `req.object_refs`, wie von
    `detect.extract_object_refs` befuellt). Segmente ohne erkannte Ref bleiben
    unveraendert. Ohne erkannte Path-Refs entspricht das Label dem
    unveraenderten Pfad.
    """
    path_id_types = {ref.selector: ref.id_type for ref in req.object_refs if ref.location == "path"}
    parsed = urlsplit(req.url)
    segments = parsed.path.split("/")

    templated: list[str] = []
    non_empty_seen = -1
    for segment in segments:
        if segment == "":
            templated.append(segment)
            continue
        non_empty_seen += 1
        id_type = path_id_types.get(str(non_empty_seen))
        templated.append(f"{{{id_type}}}" if id_type else segment)

    templated_path = "/".join(templated) or "/"
    return f"{req.method.upper()} {templated_path}"


def assemble_triads(results: list[ReplayResult]) -> list[ReplayTriad]:
    """Gruppiert `self`- und `swap`-Ergebnisse zu vollstaendigen Triaden.

    Gruppierungsschluessel: `(endpoint, object_ref.selector, identity_name)`
    fuer die `self`-Ergebnisse (Selector statt Ref-Wert, da der Wert je
    Identitaet unterschiedlich ist, die Location/der Selector aber stabil
    bleibt). Jedes `swap`-Ergebnis sucht sich darueber seine beiden fehlenden
    Ecken: die `self`-Baseline des Owners (`(endpoint, selector, owner_identity)`)
    und die `self`-Baseline des Angreifers (`(endpoint, selector,
    identity_name)`). Fehlt eine Ecke (kein `self`-Treffer, keine Response,
    kein `prepared` in der swap-Zelle - z.B. weil geskippt/dry-run/Fehler),
    wird diese Triade ausgelassen statt mit `None` aufgefuellt.
    """
    self_by_key: dict[tuple[str, str, str], ReplayResult] = {}
    for r in results:
        if r.strategy != "self" or r.object_ref is None or r.response is None:
            continue
        key = (r.endpoint, r.object_ref.selector, r.identity_name)
        self_by_key.setdefault(key, r)

    triads: list[ReplayTriad] = []
    for r in results:
        if r.strategy != "swap" or r.object_ref is None or r.response is None or r.prepared is None:
            continue
        if r.owner_identity is None:
            continue

        owner_baseline = self_by_key.get((r.endpoint, r.object_ref.selector, r.owner_identity))
        attacker_baseline = self_by_key.get((r.endpoint, r.object_ref.selector, r.identity_name))
        if owner_baseline is None or attacker_baseline is None:
            continue

        triads.append(
            ReplayTriad(
                owner_baseline=owner_baseline.response,
                attacker_resp=r.response,
                attacker_own_baseline=attacker_baseline.response,
                object_ref=r.object_ref,
                endpoint=r.endpoint,
                attacker_identity=r.identity_name,
                owner_identity=r.owner_identity,
                write_operation=r.write_operation,
                source_ref=r.request_source_ref,
                strategy=r.strategy,
                attacker_prepared=r.prepared,
            )
        )

    return triads


__all__ = ["ReplayEngine", "ReplayResult", "ReplayTriad", "assemble_triads"]
