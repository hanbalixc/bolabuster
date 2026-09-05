"""Objekt-Referenz-Erkennung: durchsucht einen CanonicalRequest nach IDs.

`extract_object_refs` durchlaeuft Pfad, Query, JSON-Body (rekursiver Walk mit
JSON-Pointer-Erzeugung nach RFC 6901), eine Header-Whitelist sowie GraphQL-
Variablen und liefert eine Liste von `ObjectRef`. Ungueltiges JSON im Body
fuehrt NICHT zu einem Wurf: `req.body_parse_failed` wird gesetzt, der Body
wird opaque behandelt (keine Body-Refs) und eine Warnung landet in
`DetectionHints.warnings`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from bolabuster.detect.detectors import IdDetector, LocationContext
from bolabuster.models import CanonicalRequest, ObjectRef

# Header, die IDs tragen koennen und deshalb geprueft werden. Bewusst KEINE
# Auth-/Session-Header (Authorization, Cookie, ...), um deren Werte nicht als
# Objekt-IDs misszuverstehen bzw. Secrets nicht unnoetig zu verarbeiten.
HEADER_WHITELIST = {
    "x-request-id",
    "x-correlation-id",
    "x-account-id",
    "x-tenant-id",
    "x-user-id",
    "x-resource-id",
    "x-object-id",
}

_FORCE_ID_CONFIDENCE = 1.0


@dataclass
class DetectionHints:
    """Steuert die Erkennung ueber Config-Hints je Selector.

    `force_id`: selector -> id_type. Erzwingt an diesem Selector eine
      `ObjectRef` mit hoher Confidence, unabhaengig davon, ob ein Detektor
      dort einen Treffer gefunden haette (auch wenn der Wert dort fehlt/kein
      Match ist, wird die Ref nur erzeugt, wenn der Selector tatsaechlich
      einen Wert im Request hat).
    `ignore`: Menge von Selectors, an denen KEIN Treffer erzeugt wird, auch
      wenn ein Detektor dort matcht.
    `warnings`: wird von `extract_object_refs` befuellt (z.B. bei kaputtem
      JSON-Body) und dient als durchgereichter Sammelpunkt fuer Aufrufer, die
      keine Exceptions abfangen wollen. Wird der Aufrufer keine eigene
      Instanz übergeben, wird eine neue mit leerer `warnings`-Liste erzeugt.
    """

    force_id: dict[str, str] = field(default_factory=dict)
    ignore: set[str] = field(default_factory=set)
    warnings: list[str] = field(default_factory=list)


def extract_object_refs(
    req: CanonicalRequest,
    detectors: list[IdDetector],
    hints: DetectionHints,
) -> list[ObjectRef]:
    """Erkennt Objekt-Referenzen in `req` und gibt sie als Liste zurueck.

    Wirft nie wegen "keine ID gefunden" (leere Liste ist ein gueltiges
    Ergebnis). Setzt bei kaputtem JSON-Body `req.body_parse_failed = True`
    und haengt eine Warnung an `hints.warnings` an, statt zu werfen.
    """
    refs: list[ObjectRef] = []

    refs.extend(_extract_path_refs(req.url, detectors, hints))
    refs.extend(_extract_query_refs(req.url, detectors, hints))
    refs.extend(_extract_header_refs(req.headers, detectors, hints))
    refs.extend(_extract_body_refs(req, detectors, hints))
    refs.extend(_extract_graphql_refs(req, detectors, hints))

    _apply_pending_force_ids(refs, hints)
    return refs


def _selector_allowed(selector: str, hints: DetectionHints) -> bool:
    return selector not in hints.ignore


def _match_value(
    value: str,
    ctx: LocationContext,
    detectors: list[IdDetector],
    hints: DetectionHints,
) -> tuple[str, float] | None:
    """Ermittelt id_type+confidence fuer `value`, Hints beruecksichtigend."""
    if not _selector_allowed(ctx.selector, hints):
        return None

    forced_id_type = hints.force_id.get(ctx.selector)
    if forced_id_type is not None:
        return forced_id_type, _FORCE_ID_CONFIDENCE

    for detector in detectors:
        match = detector.detect(value, ctx)
        if match is not None:
            return match.id_type, match.confidence
    return None


def _extract_path_refs(
    url: str, detectors: list[IdDetector], hints: DetectionHints
) -> list[ObjectRef]:
    refs: list[ObjectRef] = []
    path = urlsplit(url).path
    segments = [seg for seg in path.split("/") if seg != ""]
    for index, segment in enumerate(segments):
        selector = str(index)
        ctx = LocationContext(location="path", selector=selector, param_name=None)
        result = _match_value(segment, ctx, detectors, hints)
        if result is None:
            continue
        id_type, confidence = result
        refs.append(
            ObjectRef(location="path", selector=selector, id_type=id_type, value=segment, confidence=confidence)
        )
    return refs


def _extract_query_refs(
    url: str, detectors: list[IdDetector], hints: DetectionHints
) -> list[ObjectRef]:
    refs: list[ObjectRef] = []
    query = urlsplit(url).query
    for name, value in parse_qsl(query, keep_blank_values=True):
        ctx = LocationContext(location="query", selector=name, param_name=name)
        result = _match_value(value, ctx, detectors, hints)
        if result is None:
            continue
        id_type, confidence = result
        refs.append(ObjectRef(location="query", selector=name, id_type=id_type, value=value, confidence=confidence))
    return refs


def _extract_header_refs(
    headers: dict[str, str], detectors: list[IdDetector], hints: DetectionHints
) -> list[ObjectRef]:
    refs: list[ObjectRef] = []
    for name, value in headers.items():
        if name.lower() not in HEADER_WHITELIST:
            continue
        ctx = LocationContext(location="header", selector=name, param_name=name)
        result = _match_value(value, ctx, detectors, hints)
        if result is None:
            continue
        id_type, confidence = result
        refs.append(ObjectRef(location="header", selector=name, id_type=id_type, value=value, confidence=confidence))
    return refs


def _extract_body_refs(
    req: CanonicalRequest, detectors: list[IdDetector], hints: DetectionHints
) -> list[ObjectRef]:
    if not req.body:
        return []

    try:
        parsed = json.loads(req.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        req.body_parse_failed = True
        hints.warnings.append(f"{req.source_ref}: Body konnte nicht als JSON geparst werden ({exc}); Body ignoriert")
        return []

    refs: list[ObjectRef] = []
    for pointer, value in _walk_json(parsed, ""):
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            continue
        param_name = pointer.rsplit("/", 1)[-1] if pointer else None
        ctx = LocationContext(location="body", selector=pointer, param_name=param_name)
        str_value = str(value)
        result = _match_value(str_value, ctx, detectors, hints)
        if result is None:
            continue
        id_type, confidence = result
        refs.append(
            ObjectRef(location="body", selector=pointer, id_type=id_type, value=str_value, confidence=confidence)
        )
    return refs


def _walk_json(node: Any, pointer: str) -> list[tuple[str, Any]]:
    """Rekursiver JSON-Walk, erzeugt (JSON-Pointer, Blattwert)-Paare.

    JSON-Pointer nach RFC 6901: `/` trennt Segmente, `~` -> `~0`, `/` -> `~1`
    innerhalb eines Schluessels (Escaping analog zum Standard).
    """
    results: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            results.extend(_walk_json(value, f"{pointer}/{escaped}"))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            results.extend(_walk_json(value, f"{pointer}/{index}"))
    else:
        results.append((pointer, node))
    return results


def _extract_graphql_refs(
    req: CanonicalRequest, detectors: list[IdDetector], hints: DetectionHints
) -> list[ObjectRef]:
    if req.graphql is None:
        return []

    refs: list[ObjectRef] = []
    for pointer, value in _walk_json(req.graphql.variables, ""):
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            continue
        selector = pointer.lstrip("/") or pointer
        param_name = selector.rsplit("/", 1)[-1] if selector else None
        ctx = LocationContext(location="graphql", selector=selector, param_name=param_name)
        str_value = str(value)
        result = _match_value(str_value, ctx, detectors, hints)
        if result is None:
            continue
        id_type, confidence = result
        refs.append(
            ObjectRef(location="graphql", selector=selector, id_type=id_type, value=str_value, confidence=confidence)
        )
    return refs


def _apply_pending_force_ids(refs: list[ObjectRef], hints: DetectionHints) -> None:
    """Warnt (still, ohne Wurf) ueber `force_id`-Selectors ohne Wert.

    `force_id` erzwingt an vorhandenen Selectors einen id_type (siehe
    `_match_value`). Ein Selector, den kein Extraktionsschritt ueberhaupt
    besucht hat (z.B. Tippfehler in der Config), erzeugt keine Ref - das wird
    hier als Warnung dokumentiert statt stillschweigend verworfen.
    """
    seen_selectors = {ref.selector for ref in refs}
    for selector in hints.force_id:
        if selector not in seen_selectors and selector not in hints.ignore:
            hints.warnings.append(f"force_id-Selector {selector!r} wurde in keiner Location gefunden")
