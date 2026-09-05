"""Request-Vorbereitung: baut aus einem `CanonicalRequest` einen sendebereiten
`PreparedRequest` fuer eine Identitaet/Strategie-Kombination.

`prepare_request` ist eine reine Funktion (kein Netzwerk-IO, keine Seiteneffekte
ausser dem Kopieren/Mutieren des uebergebenen `CanonicalRequest`-Inhalts in ein
neues `PreparedRequest`), damit sie unabhaengig von der Replay-Engine getestet
werden kann.

Substitution eines `mutated_ref` (ID-Swap/Enumeration) erfolgt an der Location,
die die `ObjectRef` traegt:
- `path`: `selector` ist der Index (als String) des nicht-leeren Pfadsegments
  (0-basiert), analog zur Zaehlweise in `detect/extract.py::_extract_path_refs`.
- `query`: `selector` ist der Parametername; ersetzt wird das erste Vorkommen
  mit diesem Namen (Reihenfolge/uebrige Parameter bleiben erhalten).
- `body`: `selector` ist ein RFC-6901-JSON-Pointer in den JSON-Body (analog zu
  `detect/extract.py::_walk_json`); der Body wird geparst, am Pointer ersetzt
  und neu serialisiert. Der urspruengliche JSON-Typ des Blattwerts (int/float)
  wird nach Moeglichkeit beibehalten, damit z.B. numerische IDs numerisch
  bleiben.
- `header`: `selector` ist der Header-Name; der Header wird direkt gesetzt.
- `graphql`: `selector` ist (wie in `_extract_graphql_refs`) ein von seinem
  fuehrenden `/` befreiter JSON-Pointer relativ zum `variables`-Objekt im
  JSON-Body (Annahme: der Body traegt den ueblichen GraphQL-POST-Envelope
  `{"query": ..., "variables": {...}}`). Fehlt ein `variables`-Objekt im Body,
  wird eine `ValueError` geworfen - der Aufrufer (ReplayEngine) faengt das pro
  Zelle ab.

Reihenfolge Header/Auth: zuerst werden ggf. vorhandene `mutated_ref`-Header
sowie die statischen `identity.headers` gesetzt, danach erst
`identity.auth.apply(...)` aufgerufen. So kann Auth (z.B. Authorization-Header)
nicht versehentlich durch generische `identity.headers` ueberschrieben werden.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bolabuster.models import CanonicalRequest, Identity, ObjectRef, PreparedRequest


def prepare_request(
    req: CanonicalRequest,
    identity: Identity,
    strategy: str,
    mutated_ref: ObjectRef | None = None,
) -> PreparedRequest:
    """Baut den sendebereiten `PreparedRequest` fuer `identity`/`strategy`.

    Netzfrei, wirft bei ungueltiger Substitution (z.B. Pointer nicht im Body
    vorhanden, Body fehlt) statt still zu verwerfen - das ist beabsichtigt,
    damit der Aufrufer (ReplayEngine) den Fehler pro Zelle protokollieren kann.
    """
    method = req.method
    url = req.url
    body = req.body
    headers = dict(req.headers)

    if mutated_ref is not None:
        if mutated_ref.location == "path":
            url = _substitute_path_segment(url, mutated_ref.selector, mutated_ref.value)
        elif mutated_ref.location == "query":
            url = _substitute_query_param(url, mutated_ref.selector, mutated_ref.value)
        elif mutated_ref.location == "body":
            body = _substitute_body_pointer(body, mutated_ref.selector, mutated_ref.value)
        elif mutated_ref.location == "graphql":
            body = _substitute_graphql_variable(body, mutated_ref.selector, mutated_ref.value)
        elif mutated_ref.location == "header":
            headers[mutated_ref.selector] = mutated_ref.value
        else:
            raise ValueError(f"unbekannte ObjectRef.location {mutated_ref.location!r}")

    headers.update(identity.headers)

    prepared = PreparedRequest(
        method=method,
        url=url,
        headers=headers,
        body=body,
        identity_name=identity.name,
        strategy=strategy,
        mutated_ref=mutated_ref,
    )
    return identity.auth.apply(prepared)


def _substitute_path_segment(url: str, selector: str, new_value: str) -> str:
    target_index = int(selector)
    parts = urlsplit(url)
    segments = parts.path.split("/")

    non_empty_seen = -1
    for i, segment in enumerate(segments):
        if segment == "":
            continue
        non_empty_seen += 1
        if non_empty_seen == target_index:
            segments[i] = new_value
            break
    else:
        raise IndexError(f"Pfadsegment-Index {target_index} nicht in URL {url!r} gefunden")

    new_path = "/".join(segments)
    return urlunsplit(parts._replace(path=new_path))


def _substitute_query_param(url: str, selector: str, new_value: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)

    replaced = False
    new_pairs: list[tuple[str, str]] = []
    for name, value in pairs:
        if not replaced and name == selector:
            new_pairs.append((name, new_value))
            replaced = True
        else:
            new_pairs.append((name, value))
    if not replaced:
        raise KeyError(f"Query-Parameter {selector!r} nicht in URL {url!r} gefunden")

    new_query = urlencode(new_pairs)
    return urlunsplit(parts._replace(query=new_query))


def _substitute_body_pointer(body: bytes | None, selector: str, new_value: str) -> bytes:
    if body is None:
        raise ValueError("mutated_ref.location='body' erfordert einen vorhandenen Body")
    document = json.loads(body)
    _json_pointer_set(document, selector, new_value)
    return json.dumps(document).encode("utf-8")


def _substitute_graphql_variable(body: bytes | None, selector: str, new_value: str) -> bytes:
    if body is None:
        raise ValueError("mutated_ref.location='graphql' erfordert einen vorhandenen Body")
    document = json.loads(body)
    variables = document.get("variables")
    if not isinstance(variables, dict):
        raise ValueError("Body enthaelt kein 'variables'-Objekt fuer GraphQL-Substitution")
    pointer = selector if selector.startswith("/") else f"/{selector}"
    _json_pointer_set(variables, pointer, new_value)
    return json.dumps(document).encode("utf-8")


def _json_pointer_set(document: Any, pointer: str, new_value: str) -> None:
    """Setzt den Blattwert an `pointer` (RFC 6901) in-place auf `new_value`.

    Der urspruengliche JSON-Typ (int/float) des Blattwerts wird beibehalten,
    sofern `new_value` sich entsprechend parsen laesst - sonst bleibt es str.
    """
    if not pointer:
        raise ValueError("leerer JSON-Pointer wird nicht unterstuetzt")

    tokens = [_unescape_pointer_token(t) for t in pointer.split("/")[1:]]
    cursor: Any = document
    for token in tokens[:-1]:
        cursor = cursor[int(token)] if isinstance(cursor, list) else cursor[token]

    last = tokens[-1]
    if isinstance(cursor, list):
        index = int(last)
        cursor[index] = _coerce_value(new_value, cursor[index])
    else:
        cursor[last] = _coerce_value(new_value, cursor.get(last))


def _unescape_pointer_token(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _coerce_value(new_value: str, original: Any) -> Any:
    if isinstance(original, bool):
        return new_value
    if isinstance(original, int):
        try:
            return int(new_value)
        except ValueError:
            return new_value
    if isinstance(original, float):
        try:
            return float(new_value)
        except ValueError:
            return new_value
    return new_value


__all__ = ["prepare_request"]
