"""ID-Detektoren: erkennen ID-verdaechtige Werte an einer Location.

Jeder Detektor bekommt einen rohen String-Wert plus `LocationContext` (welche
Location/Selector der Wert hat) und liefert entweder einen `IdMatch` oder
`None`. Die false-positive-Vermeidung fuer numerische Werte (Pagination-
Parameter wie `page`/`limit` etc.) sitzt in `NumericDetector`.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Protocol

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NUMERIC_RE = re.compile(r"^\d+$")

# Bekannte Pagination-/Zaehl-Parameternamen: hier NIE eine Objekt-ID annehmen.
# Vergleich erfolgt case-insensitive auf dem letzten Selector-Segment.
PAGINATION_PARAM_NAMES = {
    "page",
    "limit",
    "offset",
    "per_page",
    "perpage",
    "size",
    "count",
    "page_size",
    "pagesize",
}

# Selector-Namen, die stark auf eine Objekt-ID hindeuten (case-insensitive
# Vergleich auf dem letzten Segment bzw. Pfad-Kontext).
_ID_SUSPECT_RE = re.compile(r"(^id$|_id$|Id$|^ID$)")


@dataclass
class LocationContext:
    """Kontext eines untersuchten Werts: wo im Request er herkommt."""

    location: str  # "path" | "query" | "body" | "header" | "graphql"
    selector: str  # segment-index | param-name | json-pointer | header-name
    param_name: str | None = None  # letztes Namenssegment, falls vorhanden


@dataclass
class IdMatch:
    """Ergebnis eines Detektor-Treffers (ohne location/selector/value)."""

    id_type: str
    confidence: float


class IdDetector(Protocol):
    id_type: str

    def detect(self, value: str, ctx: LocationContext) -> IdMatch | None: ...


def _looks_id_suspect(ctx: LocationContext) -> bool:
    """Heuristik: deutet der Selector-Name auf eine Objekt-ID hin?

    Greift bei Segmentnamen wie `id`, `user_id`, `userId` sowie bei
    Pfadsegmenten, deren Vorgaenger-Segment auf ein Ressourcen-Collection
    hindeutet (z.B. `/users/1001` -> Segment nach "users").
    """
    name = ctx.param_name
    if name and _ID_SUSPECT_RE.search(name):
        return True
    if ctx.location == "path":
        # numerische Pfadsegmente ohne expliziten Namen gelten als
        # ID-verdaechtig, da REST-Pfade IDs meist positionell tragen
        # (z.B. /api/v1/users/1001).
        return True
    return False


class NumericDetector:
    """Erkennt rein numerische IDs, arm an False-Positives.

    Heuristik:
    - Bekannte Pagination-Parameternamen (siehe `PAGINATION_PARAM_NAMES`)
      werden komplett ausgeschlossen (kein Match).
    - Ist der Selector-Name ID-verdaechtig (`id`, `*_id`, `*Id`) oder liegt
      der Wert in einem Pfadsegment, wird mit hoher Confidence (0.85)
      gematcht.
    - Sonst (z.B. ein Query-/Body-Feld ohne id-artigen Namen) wird mit
      niedriger Confidence (0.3) gematcht - der Wert bleibt als moegliche
      Objekt-ID sichtbar, wird aber wegen der geringen Aussagekraft des
      Namens niedrig gewichtet.
    """

    id_type = "numeric"

    _HIGH_CONFIDENCE = 0.85
    _LOW_CONFIDENCE = 0.3

    def detect(self, value: str, ctx: LocationContext) -> IdMatch | None:
        if not _NUMERIC_RE.match(value):
            return None

        param_name = (ctx.param_name or "").lower()
        if param_name in PAGINATION_PARAM_NAMES:
            return None

        if _looks_id_suspect(ctx):
            return IdMatch(id_type=self.id_type, confidence=self._HIGH_CONFIDENCE)

        return IdMatch(id_type=self.id_type, confidence=self._LOW_CONFIDENCE)


class UuidDetector:
    """Erkennt RFC-4122-UUID-Werte (Confidence 1.0, Form ist eindeutig)."""

    id_type = "uuid"

    def detect(self, value: str, ctx: LocationContext) -> IdMatch | None:
        if _UUID_RE.match(value):
            return IdMatch(id_type=self.id_type, confidence=1.0)
        return None


class GraphQlGlobalIdDetector:
    """Erkennt Relay-Global-IDs: base64(`Type:id`).

    Dekodierstrategie (best effort): der Wert wird als Standard-Base64
    dekodiert (mit Padding-Toleranz). Enthaelt das Ergebnis genau ein `:`
    und besteht aus druckbaren, nicht-leeren Teilen, gilt es als Treffer.
    Da rein numerische oder zufaellige Strings ebenfalls gueltiges Base64
    sein koennen, wird die Confidence bewusst < 1 gesetzt (0.6); per Hint
    (`force_id`) laesst sich ein Treffer erzwingen bzw. der Wert stattdessen
    einem anderen id_type zuordnen.
    """

    id_type = "graphql_global"

    _CONFIDENCE = 0.6

    def detect(self, value: str, ctx: LocationContext) -> IdMatch | None:
        decoded = _try_decode_relay_global_id(value)
        if decoded is None:
            return None
        return IdMatch(id_type=self.id_type, confidence=self._CONFIDENCE)


def _try_decode_relay_global_id(value: str) -> str | None:
    if not value or not re.fullmatch(r"[A-Za-z0-9+/_-]+={0,2}", value):
        return None
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded) if ("-" in value or "_" in value) else base64.b64decode(padded)
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    if decoded.count(":") != 1:
        return None
    type_part, id_part = decoded.split(":", 1)
    if not type_part or not id_part or not type_part.isprintable() or not id_part.isprintable():
        return None
    return decoded


# Default-Reihenfolge: spezifischere Formate (uuid, graphql_global) vor dem
# unspezifischen numeric-Detektor, damit z.B. eine UUID nicht faelschlich
# vom numeric-Detektor konsumiert wird (UUID matcht ohnehin nicht auf
# `_NUMERIC_RE`, die Reihenfolge dient primaer der Lesbarkeit/Erweiterung).
DEFAULT_DETECTORS: list[IdDetector] = [
    UuidDetector(),
    GraphQlGlobalIdDetector(),
    NumericDetector(),
]
