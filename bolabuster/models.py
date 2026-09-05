"""Kern-Datenmodelle fuer bolabuster.

`from __future__ import annotations` wird verwendet, damit die
Forward-References zwischen `AuthMaterial.apply` (referenziert
`PreparedRequest`, das erst spaeter in dieser Datei definiert wird) und den
uebrigen Dataclasses ohne Umsortierung sauber aufloesbar sind.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


@dataclass
class GraphQlMeta:
    operation: str | None
    query: str
    variables: dict[str, Any] = field(default_factory=dict)


@dataclass
class ObjectRef:
    location: Literal["path", "query", "body", "header", "graphql"]
    selector: str  # segment-index | param-name | json-pointer
    id_type: str
    value: str
    confidence: float  # 0..1


@dataclass
class PreparedRequest:  # nach Auth+ID-Substitution, sendebereit
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    identity_name: str
    strategy: Literal["self", "swap", "enumerate"]
    mutated_ref: ObjectRef | None = None


class AuthMaterial(Protocol):
    """Typ-diskriminiertes Auth-Material. Konkrete Handler folgen spaeter."""

    type: str

    def apply(self, prepared: PreparedRequest) -> PreparedRequest: ...


@dataclass
class Identity:
    name: str
    auth: AuthMaterial  # type-diskriminiert
    headers: dict[str, str] = field(default_factory=dict)
    known_object_ids: list[str] = field(default_factory=list)


@dataclass
class CanonicalRequest:
    method: str
    url: str  # absolut
    headers: dict[str, str]
    body: bytes | None
    body_media_type: str | None
    source_ref: str  # Herkunft (Datei+Index)
    graphql: GraphQlMeta | None = None
    object_refs: list[ObjectRef] = field(default_factory=list)
    body_parse_failed: bool = False


@dataclass
class RawResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    error: str | None = None  # bei Transportfehler gesetzt, status=-1


@dataclass
class DiffEvidence:
    attacker_excerpt: str
    owner_excerpt: str
    notes: str = ""


@dataclass
class Finding:
    id: str  # stabil hashbasiert (endpoint+param+strat)
    severity: Literal["critical", "high", "medium", "low", "info"]
    verdict: Literal["confirmed", "empty_200"]
    endpoint: str  # method + path template
    parameter: str  # selector der ObjectRef
    id_type: str
    attacker_identity: str
    owner_identity: str
    evidence: DiffEvidence  # gekuerzte Auszuege beider Antworten
    repro_curl: str
    write_operation: bool
    source_ref: str
