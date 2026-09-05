"""Protocol und Optionen fuer Corpus-Parser.

Neue Parser (z.B. OpenAPI, GraphQL in Schritt 5) implementieren das
`CorpusParser`-Protocol und werden in `registry.BUILTIN_PARSERS`
registriert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from bolabuster.models import CanonicalRequest


@dataclass
class ParserOptions:
    """Optionen, die allen Parsern gemeinsam durchgereicht werden.

    `warnings` sammelt Hinweise (z.B. unbekannter mimeType, mehrdeutige
    URL) - Parser haengen dort an, statt Sonderfaelle still zu ignorieren.
    """

    warnings: list[str] = field(default_factory=list)
    default_scheme: str = "https"


class CorpusParser(Protocol):
    name: str  # z.B. "har", "raw_http"

    def can_parse(self, source: Path) -> bool: ...

    def parse(self, source: Path, opts: ParserOptions) -> list[CanonicalRequest]: ...
