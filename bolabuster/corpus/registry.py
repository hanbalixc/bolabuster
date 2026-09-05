"""Parser-Registry: Auto-Detect und expliziter Format-Lookup.

Neue Parser (z.B. OpenAPI, GraphQL in Schritt 5) werden per `register()`
hinzugefuegt oder direkt in `BUILTIN_PARSERS` ergaenzt.
"""

from __future__ import annotations

from pathlib import Path

from bolabuster.corpus.base import CorpusParser
from bolabuster.corpus.graphql import GraphQlParser
from bolabuster.corpus.har import HarParser
from bolabuster.corpus.openapi import OpenApiParser
from bolabuster.corpus.raw_http import RawHttpParser
from bolabuster.errors import AmbiguousCorpusError, UnsupportedCorpusError

BUILTIN_PARSERS: list[CorpusParser] = [
    HarParser(),
    RawHttpParser(),
    OpenApiParser(),
    GraphQlParser(),
]


def register(parser: CorpusParser) -> None:
    """Registriert einen zusaetzlichen Parser (z.B. fuer OpenAPI/GraphQL)."""
    BUILTIN_PARSERS.append(parser)


def get_parser(fmt: str | None, source: Path) -> CorpusParser:
    """Ermittelt den passenden Parser fuer `source`.

    `fmt=None` -> Auto-Detect ueber `can_parse` aller registrierten Parser.
    Mehrdeutiger Treffer -> `AmbiguousCorpusError`. Kein Treffer bzw.
    unbekannter `fmt` -> `UnsupportedCorpusError`.
    """
    if fmt is not None:
        for parser in BUILTIN_PARSERS:
            if parser.name == fmt:
                if not parser.can_parse(source):
                    raise UnsupportedCorpusError(
                        f"Parser {fmt!r} kann Quelle {str(source)!r} nicht verarbeiten"
                    )
                return parser
        known = ", ".join(sorted(p.name for p in BUILTIN_PARSERS))
        raise UnsupportedCorpusError(f"unbekanntes Corpus-Format {fmt!r}; bekannt: {known}")

    matches = [p for p in BUILTIN_PARSERS if p.can_parse(source)]
    if not matches:
        raise UnsupportedCorpusError(f"kein Parser erkennt Quelle {str(source)!r}")
    if len(matches) > 1:
        names = ", ".join(sorted(p.name for p in matches))
        raise AmbiguousCorpusError(f"mehrere Parser erkennen Quelle {str(source)!r}: {names}")
    return matches[0]
