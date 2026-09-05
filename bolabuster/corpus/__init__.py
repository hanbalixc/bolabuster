"""Corpus-Parser-Schicht: liest Anfragen-Korpora und normalisiert sie auf
`CanonicalRequest`.

MVP (Schritt 4): `HarParser`, `RawHttpParser`. Schritt 5 ergaenzt
`OpenApiParser` und `GraphQlParser` per `register()`.
"""

from __future__ import annotations

from bolabuster.corpus.base import CorpusParser, ParserOptions
from bolabuster.corpus.graphql import GraphQlParser
from bolabuster.corpus.har import HarParser
from bolabuster.corpus.openapi import OpenApiParser
from bolabuster.corpus.raw_http import RawHttpParser
from bolabuster.corpus.registry import BUILTIN_PARSERS, get_parser, register

__all__ = [
    "CorpusParser",
    "ParserOptions",
    "HarParser",
    "RawHttpParser",
    "OpenApiParser",
    "GraphQlParser",
    "BUILTIN_PARSERS",
    "get_parser",
    "register",
]
