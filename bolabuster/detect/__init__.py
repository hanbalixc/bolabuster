"""Detect-Layer: erkennt Objekt-Referenzen (IDs) in einem CanonicalRequest."""

from bolabuster.detect.detectors import (
    DEFAULT_DETECTORS,
    PAGINATION_PARAM_NAMES,
    GraphQlGlobalIdDetector,
    IdDetector,
    IdMatch,
    LocationContext,
    NumericDetector,
    UuidDetector,
)
from bolabuster.detect.extract import HEADER_WHITELIST, DetectionHints, extract_object_refs

__all__ = [
    "DEFAULT_DETECTORS",
    "PAGINATION_PARAM_NAMES",
    "GraphQlGlobalIdDetector",
    "IdDetector",
    "IdMatch",
    "LocationContext",
    "NumericDetector",
    "UuidDetector",
    "HEADER_WHITELIST",
    "DetectionHints",
    "extract_object_refs",
]
