"""Finding-Erzeugung aus einer Classification: Severity, ID, Evidence.

`CellContext` ist die Entkopplungs-Naht zur Engine/Orchestrierung (Schritt
8/11): `build_finding` braucht nur diese Felder und importiert nichts aus
`bolabuster.engine`. Die spaetere Engine fuellt `CellContext` (inkl. des
bereits fertig gebauten `repro_curl`-Strings) und ruft `build_finding` mit
dem Ergebnis von `classify_cell` auf.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from bolabuster.classify.classify import Classification
from bolabuster.models import Finding


@dataclass
class CellContext:
    """Kontext einer Replay-Zelle, wie ihn `build_finding` benoetigt."""

    endpoint: str  # method + path template
    parameter: str  # selector der ObjectRef
    id_type: str
    attacker_identity: str
    owner_identity: str
    write_operation: bool
    source_ref: str
    strategy: str  # "self" | "swap" | "enumerate"
    repro_curl: str


def _finding_id(cell: CellContext) -> str:
    """Deterministische, hashbasierte Finding-ID aus endpoint+parameter+strategy.

    Gleicher Input -> gleiche ID (sha1-Hexdigest, auf 16 Zeichen gekuerzt).
    """
    raw = f"{cell.endpoint}|{cell.parameter}|{cell.strategy}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def _severity(cls: Classification, cell: CellContext) -> str | None:
    """Severity-Logik gemaess Spezifikation Abschnitt 3.5.

    - confirmed + structural_only (Risiko-1) -> medium (unsicher, manuelle
      Verifikation noetig, siehe `Classification.structural_only`)
    - confirmed + Write/Delete -> critical
    - confirmed + Read -> high
    - empty_200 -> low
    - alles andere -> None (kein Finding, siehe `build_finding`)
    """
    if cls.verdict == "confirmed":
        if cls.structural_only:
            return "medium"
        return "critical" if cell.write_operation else "high"
    if cls.verdict == "empty_200":
        return "low"
    return None


def build_finding(cell: CellContext, cls: Classification) -> Finding | None:
    """Erzeugt ein `Finding` aus Cell-Kontext + Classification.

    Liefert `None`, wenn das Verdikt weder `confirmed` noch `empty_200`
    ist (d.h. bei `denied`, `error`, `irrelevant`).
    """
    severity = _severity(cls, cell)
    if severity is None:
        return None

    return Finding(
        id=_finding_id(cell),
        severity=severity,  # type: ignore[arg-type]
        verdict=cls.verdict,  # type: ignore[arg-type]
        endpoint=cell.endpoint,
        parameter=cell.parameter,
        id_type=cell.id_type,
        attacker_identity=cell.attacker_identity,
        owner_identity=cell.owner_identity,
        evidence=cls.evidence,
        repro_curl=cell.repro_curl,
        write_operation=cell.write_operation,
        source_ref=cell.source_ref,
    )
