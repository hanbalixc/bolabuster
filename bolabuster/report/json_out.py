"""Schema-versioniertes, deterministisch sortiertes JSON fuer Findings."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from bolabuster.errors import ReportWriteError
from bolabuster.models import Finding

SCHEMA_VERSION = "1.0"

# Severity-Rang: niedrigere Zahl = wichtiger, bestimmt Sortierreihenfolge.
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass
class RunMeta:
    """Metadaten eines Scan-Laufs. Wird von der CLI (Schritt 11) befuellt."""

    version: str
    target: str
    started_at: str  # ISO-Zeitstempel
    tool: str = "bolabuster"
    engagement_ref: str | None = None
    finished_at: str | None = None
    counts: dict[str, int] = field(default_factory=dict)


def _severity_rank(severity: str) -> int:
    # Unbekannte Severities landen ans Ende, statt den Sort zu brechen.
    return _SEVERITY_RANK.get(severity, len(_SEVERITY_RANK))


def _sort_key(finding: Finding) -> tuple[int, str, str, str]:
    return (
        _severity_rank(finding.severity),
        finding.endpoint,
        finding.parameter,
        finding.id,
    )


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "severity": finding.severity,
        "verdict": finding.verdict,
        "endpoint": finding.endpoint,
        "parameter": finding.parameter,
        "id_type": finding.id_type,
        "attacker_identity": finding.attacker_identity,
        "owner_identity": finding.owner_identity,
        "evidence": {
            "attacker_excerpt": finding.evidence.attacker_excerpt,
            "owner_excerpt": finding.evidence.owner_excerpt,
            "notes": finding.evidence.notes,
        },
        "repro_curl": finding.repro_curl,
        "write_operation": finding.write_operation,
        "source_ref": finding.source_ref,
    }


def _meta_to_dict(meta: RunMeta) -> dict:
    return {
        "tool": meta.tool,
        "version": meta.version,
        "engagement_ref": meta.engagement_ref,
        "target": meta.target,
        "started_at": meta.started_at,
        "finished_at": meta.finished_at,
        "counts": meta.counts,
    }


def write_json(findings: list[Finding], meta: RunMeta, out: Path) -> None:
    """Schreibt Findings + Meta als schema-versioniertes JSON nach `out`.

    Findings werden stabil nach (Severity-Rang, endpoint, parameter, id)
    sortiert; Objekt-Keys sind ueber `sort_keys=True` in stabiler
    Reihenfolge, sodass identische Findings byte-identisches JSON ergeben.
    """
    sorted_findings = sorted(findings, key=_sort_key)
    document = {
        "schema_version": SCHEMA_VERSION,
        "meta": _meta_to_dict(meta),
        "findings": [_finding_to_dict(f) for f in sorted_findings],
    }
    text = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False)
    try:
        out.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ReportWriteError(f"failed to write report to {out}: {exc}") from exc
