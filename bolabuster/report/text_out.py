"""Menschenlesbarer Text-Report (terminalfreundlich, ohne Farbcodes)."""

from __future__ import annotations

from bolabuster.models import Finding

from .json_out import RunMeta, _sort_key

_SEVERITY_LABELS = ["critical", "high", "medium", "low", "info"]


def _render_header(meta: RunMeta) -> list[str]:
    lines = [
        "bolabuster report",
        "=" * 17,
        f"target:         {meta.target}",
        f"engagement_ref: {meta.engagement_ref or '-'}",
        f"started_at:     {meta.started_at}",
        f"finished_at:    {meta.finished_at or '-'}",
        f"tool/version:   {meta.tool} {meta.version}",
        "",
        "findings by severity:",
    ]
    for label in _SEVERITY_LABELS:
        lines.append(f"  {label:<9}: {meta.counts.get(label, 0)}")
    # Unbekannte Severities (nicht in der Standard-Liste) trotzdem anzeigen.
    for label, count in meta.counts.items():
        if label not in _SEVERITY_LABELS:
            lines.append(f"  {label:<9}: {count}")
    lines.append("")
    return lines


def _render_finding(finding: Finding, index: int) -> list[str]:
    lines = [
        "-" * 60,
        f"[{index}] {finding.severity.upper()} - {finding.verdict}",
        f"endpoint:          {finding.endpoint}",
        f"parameter:         {finding.parameter} ({finding.id_type})",
        f"attacker identity: {finding.attacker_identity}",
        f"owner identity:    {finding.owner_identity}",
        f"write operation:   {finding.write_operation}",
        f"source ref:        {finding.source_ref}",
        f"finding id:        {finding.id}",
        "",
        "evidence:",
        f"  attacker: {finding.evidence.attacker_excerpt}",
        f"  owner:    {finding.evidence.owner_excerpt}",
    ]
    if finding.evidence.notes:
        lines.append(f"  notes:    {finding.evidence.notes}")
    lines.append("")
    lines.append("repro curl:")
    lines.extend(f"  {line}" for line in finding.repro_curl.splitlines())
    lines.append("")
    return lines


def render_text(findings: list[Finding], meta: RunMeta) -> str:
    """Rendert Findings + Meta als menschenlesbaren Text-Report.

    Reihenfolge der Findings ist stabil (dieselbe Sortierung wie
    `write_json`: Severity-Rang, endpoint, parameter, id).
    """
    sorted_findings = sorted(findings, key=_sort_key)
    lines = _render_header(meta)
    if not sorted_findings:
        lines.append("(keine Findings)")
    for index, finding in enumerate(sorted_findings, start=1):
        lines.extend(_render_finding(finding, index))
    return "\n".join(lines).rstrip() + "\n"
