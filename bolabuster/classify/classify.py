"""Klassifikations-Pipeline: aus drei RawResponses + ObjectRef -> Classification.

Kernfrage: konnte Identitaet A (Angreifer) auf B's (Owner) Objekt zugreifen?
Das staerkste Signal dafuer ist, dass A's Antwort eigentuemerspezifische
Werte aus B's Baseline enthaelt ("Ownership-Marker"). Die Pipeline in
`classify_cell` wirft nie - jeder Pfad liefert eine `Classification`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from bolabuster.classify import diff
from bolabuster.models import DiffEvidence, ObjectRef, RawResponse

Verdict = Literal["confirmed", "empty_200", "denied", "error", "irrelevant"]

# Eingebaute Default-Volatile-Felder (case-insensitive), zusaetzlich zu
# `diff.DEFAULT_VOLATILE_KEYS`, die intern immer greifen. Beide Listen
# ergaenzen sich; hier stehen projekttypische Namen, die als sinnvolle
# Default-Config-Vorbelegung dienen.
_DEFAULT_VOLATILE_FIELDS = [
    "timestamp",
    "created_at",
    "updated_at",
    "expires_at",
    "issued_at",
    "nonce",
    "request_id",
    "trace_id",
    "csrf_token",
    "etag",
    "session_id",
    "generated_at",
]

# Deutet ein 3xx-Redirect-Ziel auf eine Login-/Auth-Seite hin? (grobe
# Heuristik auf dem Location-Header, case-insensitive)
_LOGIN_HINT_RE = re.compile(r"(login|signin|sign-in|auth)", re.IGNORECASE)


@dataclass
class ClassifyConfig:
    """Konfiguration fuer `classify_cell`.

    - `volatile_fields`: Feldnamen (case-insensitive), deren Werte vor dem
      Vergleich maskiert werden - zusaetzlich zu den eingebauten
      `diff.DEFAULT_VOLATILE_KEYS`, die immer greifen.
    - `evidence_max_bytes`: max. Laenge je Evidence-Auszug in Bytes
      (Default 2048).
    - `empty_body_threshold`: normalisierte Body-Laenge (Zeichen), unterhalb
      derer ein 200er als leer/objektlos gilt (Default 2, deckt z.B. "" und
      "{}" nicht direkt ab - dafuer greift der explizite Leer-JSON-Check -
      sondern sehr kurze Fragmente wie "-" oder "ok").
    - `jaccard_threshold`: minimale Jaccard-Aehnlichkeit der JSON-Key-Mengen
      (bzw. SequenceMatcher-Ratio bei Nicht-JSON), damit zwei Bodies als
      strukturell gleich gelten (Default 0.8).
    - `size_delta_tolerance`: max. relative Groessendifferenz zwischen zwei
      Bodies, damit sie noch als strukturell gleich gelten (Default 0.25).
    """

    volatile_fields: list[str] = field(default_factory=lambda: list(_DEFAULT_VOLATILE_FIELDS))
    evidence_max_bytes: int = 2048
    empty_body_threshold: int = 2
    jaccard_threshold: float = 0.8
    size_delta_tolerance: float = 0.25


@dataclass
class Classification:
    """Ergebnis von `classify_cell`.

    `structural_only=True` markiert den Risiko-1-Fall: Owner-Baseline und
    Attacker-Own-Baseline sind (nach Maskierung) identisch, es lassen sich
    keine Ownership-Marker ableiten. Ownership ist damit nicht *beweisbar*,
    aber die Attacker-Antwort ist strukturell identisch zur Owner-Baseline -
    ein unsicheres, aber nicht verwerfbares Ergebnis (siehe `build_finding`,
    das daraus ein medium-Finding statt high/critical macht).
    """

    verdict: Verdict
    score: float
    evidence: DiffEvidence
    structural_only: bool = False


def _is_login_redirect(resp: RawResponse) -> bool:
    if not (300 <= resp.status < 400):
        return False
    location = resp.headers.get("Location") or resp.headers.get("location") or ""
    return bool(_LOGIN_HINT_RE.search(location))


def _excerpt(body: bytes, cfg: ClassifyConfig) -> str:
    """Body -> gekuerzter, secret-maskierter Text fuer Evidence-Auszuege."""
    parsed = diff.try_parse_json(body)
    if parsed is not None:
        text = diff.canonical_text(diff.mask_secrets_json(parsed))
    else:
        text = diff.mask_secrets_text(diff.normalize_text(body))

    encoded = text.encode("utf-8")
    if len(encoded) > cfg.evidence_max_bytes:
        text = encoded[: cfg.evidence_max_bytes].decode("utf-8", errors="ignore") + "...<truncated>"
    return text


def _make_evidence(
    attacker_resp: RawResponse, owner_baseline: RawResponse, cfg: ClassifyConfig, notes: str = ""
) -> DiffEvidence:
    return DiffEvidence(
        attacker_excerpt=_excerpt(attacker_resp.body, cfg),
        owner_excerpt=_excerpt(owner_baseline.body, cfg),
        notes=notes,
    )


def classify_cell(
    owner_baseline: RawResponse,
    attacker_resp: RawResponse,
    attacker_own_baseline: RawResponse,
    ref: ObjectRef,
    cfg: ClassifyConfig,
) -> Classification:
    """Klassifiziert eine Replay-Zelle. Wirft nie - jeder Pfad liefert eine
    `Classification`. Reihenfolge exakt nach Spezifikation Abschnitt 3.5:

    1. Transportfehler -> error
    2. 401/403 oder Login-Redirect -> denied
    3. 5xx -> error
    4. 2xx -> Body-Diff/Ownership-Marker-Analyse (confirmed/empty_200/irrelevant)
       alles andere -> irrelevant (kein belastbares Signal)
    """
    # 1. Transportfehler
    if attacker_resp.error or attacker_resp.status < 0:
        return Classification(
            verdict="error",
            score=0.0,
            evidence=_make_evidence(
                attacker_resp, owner_baseline, cfg,
                notes=f"Transportfehler: {attacker_resp.error or 'status<0'}",
            ),
        )

    # 2. Zugriff verweigert
    if attacker_resp.status in (401, 403) or _is_login_redirect(attacker_resp):
        return Classification(
            verdict="denied",
            score=0.0,
            evidence=_make_evidence(
                attacker_resp, owner_baseline, cfg,
                notes=f"Zugriff verweigert (status={attacker_resp.status})",
            ),
        )

    # 3. Serverfehler
    if attacker_resp.status >= 500:
        return Classification(
            verdict="error",
            score=0.0,
            evidence=_make_evidence(
                attacker_resp, owner_baseline, cfg,
                notes=f"Serverfehler (status={attacker_resp.status})",
            ),
        )

    # 4. Nur 2xx traegt ein belastbares Signal fuer Objektzugriff.
    if not (200 <= attacker_resp.status < 300):
        return Classification(
            verdict="irrelevant",
            score=0.0,
            evidence=_make_evidence(
                attacker_resp, owner_baseline, cfg,
                notes=f"unbehandelter Statuscode {attacker_resp.status}",
            ),
        )

    owner_text, owner_json = diff.normalized_view(owner_baseline.body, cfg.volatile_fields)
    attacker_own_text, attacker_own_json = diff.normalized_view(attacker_own_baseline.body, cfg.volatile_fields)
    attacker_text, attacker_json = diff.normalized_view(attacker_resp.body, cfg.volatile_fields)

    jaccard, size_delta = diff.structural_similarity(attacker_json, attacker_text, owner_json, owner_text)
    structurally_similar = jaccard >= cfg.jaccard_threshold and size_delta <= cfg.size_delta_tolerance

    markers = diff.derive_ownership_markers(owner_json, attacker_own_json, owner_text, attacker_own_text)

    if markers:
        if diff.contains_markers(attacker_text, markers, json_obj=attacker_json) and structurally_similar:
            evidence = _make_evidence(
                attacker_resp, owner_baseline, cfg,
                notes="Owner-spezifische Marker in Attacker-Antwort gefunden.",
            )
            return Classification(verdict="confirmed", score=1.0, evidence=evidence)
    else:
        # Risiko-1: keine Marker ableitbar, weil owner_baseline und
        # attacker_own_baseline (nach Maskierung) identisch sind - Ownership
        # ist so nicht beweisbar. Statt zu verwerfen, liefern wir bei
        # struktureller Gleichheit zur Owner-Baseline ein unsicheres
        # Ergebnis (siehe Klassendoc `Classification.structural_only`).
        if owner_text == attacker_own_text and structurally_similar:
            evidence = _make_evidence(
                attacker_resp, owner_baseline, cfg,
                notes="manuelle Verifikation noetig: identische Baselines, Ownership nicht beweisbar",
            )
            return Classification(verdict="confirmed", score=0.5, evidence=evidence, structural_only=True)

    # Kein Marker-Treffer: leer/objektlos von irrelevant unterscheiden.
    objectless_json = attacker_json in ({}, [], None) if attacker_json is not None else False
    empty_len = len(attacker_text.encode("utf-8"))
    if empty_len < cfg.empty_body_threshold or objectless_json or not structurally_similar:
        evidence = _make_evidence(
            attacker_resp, owner_baseline, cfg,
            notes="Body leer, objektlos oder strukturell abweichend von Owner-Baseline.",
        )
        return Classification(verdict="empty_200", score=0.2, evidence=evidence)

    evidence = _make_evidence(
        attacker_resp, owner_baseline, cfg,
        notes="Struktur passt, aber keine Owner-spezifischen Marker gefunden.",
    )
    return Classification(verdict="irrelevant", score=0.1, evidence=evidence)
