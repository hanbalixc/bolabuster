"""Body-Normalisierung, Volatile-Maskierung, Ownership-Marker-Ableitung und
strukturelle Aehnlichkeit fuer die Response-Klassifikation (Schritt 9).

Alle Funktionen hier sind reine, werfen-nie-Helfer: sie bekommen Bytes/JSON
und liefern Text/Zahlen zurueck, ohne selbst ueber ein Verdikt zu
entscheiden - das passiert in `classify.py`.
"""

from __future__ import annotations

import difflib
import json
import re
from typing import Any

# ISO-8601-Zeitstempel (mit optionalen Sekundenbruchteilen/Zeitzone) sowie
# reine Unix-Epoch-Werte (10 oder 13 Ziffern, Sekunden/Millisekunden).
_ISO_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$"
)
_EPOCH_TIMESTAMP_RE = re.compile(r"^\d{10}(\d{3})?$")

# Feldnamen, die typischerweise volatile/nonce-artige Werte tragen
# (case-insensitive), unabhaengig von der projektspezifischen
# `cfg.volatile_fields`-Liste. Ergaenzt diese, ersetzt sie nicht.
DEFAULT_VOLATILE_KEYS = {
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
    "request_time",
    "server_time",
}

_MASK = "<MASKED>"
_UNSET = object()

_WS_RE = re.compile(r"\s+")

# Secrets, die niemals im Klartext in Evidence-Auszuegen landen duerfen.
_SECRET_KEY_RE = re.compile(
    r"(authorization|token|password|secret|api[_-]?key|cookie|jwt|access|refresh|session|bearer)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(Bearer\s+)[A-Za-z0-9\-_.]{8,}", re.IGNORECASE)
_SECRET_FIELD_TEXT_RE = re.compile(
    r'("?(?:password|api[_-]?key|secret|token|jwt|access|refresh|session|bearer)"?\s*[:=]\s*")([^"]*)(")',
    re.IGNORECASE,
)
_AUTH_HEADER_TEXT_RE = re.compile(r'(?i)(authorization"?\s*[:=]\s*"?)([^",}\s]+)')
# Offensichtliche JWT-/lange-Base64-Tokens im Evidence-Text (unabhaengig vom
# Feldnamen) - konservativ genug, um echte Ownership-Marker nicht flaechig
# zu zerstoeren: nur eyJ...-Praefix (JWT-Header) oder lange Base64-artige
# Strings ab ~40 Zeichen.
_JWT_OR_LONG_TOKEN_RE = re.compile(r"\beyJ[A-Za-z0-9\-_]+(?:\.[A-Za-z0-9\-_]+){1,2}\b|\b[A-Za-z0-9+/_\-]{40,}={0,2}\b")


def try_parse_json(body: bytes) -> Any | None:
    """Versucht, `body` als JSON zu parsen. Liefert None statt zu werfen."""
    if not body:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def normalize_text(body: bytes) -> str:
    """Kollabiert Whitespace fuer robusten Text-/Fallback-Vergleich."""
    text = body.decode("utf-8", errors="replace") if body else ""
    return _WS_RE.sub(" ", text).strip()


def _is_volatile_key(key: str, volatile_fields: list[str]) -> bool:
    lowered = key.lower()
    if lowered in {f.lower() for f in volatile_fields}:
        return True
    return lowered in DEFAULT_VOLATILE_KEYS


def _is_volatile_scalar(value: Any) -> bool:
    if isinstance(value, str):
        return bool(_ISO_TIMESTAMP_RE.match(value) or _EPOCH_TIMESTAMP_RE.match(value))
    if isinstance(value, int) and not isinstance(value, bool):
        return bool(_EPOCH_TIMESTAMP_RE.match(str(value)))
    return False


def mask_volatile_json(obj: Any, volatile_fields: list[str]) -> Any:
    """Rekursive Maskierung volatiler Felder in einer JSON-Struktur.

    Ein Feld gilt als volatil, wenn sein Schluesselname in
    `volatile_fields`/`DEFAULT_VOLATILE_KEYS` steht, ODER wenn sein
    Skalarwert selbst wie ein Zeitstempel aussieht (ISO-8601/Unix-Epoch) -
    unabhaengig vom Feldnamen, damit auch unbenannte Timestamp-Felder
    das Urteil nicht verfaelschen.
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if _is_volatile_key(k, volatile_fields):
                out[k] = _MASK
            elif isinstance(v, (dict, list)):
                out[k] = mask_volatile_json(v, volatile_fields)
            elif _is_volatile_scalar(v):
                out[k] = _MASK
            else:
                out[k] = v
        return out
    if isinstance(obj, list):
        return [
            mask_volatile_json(v, volatile_fields) if isinstance(v, (dict, list))
            else (_MASK if _is_volatile_scalar(v) else v)
            for v in obj
        ]
    return obj


def canonical_text(json_obj: Any) -> str:
    """Kanonische, sortierte JSON-Textform fuer stabile Vergleiche."""
    return json.dumps(json_obj, sort_keys=True, ensure_ascii=False)


def normalized_view(body: bytes, volatile_fields: list[str]) -> tuple[str, Any | None]:
    """Liefert (vergleichbarer Text, maskiertes JSON-Objekt oder None).

    Ist der Body JSON, wird er zuerst volatile-maskiert und dann kanonisch
    serialisiert (sortierte Keys) zurueckgegeben; sonst Whitespace-
    kollabierter Rohtext.
    """
    parsed = try_parse_json(body)
    if parsed is not None:
        masked = mask_volatile_json(parsed, volatile_fields)
        return canonical_text(masked), masked
    return normalize_text(body), None


def _flatten_scalars(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flacht eine JSON-Struktur zu {json-pointer: skalarer-Wert} ab."""
    out: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(_flatten_scalars(v, f"{prefix}/{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.update(_flatten_scalars(v, f"{prefix}/{i}"))
    else:
        out[prefix or "/"] = obj
    return out


def _token_diff_markers(owner_text: str, attacker_text: str, min_len: int = 4) -> list[str]:
    """Fallback-Marker-Ableitung fuer nicht-JSON-Bodies: laengste Tokens, die
    in `owner_text` vorkommen, aber nicht in `attacker_text`."""
    owner_tokens = re.findall(r"[A-Za-z0-9_.\-@]+", owner_text)
    attacker_tokens = set(re.findall(r"[A-Za-z0-9_.\-@]+", attacker_text))
    diff_tokens = [t for t in owner_tokens if t not in attacker_tokens and len(t) >= min_len]
    diff_tokens.sort(key=len, reverse=True)
    return diff_tokens


def _scalar_value_set(obj: Any) -> set[str]:
    """Sammelt die Menge aller skalaren Werte (rekursiv) als normalisierte
    Strings - Grundlage fuer wertbasiertes (statt Substring-) Matching."""
    values: set[str] = set()
    for v in _flatten_scalars(obj).values():
        if v is None or v == _MASK:
            continue
        values.add(v if isinstance(v, str) else str(v))
    return values


def derive_ownership_markers(
    owner_json: Any | None,
    attacker_own_json: Any | None,
    owner_text: str,
    attacker_own_text: str,
) -> list[str]:
    """Leitet eigentuemerspezifische Werte aus dem Diff Owner- vs
    Attacker-Own-Baseline ab (auf bereits volatile-maskierten Werten).

    JSON-Pfad: abweichende Skalarwerte je Feld (via JSON-Pointer-Diff).
    Fallback (kein valides JSON auf mind. einer Seite): laengste
    unterschiedliche Tokens aus einem Text-Diff, damit z.B. HTML/Text-
    Bodies ebenfalls Marker liefern.

    In beiden Faellen werden Kandidaten verworfen, die auch irgendwo (nicht
    nur am selben Pfad/als Token) in der Attacker-Own-Baseline vorkommen -
    ein Wert, den A ohnehin in der eigenen Baseline sieht, ist nicht
    owner-exklusiv und darf kein `confirmed` stuetzen.
    """
    if owner_json is not None and attacker_own_json is not None:
        owner_flat = _flatten_scalars(owner_json)
        attacker_flat = _flatten_scalars(attacker_own_json)
        attacker_own_values = _scalar_value_set(attacker_own_json)
        markers: list[str] = []
        for path, owner_val in owner_flat.items():
            if owner_val == _MASK:
                continue
            attacker_val = attacker_flat.get(path, _UNSET)
            if attacker_val == owner_val:
                continue
            if isinstance(owner_val, str) and owner_val.strip():
                candidate = owner_val
            elif not isinstance(owner_val, str) and owner_val is not None:
                candidate = str(owner_val)
            else:
                continue
            if candidate in attacker_own_values:
                continue
            markers.append(candidate)
        return markers

    return _token_diff_markers(owner_text, attacker_own_text)


_TOKEN_CHARS = r"A-Za-z0-9_.\-@"


def contains_markers(
    text: str, markers: list[str], json_obj: Any | None = None, min_len: int = 4
) -> bool:
    """True, wenn ein Marker tatsaechlich in der Attacker-Antwort vorkommt.

    JSON-Antworten (`json_obj` gesetzt): Marker muss als Mitgliedschaft in
    der Menge der skalaren Werte (rekursiv, normalisiert) auftreten - kein
    Substring-Match im serialisierten Text, damit kurze numerische IDs
    (z.B. "1") nicht faelschlich in laengeren Zahlen (z.B. "21") "stecken"
    koennen.

    Nicht-JSON-Fallback: grenzsicheres Token-Matching per Regex (Wort-/
    Tokengrenze) UND Mindest-Markerlaenge - reine Substring-Treffer unter
    der Mindestlaenge werden verworfen.
    """
    if not markers:
        return False
    if json_obj is not None:
        value_set = _scalar_value_set(json_obj)
        return any(m in value_set for m in markers)
    for marker in markers:
        if len(marker) < min_len:
            continue
        pattern = rf"(?<![{_TOKEN_CHARS}]){re.escape(marker)}(?![{_TOKEN_CHARS}])"
        if re.search(pattern, text):
            return True
    return False


def _json_key_set(obj: Any, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}/{k}"
            keys.add(path)
            keys |= _json_key_set(v, path)
    elif isinstance(obj, list):
        for v in obj:
            keys |= _json_key_set(v, f"{prefix}/[]")
    return keys


def structural_similarity(
    a_json: Any | None, a_text: str, b_json: Any | None, b_text: str
) -> tuple[float, float]:
    """Liefert (jaccard-Aehnlichkeit, relatives Groessen-Delta) zweier Bodies.

    Bei JSON auf beiden Seiten: Jaccard ueber die rekursive JSON-Key-Menge
    (Pfade), Groessen-Delta ueber die Laenge der kanonischen Textform. Sonst
    (mind. eine Seite kein valides JSON): `difflib.SequenceMatcher.ratio`
    als Jaccard-Ersatz auf dem normalisierten Text.
    """
    if a_json is not None and b_json is not None:
        a_keys, b_keys = _json_key_set(a_json), _json_key_set(b_json)
        union = a_keys | b_keys
        jaccard = (len(a_keys & b_keys) / len(union)) if union else 1.0
    else:
        jaccard = difflib.SequenceMatcher(None, a_text, b_text).ratio()

    size_delta = abs(len(a_text) - len(b_text)) / max(len(a_text), len(b_text), 1)
    return jaccard, size_delta


def mask_secrets_json(obj: Any) -> Any:
    """Rekursive Secret-Maskierung fuer Evidence-Auszuege aus JSON.

    Maskiert sowohl anhand des Schluesselnamens (`_SECRET_KEY_RE`) als auch
    wertbasiert: offensichtliche JWT-/lange-Base64-Tokens werden unabhaengig
    vom Feldnamen maskiert (konservativ, s. `_JWT_OR_LONG_TOKEN_RE`).
    """
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if _SECRET_KEY_RE.search(k):
                out[k] = "<REDACTED>"
            elif isinstance(v, str) and _JWT_OR_LONG_TOKEN_RE.search(v):
                out[k] = "<REDACTED>"
            else:
                out[k] = mask_secrets_json(v)
        return out
    if isinstance(obj, list):
        return [mask_secrets_json(v) for v in obj]
    return obj


def mask_secrets_text(text: str) -> str:
    """Best-effort Secret-Maskierung fuer nicht-JSON-Evidence-Text.

    Deckt gaengige Muster ab: `Authorization: Bearer <token>`,
    `password=<wert>`/`"password": "<wert>"` u.ae. sowie wertbasiert
    offensichtliche JWT-/lange-Base64-Tokens (unabhaengig vom Feldnamen).
    Wird ausschliesslich auf Evidence-Auszuege angewendet, nie auf die
    Verdikt-Berechnung.
    """
    text = _BEARER_RE.sub(lambda m: m.group(1) + "<REDACTED>", text)
    text = _SECRET_FIELD_TEXT_RE.sub(lambda m: m.group(1) + "<REDACTED>" + m.group(3), text)
    text = _AUTH_HEADER_TEXT_RE.sub(lambda m: m.group(1) + "<REDACTED>", text)
    text = _JWT_OR_LONG_TOKEN_RE.sub("<REDACTED>", text)
    return text
