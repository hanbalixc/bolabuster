"""Reproduzierbarer curl-Befehl aus einem `PreparedRequest`.

Design-Naht (sicherheitsrelevant): `to_curl` gibt bewusst die vollstaendigen
Auth-Header der Angreifer-Identitaet aus `prepared.headers` unveraendert
weiter, weil der curl-Befehl lauffaehig sein und die Attacke reproduzieren
muss. Das ist eine dokumentierte Ausnahme von "keine Secrets ausgeben" und
wird durch eine Warn-Kommentarzeile im Output markiert.
"""

from __future__ import annotations

import shlex

from bolabuster.models import PreparedRequest

_WARNING_LINE = (
    "# WARNING: enthaelt Live-Zugangsdaten der Angreifer-Identitaet "
    "- nur im autorisierten Scope ausfuehren"
)


def to_curl(prepared: PreparedRequest) -> str:
    """Baut einen reproduzierbaren, korrekt gequoteten curl-Befehl.

    Enthaelt Methode (-X), alle Header (-H) inkl. Auth der Angreifer-
    Identitaet, und Body (--data) falls vorhanden. Body-Bytes werden als
    UTF-8 dekodiert; schlaegt das fehl, wird der Body weggelassen und ein
    Kommentar dazu ausgegeben.
    """
    parts = ["curl", "-X", shlex.quote(prepared.method), shlex.quote(prepared.url)]

    for name, value in prepared.headers.items():
        parts.append("-H")
        parts.append(shlex.quote(f"{name}: {value}"))

    body_comment = None
    if prepared.body is not None:
        try:
            body_text = prepared.body.decode("utf-8")
        except UnicodeDecodeError:
            body_text = None
            body_comment = (
                "# NOTE: body konnte nicht als UTF-8 dekodiert werden - "
                "weggelassen"
            )
        if body_text is not None:
            parts.append("--data")
            parts.append(shlex.quote(body_text))

    command = " ".join(parts)
    lines = [_WARNING_LINE]
    if body_comment is not None:
        lines.append(body_comment)
    lines.append(command)
    return "\n".join(lines)
