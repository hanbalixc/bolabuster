"""Parser fuer rohe HTTP-Requests im Burp/Text-Format.

Format pro Request:
    METHOD /pfad HTTP/1.1
    Header-Name: wert
    ...
    <Leerzeile>
    <optionaler Body>

Mehrere Requests in einer Datei koennen durch eine reine Trennzeile aus
`=`-Zeichen (z.B. `======`) oder durch mindestens zwei aufeinanderfolgende
Leerzeilen (`\\n\\n\\n`) getrennt werden - eine einzelne Leerzeile trennt
innerhalb eines Requests weiterhin nur Header von Body.

Schema-Annahme: Ist der Request-Ziel bereits eine absolute URL
(`GET http://host/pfad HTTP/1.1`), wird diese direkt uebernommen. Sonst wird
`opts.default_scheme` (Default `"https"`) verwendet und eine Warnung
angehaengt, da das Schema in einem reinen Text-/Burp-Dump nicht zuverlaessig
erkennbar ist.
"""

from __future__ import annotations

import re
from pathlib import Path

from bolabuster.corpus.base import ParserOptions
from bolabuster.errors import CorpusParseError
from bolabuster.models import CanonicalRequest

_REQUEST_LINE_RE = re.compile(r"^(\S+)\s+(\S+)\s+HTTP/\d\.\d\s*$")
_SEPARATOR_LINE_RE = re.compile(r"^=+$")


def _split_requests(text: str) -> list[str]:
    lines = text.split("\n")
    if any(_SEPARATOR_LINE_RE.match(line.strip()) for line in lines):
        blocks = re.split(r"\n\s*=+\s*\n", text)
    else:
        blocks = re.split(r"\n{3,}", text)
    return [b for b in blocks if b.strip()]


class RawHttpParser:
    name = "raw_http"

    def can_parse(self, source: Path) -> bool:
        try:
            text = source.read_text(encoding="utf-8")
        except OSError:
            return False
        if not text.strip():
            return False
        for block in _split_requests(text):
            first_line = block.strip("\n").split("\n", 1)[0].strip()
            if _REQUEST_LINE_RE.match(first_line):
                return True
        return False

    def parse(self, source: Path, opts: ParserOptions) -> list[CanonicalRequest]:
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise CorpusParseError(str(source), f"Datei konnte nicht gelesen werden: {exc}") from exc

        if not text.strip():
            raise CorpusParseError(str(source), "Datei ist leer")

        blocks = _split_requests(text)
        if not blocks:
            raise CorpusParseError(str(source), "keine Requests gefunden")

        requests: list[CanonicalRequest] = []
        for index, block in enumerate(blocks):
            requests.append(self._parse_block(block, source, index, opts))
        return requests

    def _parse_block(self, block: str, source: Path, index: int, opts: ParserOptions) -> CanonicalRequest:
        lines = block.strip("\n").split("\n")

        request_line = lines[0].strip() if lines else ""
        match = _REQUEST_LINE_RE.match(request_line)
        if not match:
            raise CorpusParseError(str(source), f"request #{index}: ungueltige Request-Line {request_line!r}")
        method, target = match.group(1), match.group(2)

        headers: dict[str, str] = {}
        body_lines: list[str] = []
        in_body = False
        for line in lines[1:]:
            if not in_body:
                if line.strip() == "":
                    in_body = True
                    continue
                if ":" not in line:
                    opts.warnings.append(f"{source.name}#{index}: unparsbare Header-Zeile ignoriert: {line!r}")
                    continue
                name, _, value = line.partition(":")
                headers[name.strip()] = value.strip()
            else:
                body_lines.append(line)

        body_text = "\n".join(body_lines).strip("\n")
        body: bytes | None = body_text.encode("utf-8") if body_text else None
        body_media_type = headers.get("Content-Type") or headers.get("content-type")
        if body is not None and body_media_type is None:
            opts.warnings.append(f"{source.name}#{index}: Body ohne Content-Type-Header")

        if target.startswith("http://") or target.startswith("https://"):
            url = target
        else:
            host = headers.get("Host") or headers.get("host")
            if not host:
                raise CorpusParseError(str(source), f"request #{index}: kein Host-Header und keine absolute URL")
            scheme = opts.default_scheme
            opts.warnings.append(
                f"{source.name}#{index}: kein Schema in Request-Line erkennbar, nehme {scheme!r} an"
            )
            path = target if target.startswith("/") else f"/{target}"
            url = f"{scheme}://{host}{path}"

        return CanonicalRequest(
            method=method,
            url=url,
            headers=headers,
            body=body,
            body_media_type=body_media_type,
            source_ref=f"{source.name}#{index}",
        )
