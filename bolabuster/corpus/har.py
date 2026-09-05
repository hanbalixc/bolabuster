"""HAR-Parser (`log.entries[].request` -> `CanonicalRequest`)."""

from __future__ import annotations

import json
from pathlib import Path

from bolabuster.corpus.base import ParserOptions
from bolabuster.errors import CorpusParseError
from bolabuster.models import CanonicalRequest


class HarParser:
    name = "har"

    def can_parse(self, source: Path) -> bool:
        if source.suffix.lower() == ".har":
            return True
        try:
            text = source.read_text(encoding="utf-8")
        except OSError:
            return False
        if not text.strip():
            return False
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return False
        return isinstance(data, dict) and isinstance(data.get("log"), dict)

    def parse(self, source: Path, opts: ParserOptions) -> list[CanonicalRequest]:
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise CorpusParseError(str(source), f"Datei konnte nicht gelesen werden: {exc}") from exc

        if not text.strip():
            raise CorpusParseError(str(source), "Datei ist leer")

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CorpusParseError(str(source), f"ungueltiges JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise CorpusParseError(str(source), "HAR-Root muss ein JSON-Objekt sein")

        log = data.get("log")
        if not isinstance(log, dict):
            raise CorpusParseError(str(source), "HAR fehlt 'log'-Objekt")

        entries = log.get("entries")
        if not isinstance(entries, list):
            raise CorpusParseError(str(source), "HAR fehlt 'log.entries'-Liste")
        if not entries:
            raise CorpusParseError(str(source), "HAR 'log.entries' ist leer")

        requests: list[CanonicalRequest] = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
                raise CorpusParseError(str(source), f"entries[{index}] hat kein gueltiges 'request'-Objekt")
            req = entry["request"]

            method = req.get("method")
            url = req.get("url")
            if not method or not isinstance(method, str):
                raise CorpusParseError(str(source), f"entries[{index}].request.method fehlt")
            if not url or not isinstance(url, str):
                raise CorpusParseError(str(source), f"entries[{index}].request.url fehlt")

            headers: dict[str, str] = {}
            for h in req.get("headers", []) or []:
                if isinstance(h, dict) and "name" in h and "value" in h:
                    headers[str(h["name"])] = str(h["value"])
                else:
                    opts.warnings.append(f"{source.name}#{index}: ungueltiger Header-Eintrag ignoriert")

            body: bytes | None = None
            body_media_type: str | None = None
            post_data = req.get("postData")
            if isinstance(post_data, dict):
                body_media_type = post_data.get("mimeType")
                text_body = post_data.get("text")
                if isinstance(text_body, str):
                    body = text_body.encode("utf-8")
                if body_media_type is None:
                    opts.warnings.append(f"{source.name}#{index}: Body ohne mimeType")

            requests.append(
                CanonicalRequest(
                    method=method,
                    url=url,
                    headers=headers,
                    body=body,
                    body_media_type=body_media_type,
                    source_ref=f"{source.name}#{index}",
                )
            )

        return requests
