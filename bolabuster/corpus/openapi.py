"""OpenAPI/Swagger-Parser (`paths.<path>.<method>` -> `CanonicalRequest`).

Unterstuetzt OpenAPI 3.x (Schluessel `openapi:`) und Swagger 2.0 (Schluessel
`swagger:`), jeweils als JSON oder YAML. Da gueltiges JSON auch gueltiges
YAML ist, deckt `yaml.safe_load` beide Serialisierungen mit einem Parser ab.

URL-Basis-Synthese:
- OpenAPI 3.x: `servers[0].url` wird als Basis verwendet (relative
  `servers[].url` werden mit `opts.default_scheme` + synthetischem Host
  aufgeloest, mit Warnung).
- Swagger 2.0: Basis aus `schemes[0]` (Default `opts.default_scheme`),
  `host` und `basePath`.
- Fehlt jede Basisangabe, wird eine synthetische Basis
  `<default_scheme>://example-api.invalid` mit Warnung angenommen. Ein
  Discovery-Tool braucht eine absolute URL, um Requests ueberhaupt bauen zu
  koennen - eine erfundene, klar als Platzhalter erkennbare Domain
  (`.invalid`-TLD, siehe RFC 2606) ist dafuer akzeptabel und wird ueber die
  Warnung transparent gemacht.

Pfad-Parameter-Synthese:
- Fuer jeden `{name}`-Platzhalter im Pfad wird nach einem passenden Eintrag
  in `parameters` (path-level oder operation-level) gesucht.
- Beispielwert-Prioritaet: `example` -> erster Eintrag aus `examples` ->
  `schema.example` -> typbasierter Default (`schema.type`/`format`).
- Typbasierte Defaults: `integer`/`number` -> `1`, `boolean` -> `true`,
  `string` mit `format: uuid` -> Beispiel-UUID
  (`00000000-0000-0000-0000-000000000001`), sonst `string` -> `"example"`.
- Fehlt jede Angabe (kein Parameter-Objekt gefunden), wird der Fallback
  `"example"` mit Warnung verwendet - diese Platzhalter sind reine
  Discovery-Hilfen (siehe Konzept-Risiko 3: Beispielwerte treffen evtl.
  keine realen Objekte); das ist bekannt und akzeptiert.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from bolabuster.corpus.base import ParserOptions
from bolabuster.errors import CorpusParseError
from bolabuster.models import CanonicalRequest

_METHODS = ("get", "post", "put", "patch", "delete")
_SYNTHETIC_HOST = "example-api.invalid"
_UUID_PLACEHOLDER = "00000000-0000-0000-0000-000000000001"


class OpenApiParser:
    name = "openapi"

    def can_parse(self, source: Path) -> bool:
        data = self._try_load(source)
        return isinstance(data, dict) and ("openapi" in data or "swagger" in data)

    def parse(self, source: Path, opts: ParserOptions) -> list[CanonicalRequest]:
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise CorpusParseError(str(source), f"Datei konnte nicht gelesen werden: {exc}") from exc

        if not text.strip():
            raise CorpusParseError(str(source), "Datei ist leer")

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise CorpusParseError(str(source), f"ungueltiges YAML/JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise CorpusParseError(str(source), "OpenAPI-Root muss ein Objekt sein")

        if "openapi" not in data and "swagger" not in data:
            raise CorpusParseError(str(source), "Dokument hat weder 'openapi' noch 'swagger'-Schluessel")

        paths = data.get("paths")
        if not isinstance(paths, dict) or not paths:
            raise CorpusParseError(str(source), "Dokument hat keine (nicht-leere) 'paths'-Sektion")

        base_url = self._resolve_base_url(data, opts)

        requests: list[CanonicalRequest] = []
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            path_level_params = path_item.get("parameters") or []
            for method in _METHODS:
                operation = path_item.get(method)
                if not isinstance(operation, dict):
                    continue
                op_params = operation.get("parameters") or []
                all_params = list(path_level_params) + list(op_params)
                resolved_path = self._resolve_path_params(path, all_params, source, opts)
                requests.append(
                    CanonicalRequest(
                        method=method.upper(),
                        url=f"{base_url}{resolved_path}",
                        headers={},
                        body=None,
                        body_media_type=None,
                        source_ref=f"{source.name}#{method.upper()} {path}",
                    )
                )

        if not requests:
            raise CorpusParseError(str(source), "keine Operationen (get/post/put/patch/delete) in 'paths' gefunden")

        return requests

    @staticmethod
    def _try_load(source: Path) -> Any:
        try:
            text = source.read_text(encoding="utf-8")
        except OSError:
            return None
        if not text.strip():
            return None
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError:
            return None

    def _resolve_base_url(self, data: dict, opts: ParserOptions) -> str:
        if "openapi" in data:
            servers = data.get("servers")
            if isinstance(servers, list) and servers and isinstance(servers[0], dict):
                url = servers[0].get("url")
                if isinstance(url, str) and url:
                    if url.startswith("http://") or url.startswith("https://"):
                        return url.rstrip("/")
                    opts.warnings.append(
                        f"servers[0].url {url!r} ist relativ, nehme Host {_SYNTHETIC_HOST!r} an"
                    )
                    path = url if url.startswith("/") else f"/{url}"
                    return f"{opts.default_scheme}://{_SYNTHETIC_HOST}{path}".rstrip("/")
            opts.warnings.append(
                f"keine 'servers'-Angabe gefunden, nehme synthetische Basis "
                f"{opts.default_scheme}://{_SYNTHETIC_HOST} an"
            )
            return f"{opts.default_scheme}://{_SYNTHETIC_HOST}"

        # Swagger 2.0
        host = data.get("host")
        base_path = data.get("basePath") or ""
        schemes = data.get("schemes")
        scheme = schemes[0] if isinstance(schemes, list) and schemes else opts.default_scheme
        if not host:
            opts.warnings.append(
                f"keine 'host'-Angabe gefunden, nehme synthetische Basis "
                f"{opts.default_scheme}://{_SYNTHETIC_HOST} an"
            )
            host = _SYNTHETIC_HOST
        return f"{scheme}://{host}{base_path}".rstrip("/")

    def _resolve_path_params(
        self, path: str, params: list[Any], source: Path, opts: ParserOptions
    ) -> str:
        resolved = path
        start = 0
        while True:
            open_idx = resolved.find("{", start)
            if open_idx == -1:
                break
            close_idx = resolved.find("}", open_idx)
            if close_idx == -1:
                break
            name = resolved[open_idx + 1 : close_idx]
            value = self._example_value_for(name, params, source, opts)
            resolved = resolved[:open_idx] + value + resolved[close_idx + 1 :]
            start = open_idx + len(value)
        return resolved

    def _example_value_for(
        self, name: str, params: list[Any], source: Path, opts: ParserOptions
    ) -> str:
        for param in params:
            if not isinstance(param, dict):
                continue
            if param.get("name") != name or param.get("in") != "path":
                continue
            if "example" in param:
                return str(param["example"])
            examples = param.get("examples")
            if isinstance(examples, dict) and examples:
                first = next(iter(examples.values()))
                if isinstance(first, dict) and "value" in first:
                    return str(first["value"])
            schema = param.get("schema") if isinstance(param.get("schema"), dict) else param
            if isinstance(schema, dict):
                if "example" in schema:
                    return str(schema["example"])
                return self._typed_default(schema)
            break

        opts.warnings.append(
            f"{source.name}: kein Parameter-Objekt fuer Pfadparameter {{{name}}} gefunden, "
            f"nehme Fallback 'example' an"
        )
        return "example"

    @staticmethod
    def _typed_default(schema: dict) -> str:
        param_type = schema.get("type")
        param_format = schema.get("format")
        if param_type in ("integer", "number"):
            return "1"
        if param_type == "boolean":
            return "true"
        if param_format == "uuid":
            return _UUID_PLACEHOLDER
        return "example"
