"""GraphQL-Parser: Introspection-Ergebnis oder Query-Sammlung -> `CanonicalRequest`.

Eingabearten (unterschieden per `can_parse`):
- **Introspection-Ergebnis**: JSON mit `data.__schema` (Standard-Antwort der
  Introspection-Query) oder direkt `__schema` auf Root-Ebene. Daraus werden
  node-/id-bezogene Queries synthetisiert (siehe unten).
- **Query-Sammlung**: Text-Datei mit einer oder mehreren GraphQL-Operationen
  (`query`/`mutation`/`subscription` als Top-Level-Keyword). Jede Operation
  wird 1:1 als `CanonicalRequest` uebernommen.

Node-Query-Generierung aus Introspection:
Es wird der Root-Query-Typ (`__schema.queryType.name`) im `types`-Array
gesucht. Fuer jedes Feld dieses Typs, das ein Argument namens `id` besitzt,
wird eine Query erzeugt - das deckt sowohl das Relay-`node(id: ID!)`-Muster
als auch benannte Felder wie `user(id: ID!)` ab, die ein einzelnes Objekt
per ID liefern (beides sind "Query-Felder mit id-Argument", ein separater
Sonderfall fuer `node` ist nicht noetig). Die Selection-Set wird best-effort
aus den Scalar-/Enum-Feldern des Rueckgabetyps gebaut (max. 5, `id` zuerst,
falls vorhanden); ist der Rueckgabetyp nicht aufloesbar (Interface/Union/
unbekannt), wird auf `{ id }` zurueckgefallen. Diese Heuristik ist
best-effort - bei unklaren Konventionen wird eine Warnung angehaengt statt
abzubrechen.

Endpoint-Platzhalter: Aus einem Schema/einer Query-Sammlung geht der
tatsaechliche GraphQL-Endpoint nicht hervor. Es wird
`<default_scheme>://<synthetischer Host>/graphql` angenommen und eine
Warnung angehaengt.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from bolabuster.corpus.base import ParserOptions
from bolabuster.errors import CorpusParseError
from bolabuster.models import CanonicalRequest, GraphQlMeta

_SYNTHETIC_HOST = "example-api.invalid"
_ID_PLACEHOLDER = "1"
_MAX_SELECTION_FIELDS = 5

_OP_START_RE = re.compile(r"^\s*(query|mutation|subscription)\b\s*(\w*)", re.MULTILINE)


class GraphQlParser:
    name = "graphql"

    def can_parse(self, source: Path) -> bool:
        try:
            text = source.read_text(encoding="utf-8")
        except OSError:
            return False
        if not text.strip():
            return False

        data = self._try_load_json(text)
        if data is not None:
            return self._extract_schema(data) is not None

        return bool(_OP_START_RE.search(text))

    def parse(self, source: Path, opts: ParserOptions) -> list[CanonicalRequest]:
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise CorpusParseError(str(source), f"Datei konnte nicht gelesen werden: {exc}") from exc

        if not text.strip():
            raise CorpusParseError(str(source), "Datei ist leer")

        data = self._try_load_json(text)
        if data is not None:
            schema = self._extract_schema(data)
            if schema is None:
                raise CorpusParseError(str(source), "JSON-Dokument enthaelt kein '__schema' (Introspection erwartet)")
            return self._parse_introspection(schema, source, opts)

        operations = self._split_operations(text)
        if not operations:
            raise CorpusParseError(
                str(source), "kein '__schema' (JSON) und keine erkennbare GraphQL-Operation (Text) gefunden"
            )
        return self._parse_operations(operations, source, opts)

    # -- gemeinsame Helfer -------------------------------------------------

    @staticmethod
    def _try_load_json(text: str) -> Any:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _extract_schema(data: Any) -> dict | None:
        if not isinstance(data, dict):
            return None
        if isinstance(data.get("__schema"), dict):
            return data["__schema"]
        inner = data.get("data")
        if isinstance(inner, dict) and isinstance(inner.get("__schema"), dict):
            return inner["__schema"]
        return None

    def _endpoint_url(self, opts: ParserOptions) -> str:
        opts.warnings.append(
            f"kein GraphQL-Endpoint aus der Quelle ableitbar, nehme "
            f"{opts.default_scheme}://{_SYNTHETIC_HOST}/graphql an"
        )
        return f"{opts.default_scheme}://{_SYNTHETIC_HOST}/graphql"

    # -- Introspection -------------------------------------------------

    def _parse_introspection(
        self, schema: dict, source: Path, opts: ParserOptions
    ) -> list[CanonicalRequest]:
        types = schema.get("types")
        if not isinstance(types, list):
            raise CorpusParseError(str(source), "'__schema.types' fehlt oder ist keine Liste")

        types_by_name: dict[str, dict] = {
            t["name"]: t for t in types if isinstance(t, dict) and isinstance(t.get("name"), str)
        }

        query_type_ref = schema.get("queryType")
        query_type_name = query_type_ref.get("name") if isinstance(query_type_ref, dict) else None
        query_type = types_by_name.get(query_type_name) if query_type_name else None
        if query_type is None:
            raise CorpusParseError(str(source), "'__schema.queryType' verweist auf keinen bekannten Typ")

        fields = query_type.get("fields")
        if not isinstance(fields, list) or not fields:
            raise CorpusParseError(str(source), f"Query-Typ {query_type_name!r} hat keine Felder")

        requests: list[CanonicalRequest] = []
        endpoint_url: str | None = None
        for field in fields:
            if not isinstance(field, dict):
                continue
            args = field.get("args") or []
            id_arg = next(
                (a for a in args if isinstance(a, dict) and str(a.get("name", "")).lower() == "id"),
                None,
            )
            if id_arg is None:
                continue

            field_name = field.get("name")
            if not isinstance(field_name, str):
                continue

            selection = self._selection_fields(field.get("type"), types_by_name)
            selection_str = " ".join(selection)
            id_arg_name = id_arg["name"]
            query_text = self._build_node_query(field_name, id_arg_name, selection_str)

            if endpoint_url is None:
                endpoint_url = self._endpoint_url(opts)

            requests.append(
                CanonicalRequest(
                    method="POST",
                    url=endpoint_url,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"query": query_text, "variables": {id_arg_name: _ID_PLACEHOLDER}}).encode(
                        "utf-8"
                    ),
                    body_media_type="application/json",
                    source_ref=f"{source.name}#{field_name}",
                    graphql=GraphQlMeta(
                        operation=field_name,
                        query=query_text,
                        variables={id_arg_name: _ID_PLACEHOLDER},
                    ),
                )
            )

        if not requests:
            opts.warnings.append(
                f"{source.name}: kein Feld mit 'id'-Argument im Query-Typ {query_type_name!r} gefunden "
                f"(weder Relay-node(id:) noch Query-Feld per ID)"
            )
            raise CorpusParseError(
                str(source), f"kein node-/id-bezogenes Feld im Query-Typ {query_type_name!r} gefunden"
            )

        return requests

    @staticmethod
    def _build_node_query(field_name: str, id_arg_name: str, selection_str: str) -> str:
        return f'query {{ {field_name}({id_arg_name}: "{_ID_PLACEHOLDER}") {{ {selection_str} }} }}'

    def _selection_fields(self, type_ref: Any, types_by_name: dict[str, dict]) -> list[str]:
        named = self._unwrap_type(type_ref)
        if named is None:
            return ["id"]
        target = types_by_name.get(named)
        if target is None or target.get("kind") not in ("OBJECT", "INTERFACE"):
            return ["id"]

        fields = target.get("fields")
        if not isinstance(fields, list) or not fields:
            return ["id"]

        leaf_names: list[str] = []
        for f in fields:
            if not isinstance(f, dict) or not isinstance(f.get("name"), str):
                continue
            leaf_named = self._unwrap_type(f.get("type"))
            leaf_type = types_by_name.get(leaf_named) if leaf_named else None
            leaf_kind = leaf_type.get("kind") if isinstance(leaf_type, dict) else None
            if leaf_kind in ("SCALAR", "ENUM") or leaf_named in ("String", "Int", "Float", "Boolean", "ID"):
                leaf_names.append(f["name"])

        if "id" in leaf_names:
            leaf_names.remove("id")
            leaf_names.insert(0, "id")
        elif not leaf_names:
            return ["id"]

        return leaf_names[:_MAX_SELECTION_FIELDS]

    @staticmethod
    def _unwrap_type(type_ref: Any) -> str | None:
        current = type_ref
        while isinstance(current, dict):
            if current.get("kind") in ("NON_NULL", "LIST"):
                current = current.get("ofType")
                continue
            return current.get("name")
        return None

    # -- Query-Sammlung -------------------------------------------------

    @staticmethod
    def _split_operations(text: str) -> list[tuple[str | None, str]]:
        matches = list(_OP_START_RE.finditer(text))
        operations: list[tuple[str | None, str]] = []
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            block = text[start:end].strip()
            if not block:
                continue
            op_name = match.group(2) or None
            operations.append((op_name, block))
        return operations

    def _parse_operations(
        self, operations: list[tuple[str | None, str]], source: Path, opts: ParserOptions
    ) -> list[CanonicalRequest]:
        endpoint_url = self._endpoint_url(opts)
        requests: list[CanonicalRequest] = []
        for index, (op_name, query_text) in enumerate(operations):
            requests.append(
                CanonicalRequest(
                    method="POST",
                    url=endpoint_url,
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"query": query_text, "variables": {}}).encode("utf-8"),
                    body_media_type="application/json",
                    source_ref=f"{source.name}#{index}",
                    graphql=GraphQlMeta(operation=op_name, query=query_text, variables={}),
                )
            )
        return requests
