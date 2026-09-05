"""Tests fuer OpenAPI- und GraphQL-Corpus-Parser (Schritt 5)."""

import json
from pathlib import Path

import pytest

from bolabuster.corpus import GraphQlParser, OpenApiParser, ParserOptions, get_parser
from bolabuster.errors import CorpusParseError

FIXTURES = Path(__file__).parent / "fixtures" / "corpus"


def test_openapi_parser_builds_request_with_synthesized_path_param():
    opts = ParserOptions()
    requests = OpenApiParser().parse(FIXTURES / "petstore.json", opts)

    assert len(requests) == 1
    req = requests[0]
    assert req.method == "GET"
    assert req.url == "https://petstore.example.com/api/pets/1"
    assert req.source_ref == "petstore.json#GET /pets/{petId}"


def test_openapi_parser_broken_document_raises_corpus_parse_error():
    opts = ParserOptions()
    with pytest.raises(CorpusParseError):
        OpenApiParser().parse(FIXTURES / "broken_openapi.json", opts)


def test_graphql_parser_generates_node_query_from_introspection():
    opts = ParserOptions()
    requests = GraphQlParser().parse(FIXTURES / "introspection.json", opts)

    assert len(requests) >= 1
    req = requests[0]
    assert req.method == "POST"
    assert req.body_media_type == "application/json"
    assert req.graphql is not None
    assert req.graphql.operation == "user"
    assert "id" in req.graphql.variables
    body = json.loads(req.body)
    assert "query" in body
    assert body["query"] == req.graphql.query


def test_graphql_parser_broken_input_raises_corpus_parse_error():
    opts = ParserOptions()
    with pytest.raises(CorpusParseError):
        GraphQlParser().parse(FIXTURES / "broken_graphql.txt", opts)


def test_graphql_parser_parses_query_collection():
    opts = ParserOptions()
    requests = GraphQlParser().parse(FIXTURES / "queries.graphql", opts)

    assert len(requests) == 2
    assert requests[0].graphql.operation == "GetUser"
    assert requests[1].graphql.operation == "UpdateUser"


def test_get_parser_autodetects_openapi():
    parser = get_parser(None, FIXTURES / "petstore.json")
    assert parser.name == "openapi"


def test_get_parser_autodetects_graphql_introspection():
    parser = get_parser(None, FIXTURES / "introspection.json")
    assert parser.name == "graphql"


def test_get_parser_still_autodetects_har_no_regression():
    parser = get_parser(None, FIXTURES / "sample.har")
    assert parser.name == "har"
