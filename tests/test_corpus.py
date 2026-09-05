"""Tests fuer die Corpus-Parser-Schicht (Registry, HAR, RawHTTP)."""

from pathlib import Path

import pytest

from bolabuster.corpus import HarParser, ParserOptions, RawHttpParser, get_parser
from bolabuster.errors import CorpusParseError, UnsupportedCorpusError

FIXTURES = Path(__file__).parent / "fixtures" / "corpus"


def test_har_parser_extracts_requests():
    opts = ParserOptions()
    requests = HarParser().parse(FIXTURES / "sample.har", opts)

    assert len(requests) == 2

    get_req = requests[0]
    assert get_req.method == "GET"
    assert get_req.url == "https://api.example.com/api/v1/users/1001"
    assert get_req.headers["Authorization"] == "Bearer alice-token"
    assert get_req.body is None
    assert get_req.source_ref == "sample.har#0"

    post_req = requests[1]
    assert post_req.method == "POST"
    assert post_req.url == "https://api.example.com/api/v1/orders"
    assert post_req.body == b'{"order_id": 42}'
    assert post_req.body_media_type == "application/json"
    assert post_req.source_ref == "sample.har#1"


def test_raw_http_parser_builds_absolute_url_from_host():
    opts = ParserOptions()
    requests = RawHttpParser().parse(FIXTURES / "burp_request.txt", opts)

    assert len(requests) == 1
    req = requests[0]
    assert req.method == "POST"
    assert req.url == "https://api.example.com/api/v1/orders/42"
    assert req.headers["Host"] == "api.example.com"
    assert req.headers["Authorization"] == "Bearer bob-token"
    assert req.body == b'{"note": "update order 42"}'
    assert req.source_ref == "burp_request.txt#0"


def test_raw_http_parser_warns_on_missing_content_type_and_scheme_default():
    opts = ParserOptions()
    RawHttpParser().parse(FIXTURES / "burp_request.txt", opts)

    assert any("Content-Type" in w for w in opts.warnings)
    assert any("Schema" in w for w in opts.warnings)


def test_har_parser_broken_json_raises_corpus_parse_error():
    opts = ParserOptions()
    with pytest.raises(CorpusParseError):
        HarParser().parse(FIXTURES / "broken.har", opts)


def test_har_parser_empty_file_raises_corpus_parse_error():
    opts = ParserOptions()
    with pytest.raises(CorpusParseError):
        HarParser().parse(FIXTURES / "empty.txt", opts)


def test_raw_http_parser_empty_file_raises_corpus_parse_error():
    opts = ParserOptions()
    with pytest.raises(CorpusParseError):
        RawHttpParser().parse(FIXTURES / "empty.txt", opts)


def test_get_parser_autodetects_har():
    parser = get_parser(None, FIXTURES / "sample.har")
    assert parser.name == "har"


def test_get_parser_autodetects_raw_http():
    parser = get_parser(None, FIXTURES / "burp_request.txt")
    assert parser.name == "raw_http"


def test_get_parser_unsupported_source_raises():
    with pytest.raises(UnsupportedCorpusError):
        get_parser(None, FIXTURES / "empty.txt")


def test_get_parser_explicit_fmt_bypasses_autodetect():
    # HAR- und RawHTTP-Formate sind strukturell disjunkt (JSON vs. Text mit
    # Request-Line) - ein natuerlich mehrdeutiger Fall liess sich nicht
    # sinnvoll konstruieren. Stattdessen wird hier der explizite fmt-Pfad
    # der Registry geprueft.
    har_parser = get_parser("har", FIXTURES / "sample.har")
    assert isinstance(har_parser, HarParser)

    raw_parser = get_parser("raw_http", FIXTURES / "burp_request.txt")
    assert isinstance(raw_parser, RawHttpParser)


def test_get_parser_unknown_fmt_raises():
    with pytest.raises(UnsupportedCorpusError):
        get_parser("openapi", FIXTURES / "sample.har")
