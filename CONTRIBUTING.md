# Contributing to bolabuster

Thank you for your interest in bolabuster! This guide covers how to develop, test, and contribute changes.

## Development Setup

```bash
# Clone the repository
git clone <repo_url>
cd bolabuster

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode with test dependencies
pip install -e ".[dev]"
```

## Running Tests

All tests are network-isolated and deterministic:

```bash
python -m pytest -q
```

For verbose output:

```bash
python -m pytest -v
```

For coverage:

```bash
pip install pytest-cov
python -m pytest --cov=bolabuster --cov-report=html
```

**Test count:** 121 tests across all modules.

## Project Architecture

### Module Organization

```
bolabuster/
├── config/        — Config loading & validation (auth, scope)
├── corpus/        — Request corpus parsers (HAR, raw HTTP, OpenAPI, GraphQL)
├── detect/        — Object ID detection (numeric, UUID, GraphQL global)
├── engine/        — Core replay logic (scope enforcement, rate limiting, execution)
├── classify/      — Response comparison & verdict assignment
├── report/        — Report generation (text, JSON, curl reproduction)
├── models.py      — Core dataclasses
├── cli.py         — Command-line interface & orchestration
└── errors.py      — Custom exceptions
```

### Data Flow

1. **Config Loading** (`config/`) — Parse identities and scope YAML.
2. **Corpus Parsing** (`corpus/`) — Extract requests from HAR, raw HTTP, OpenAPI, or GraphQL.
3. **Detection** (`detect/`) — Identify object IDs (numeric, UUID, Relay global) in requests.
4. **Preparation** (`engine/prepare.py`) — Build request variants (self, swap, enumerate).
5. **Replay** (`engine/replay.py`) — Execute all variants under rate limiting.
6. **Classification** (`classify/`) — Compare responses, detect ownership markers.
7. **Findings** (`classify/findings.py`) — Generate findings from verdicts.
8. **Reporting** (`report/`) — Render text, JSON, or curl reproduction.

## Contributing a Custom Corpus Parser

A corpus parser teaches bolabuster how to ingest a new API request format.

### 1. Implement `CorpusParser` Protocol

Create a new file `bolabuster/corpus/my_format.py`:

```python
"""Parser for MyFormat request files."""

from pathlib import Path
from bolabuster.corpus.base import CorpusParser, ParserOptions
from bolabuster.models import CanonicalRequest
from bolabuster.errors import CorpusParseError


class MyFormatParser:
    """Parses .myformat files into canonical requests."""
    
    name = "my_format"
    
    def can_parse(self, source: Path) -> bool:
        """Return True if source looks like a .myformat file."""
        if source.suffix != ".myformat":
            return False
        try:
            with open(source, "r") as f:
                first_line = f.readline()
                return first_line.startswith("## MyFormat")
        except (OSError, UnicodeDecodeError):
            return False
    
    def parse(self, source: Path, opts: ParserOptions) -> list[CanonicalRequest]:
        """Parse source file and return list of CanonicalRequest.
        
        Append warnings to opts.warnings for non-fatal issues.
        Raise CorpusParseError for fatal problems.
        """
        try:
            with open(source, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError as e:
            raise CorpusParseError(f"Cannot read {source}: {e}")
        
        requests = []
        # Parse logic here
        
        if not requests:
            opts.warnings.append(f"No requests found in {source}")
        
        return requests
```

### 2. Register the Parser

Add to `bolabuster/corpus/registry.py`:

```python
from bolabuster.corpus.my_format import MyFormatParser

BUILTIN_PARSERS = [
    HarParser(),
    RawHttpParser(),
    OpenApiParser(),
    GraphQlParser(),
    MyFormatParser(),  # Add here
]
```

Or register dynamically:

```python
from bolabuster.corpus import register
register(MyFormatParser())
```

### 3. Write Tests

Create `tests/test_corpus_myformat.py`:

```python
"""Tests for MyFormatParser."""

import pytest
from pathlib import Path
from bolabuster.corpus.my_format import MyFormatParser
from bolabuster.corpus.base import ParserOptions
from bolabuster.errors import CorpusParseError


@pytest.fixture
def parser():
    return MyFormatParser()


def test_can_parse_valid_file(parser, tmp_path):
    """Happy path: recognize valid .myformat file."""
    source = tmp_path / "test.myformat"
    source.write_text("## MyFormat\nGET /api/users/1\n")
    assert parser.can_parse(source)


def test_cannot_parse_wrong_extension(parser, tmp_path):
    """Reject files with wrong extension."""
    source = tmp_path / "test.txt"
    source.write_text("## MyFormat\n")
    assert not parser.can_parse(source)


def test_parse_single_request(parser, tmp_path):
    """Parse a simple GET request."""
    source = tmp_path / "requests.myformat"
    source.write_text("## MyFormat\nGET /api/users/123\n")
    opts = ParserOptions()
    
    requests = parser.parse(source, opts)
    
    assert len(requests) == 1
    assert requests[0].method == "GET"
    assert "users/123" in requests[0].url


def test_parse_error_on_missing_file(parser):
    """Raise CorpusParseError for missing file."""
    source = Path("nonexistent.myformat")
    opts = ParserOptions()
    
    with pytest.raises(CorpusParseError):
        parser.parse(source, opts)


def test_warnings_on_empty_file(parser, tmp_path):
    """Collect warnings for empty input."""
    source = tmp_path / "empty.myformat"
    source.write_text("## MyFormat\n")
    opts = ParserOptions()
    
    requests = parser.parse(source, opts)
    
    assert len(requests) == 0
    assert any("No requests" in w for w in opts.warnings)
```

**Testing principles:**
- All tests must be network-isolated (no real HTTP calls).
- Use `tmp_path` fixture for temporary files.
- Test both success and error cases.
- Verify warnings are collected correctly.

## Contributing a Custom ID Detector

An ID detector teaches bolabuster how to recognize a new object-ID format.

### 1. Implement `IdDetector` Protocol

Add to `bolabuster/detect/detectors.py`:

```python
class MyCustomIdDetector:
    """Detects object IDs in 'custom-12345' format."""
    
    id_type = "custom_format"
    
    def detect(self, value: str, ctx: LocationContext) -> IdMatch | None:
        """Return IdMatch if value looks like a custom ID, else None."""
        if not value or not isinstance(value, str):
            return None
        
        if value.startswith("custom-") and value[7:].isdigit():
            return IdMatch(id_type=self.id_type, confidence=0.95)
        
        return None
```

### 2. Register in DEFAULT_DETECTORS

Edit `bolabuster/detect/detectors.py`:

```python
DEFAULT_DETECTORS: list[IdDetector] = [
    UuidDetector(),
    GraphQlGlobalIdDetector(),
    NumericDetector(),
    MyCustomIdDetector(),  # Add here, order matters
]
```

**Order matters:** Place more specific detectors before general ones. If you have a custom format that also matches numeric regex, put it before `NumericDetector()`.

### 3. Write Tests

Create or extend `tests/test_detect.py`:

```python
import pytest
from bolabuster.detect.detectors import MyCustomIdDetector, LocationContext, IdMatch


@pytest.fixture
def detector():
    return MyCustomIdDetector()


def test_detect_valid_custom_id(detector):
    """Recognize valid custom-* IDs."""
    ctx = LocationContext(location="path", selector="id")
    match = detector.detect("custom-12345", ctx)
    
    assert match is not None
    assert match.id_type == "custom_format"
    assert match.confidence == 0.95


def test_reject_invalid_format(detector):
    """Reject strings without custom- prefix."""
    ctx = LocationContext(location="path", selector="id")
    assert detector.detect("12345", ctx) is None
    assert detector.detect("other-format", ctx) is None


def test_reject_non_numeric_suffix(detector):
    """Reject custom-xyz (non-numeric part)."""
    ctx = LocationContext(location="path", selector="id")
    assert detector.detect("custom-xyz", ctx) is None


def test_empty_string(detector):
    """Handle empty string gracefully."""
    ctx = LocationContext(location="path", selector="id")
    assert detector.detect("", ctx) is None
```

**Testing principles:**
- Test recognition of valid IDs (happy path).
- Test rejection of non-matching strings.
- Test edge cases (empty, None, malformed).
- Verify correct `id_type` and confidence values.

## Code Style & Standards

- **Python:** 3.11+ type hints required.
- **Imports:** `from __future__ import annotations` at the top of files (for forward references).
- **Format:** Follow PEP 8; use `black`, `isort`, `pylint` if available.
- **No external dependencies** except those in `pyproject.toml` (`httpx`, `PyYAML`, test tools).
- **Docstrings:** Use Google-style docstrings for functions and classes.

## Submitting Changes

1. **Fork and branch:** Create a feature branch from `main`.
2. **Implement:** Make your changes with tests.
3. **Test:** Run the full suite: `python -m pytest -q`.
4. **Review:** Ensure code follows standards and all tests pass.
5. **Commit:** Use clear commit messages.
6. **Push & PR:** Open a pull request with description of changes.

## Security Considerations

- **No secrets in test data:** Use `example.com`, fake tokens, dummy credentials.
- **No hardcoded credentials:** All auth material must be configurable.
- **No unsafe deserialization:** Use `yaml.safe_load()` and `json.loads()`, never `pickle`.
- **Rate limiting:** Respect `limits.rate_per_sec` in production code.
- **Authorization gate:** Never bypass `authorization.confirmed: true` check.

## Reporting Issues

- **Bugs:** Include reproduction steps, Python version, error output.
- **Feature requests:** Describe the use case and proposed solution.
- **Security issues:** Report privately to maintainers; do not open public issues.

## Questions?

See `README.md` for usage, architecture, and limitations. For development questions, open an issue or discussion.

Thank you for contributing!
